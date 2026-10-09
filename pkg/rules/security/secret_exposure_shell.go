package security

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

var (
	// shellPrint is echo or printf as a command of a script line or recipe.
	shellPrint = regexp.MustCompile(`(?:^|[;&(]\s*|\b(?:then|else|do)\s+)[@-]*\s*(?:echo|printf)\b(.*)$`)
	// shellPipeOrFile is a pipe or a redirect to a file: the value goes to a
	// program or a file, not to the terminal.
	shellPipeOrFile = regexp.MustCompile(`(?:^|[^|])\|(?:[^|]|$)|(?:^|[^0-9&>])>{1,2}\s*[^&\s]`)
	// shellVariable is $NAME or ${NAME...}; group 2 is a substring expansion
	// (${NAME:0:4}), which prints a masked part.
	shellVariable = regexp.MustCompile(`\$\$?\{?([A-Za-z_][A-Za-z0-9_]*)(:-?[0-9])?`)
	secretVarName = regexp.MustCompile(`(?:^|_)(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|SECRET_KEY|ACCESS_KEY)(?:_|$)|(?:^|_)PASS$`)
	// notSecretSuffix names a variable about the secret, not the secret.
	notSecretSuffix = regexp.MustCompile(`_(?:FILE|PATH|DIR|NAME|ID|LEN|LENGTH|SET|URL_PATH|HEADER|ENV|VAR|KEY_ID)$`)
)

// shellSecretPrints reports echo or printf of a secret-named variable to the
// terminal in a script or a make recipe: the value stays in the scrollback,
// the CI log and the recorded session.
func (r *SecretExposureRule) shellSecretPrints(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	captured := capturedHeredocLines(ctx.Lines)
	for i := 0; i < len(ctx.Lines); i++ {
		text := strings.TrimSpace(ctx.Lines[i])
		if strings.HasPrefix(text, "#") || captured[i] {
			continue
		}
		// A command continued with \ goes on: its pipe may be on a later line.
		logical := text
		for j := i; strings.HasSuffix(strings.TrimSpace(ctx.Lines[j]), "\\") && j+1 < len(ctx.Lines); j++ {
			logical = strings.TrimSuffix(logical, "\\") + " " + strings.TrimSpace(ctx.Lines[j+1])
		}
		loc := shellPrint.FindStringSubmatchIndex(logical)
		if loc == nil {
			continue
		}
		m := []string{logical[loc[0]:loc[1]], logical[loc[2]:loc[3]]}
		if shellPipeOrFile.MatchString(m[1]) || insideCommandSubstitution(logical[:loc[2]]) {
			continue
		}
		for _, v := range shellVariable.FindAllStringSubmatch(m[1], -1) {
			name := v[1]
			if v[2] != "" || name != strings.ToUpper(name) || !secretVarName.MatchString(name) || notSecretSuffix.MatchString(name) {
				continue
			}
			if ctx.IsSuppressed(i+1, r.Name()) {
				break
			}
			violation := r.CreateViolation(ctx.RelPath, i+1, "The script prints $"+name+" — the secret stays in the terminal scrollback, the CI log and any recorded session")
			violation.WithCode(text)
			violation.WithSuggestion("Print where the secret is stored or that it is set, never its value")
			violations = append(violations, violation)
			break
		}
	}
	return violations
}

// capturedHeredocLines returns the 0-based lines of the heredoc bodies whose
// command a $( ) captures whole (creds="$(ssh host bash <<'EOF'): what the
// script prints there lands in the variable, not on the terminal.
func capturedHeredocLines(lines []string) map[int]bool {
	captured := map[int]bool{}
	for _, h := range helpers.ShellHeredocs(lines) {
		if !insideCommandSubstitution(h.Before) {
			continue
		}
		for i := h.Open + 1; i < h.End; i++ {
			captured[i] = true
		}
	}
	return captured
}

// insideCommandSubstitution reports a line prefix that leaves a $( ... ), a
// <( ... ) or a backquote open: what the command prints there is captured into
// a value or read by another command as a file, not shown on the terminal.
func insideCommandSubstitution(prefix string) bool {
	var open []bool // true for $( and <(, false for a plain (
	backquote := false
	for i := 0; i < len(prefix); i++ {
		switch prefix[i] {
		case '`':
			backquote = !backquote
		case '(':
			open = append(open, i > 0 && (prefix[i-1] == '$' || prefix[i-1] == '<'))
		case ')':
			if len(open) > 0 {
				open = open[:len(open)-1]
			}
		}
	}
	for _, substitution := range open {
		if substitution {
			return true
		}
	}
	return backquote
}
