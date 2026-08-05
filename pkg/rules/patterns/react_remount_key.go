package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewReactRemountKeyRule())
}

// ReactRemountKeyRule detects a JSX key built from a value that a controlled
// input inside the same element edits. React treats a changed key as a new
// element: every keystroke unmounts the subtree, the fresh input mounts empty
// of focus, and the user can type exactly one character at a time.
//
// Real case (backoffice, 2026-08-05): a wallet row used
// key={`${wallet.walletAddress}-${index}`} while its <input
// value={wallet.walletAddress} onChange=.../> edited that very address.
//
// Precision over recall: the rule fires only when the key expression and the
// input's value= provably reference the same dotted path (x.field) and the
// input has an onChange/onInput handler in the same tag.
type ReactRemountKeyRule struct {
	*rules.BaseRule
	keyAttr    *regexp.Regexp
	dottedPath *regexp.Regexp
}

// remountKeyScanWindow bounds how far below the key= line the rule looks for
// the controlled input. The dotted path is scoped to the map callback, so a
// generous window is safe; the bound only guards against a same-named variable
// in a later unrelated scope.
const remountKeyScanWindow = 150

// NewReactRemountKeyRule creates the rule.
func NewReactRemountKeyRule() *ReactRemountKeyRule {
	return &ReactRemountKeyRule{
		BaseRule: rules.NewBaseRule(
			"react-remount-key",
			"patterns",
			"Detects a JSX key derived from a value edited by a controlled input inside the same element — each keystroke remounts the subtree and the input loses focus",
			core.SeverityHigh,
		),
		keyAttr:    regexp.MustCompile(`\bkey=\{`),
		dottedPath: regexp.MustCompile(`[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*`),
	}
}

// AnalyzeFile checks TSX/JSX sources.
func (r *ReactRemountKeyRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if ctx.IsTestFile() || isVendoredOrGeneratedPath(ctx.RelPath) {
		return nil
	}

	var violations []*core.Violation
	for i, line := range ctx.Lines {
		loc := r.keyAttr.FindStringIndex(line)
		if loc == nil {
			continue
		}
		keyExpr, ok := balancedBraceExpr(line[loc[1]:])
		if !ok {
			continue
		}
		paths := r.editablePathsInKey(keyExpr)
		if len(paths) == 0 {
			continue
		}
		lineNum := i + 1
		if ctx.IsSuppressed(lineNum, r.Name()) {
			continue
		}
		if path, found := r.findControlledInput(ctx, i, paths); found {
			v := r.CreateViolation(ctx.RelPath, lineNum,
				"JSX key is built from '"+path+"', which a controlled input inside this element edits — every keystroke remounts the subtree and the input loses focus")
			v.WithCode(strings.TrimSpace(line))
			v.WithSuggestion("Key the element by a stable identity (persistent id, or the array index for editable drafts) instead of the edited field")
			v.WithContext("pattern", "react-remount-key")
			v.WithContext("key_path", path)
			violations = append(violations, v)
		}
	}
	return violations
}

// editablePathsInKey extracts dotted member paths (wallet.walletAddress) from
// the key expression. Bare identifiers (index, id) carry no provable link to
// an input's value and are ignored.
func (r *ReactRemountKeyRule) editablePathsInKey(keyExpr string) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, path := range r.dottedPath.FindAllString(keyExpr, -1) {
		if seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	return paths
}

// findControlledInput scans below the key line for value={<path>} whose tag
// also carries an onChange/onInput handler.
func (r *ReactRemountKeyRule) findControlledInput(ctx *core.FileContext, keyLineIdx int, paths []string) (string, bool) {
	end := keyLineIdx + remountKeyScanWindow
	if end > len(ctx.Lines) {
		end = len(ctx.Lines)
	}
	for _, path := range paths {
		valueAttr := regexp.MustCompile(`\bvalue=\{\s*` + regexp.QuoteMeta(path) + `\s*\}`)
		for j := keyLineIdx; j < end; j++ {
			loc := valueAttr.FindStringIndex(ctx.Lines[j])
			if loc == nil {
				continue
			}
			if tag, ok := enclosingJSXTag(ctx.Lines, j, loc[0]); ok && jsxTagHasChangeHandler(tag) {
				return path, true
			}
		}
	}
	return "", false
}

// balancedBraceExpr returns the text up to the brace that closes an already
// opened '{'. Only single-line expressions are considered; template-literal
// interpolations balance themselves.
func balancedBraceExpr(rest string) (string, bool) {
	depth := 1
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:i], true
			}
		}
	}
	return "", false
}

// enclosingJSXTag reconstructs the JSX opening tag that contains the given
// position: back to the nearest '<' (a few lines up at most), forward to the
// first '>' outside of attribute braces.
func enclosingJSXTag(lines []string, lineIdx, col int) (string, bool) {
	const backLines, forwardLines = 6, 12

	startLine, startCol, ok := findTagOpen(lines, lineIdx, col, backLines)
	if !ok {
		return "", false
	}

	var tag strings.Builder
	depth := 0
	for j := startLine; j < len(lines) && j <= startLine+forwardLines; j++ {
		segment := lines[j]
		from := 0
		if j == startLine {
			from = startCol
		}
		for i := from; i < len(segment); i++ {
			tag.WriteByte(segment[i])
			switch segment[i] {
			case '{':
				depth++
			case '}':
				if depth > 0 {
					depth--
				}
			case '>':
				if depth == 0 {
					return tag.String(), true
				}
			}
		}
		tag.WriteByte('\n')
	}
	return "", false
}

// findTagOpen locates the '<' that opens the tag containing (lineIdx, col).
func findTagOpen(lines []string, lineIdx, col, backLines int) (int, int, bool) {
	for j := lineIdx; j >= 0 && j >= lineIdx-backLines; j-- {
		segment := lines[j]
		limit := len(segment) - 1
		if j == lineIdx {
			limit = col
		}
		for i := limit; i >= 0; i-- {
			if segment[i] != '<' {
				continue
			}
			// '=>' arrows and comparisons never start with "<letter"; a JSX
			// opening tag does.
			if i+1 < len(segment) && (isASCIILetter(segment[i+1]) || segment[i+1] == '_') {
				return j, i, true
			}
		}
	}
	return 0, 0, false
}

func jsxTagHasChangeHandler(tag string) bool {
	return strings.Contains(tag, "onChange") || strings.Contains(tag, "onInput")
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
