package frontendrules

import (
	"go/ast"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/duplication"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"

	"regexp"
	"strings"
)

func init() { rules.Register(NewMirrorCommentCopyRule()) }

// MirrorCommentCopyRule reports declarations whose comments say they duplicate
// another source of truth.
type MirrorCommentCopyRule struct{ *rules.BaseRule }

// NewMirrorCommentCopyRule creates the rule.
func NewMirrorCommentCopyRule() *MirrorCommentCopyRule {
	return &MirrorCommentCopyRule{rules.NewBaseRule("mirror-comment-copy", "patterns", "Detects production declarations whose comments say they copy another source of truth", core.SeverityMedium)}
}

var mirrorPhrase = regexp.MustCompile(`(?i:\bcop(?:y|ied)\s+from\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bported\s+from\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bduplicated\s+from\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bmirrors?\s+(?:the\s+(?:table|list)\s+in|the\s+values\s+of)\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bmirrors?\s+(?:of\s+)?(?:(?:the|a|an)\s+)?(?:backend|back-end|server)\b|\bmirrors?\s+(?:of\s+)?[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bkeep\s+in\s+sync\s+with\s+(?:(?:the|a|an)\s+)?(?:backend|back-end|server)\b|\bkeep\s+in\s+sync\s+with\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bmust\s+match\s+(?:(?:the|a|an)\s+)?(?:backend|back-end|server)\b|\bmust\s+match\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bsame\s+as\s+(?:(?:the|a|an)\s+)?(?:backend|back-end|server)\b|\bsame\s+as\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bcopy\s+of\s+(?:(?:the|a|an)\s+)?(?:backend|back-end|server)\b|\bcopy\s+of\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bcopy\s+of\s+Go\s+(?:code|function|constant|type|value)\b|держать\s+в\s+синхроне\s+(?:backend|server|бэкенд|сервер)|зеркал[\pL]*\s+(?:backend|back-end|server|Go|бэкенд|сервер)|зеркал[\pL]*\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|копи[яиюей]\s+(?:backend|server|бэкенд|сервер)|копи[яиюей]\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|дублиру[\pL]*\s+(?:backend|back-end|server|Go|бэкенд|сервер)|дублиру[\pL]*\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*)`)

// Every mirrorPhrase alternative contains one of these case-folded stems.
var mirrorPhraseNeedles = []string{"cop", "ported", "duplicated", "mirror", "keep", "must", "same", "держать", "зеркал", "копи", "дублиру"}

// Characters that may start a phrase stem only after case folding: Cyrillic
// stems, ſ (s), ᲁ (д) and the Kelvin sign U+212A (k).
const mirrorUnicodePhraseStarts = "дДзЗкКſᲁ\u212a"

var mirrorCodeSource = regexp.MustCompile(`(?i:\b(?:backend|back-end|server|сервер|бэкенд|бэкэнд|go)\b|\b[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*\b|\b(?:src|pkg|internal|models|constants)/[\w./-]+)`)
var mirrorLiteralInitializer = regexp.MustCompile(`(?s)^\s*(?:['"\x60][^'"\x60]*['"\x60]|-?\d+(?:\.\d+)?|true|false|null|\[[\s\w$:'"\x60,.-]*\]|\{[\s\w$:'"\x60,.-]*\})\s*;?\s*$`)

// mirrorDataFile is a data file name (auth.json, config.yaml): a copy of it
// is made at run time and names no declaration of another source.
var mirrorDataFile = regexp.MustCompile(`(?i)\b[\w$-]+\.(?:json|jsonl|ya?ml|toml|env|txt|csv|ini|conf|cfg|log|pem|key|crt|xml|lock|db|sqlite)\b`)

// mirrorGitFileCopy is a staged, working, worktree or index copy of a file:
// its version in git, cut out of the comment so a value copy beside it stays.
var mirrorGitFileCopy = regexp.MustCompile(`(?i)\b(?:staged|working|worktree|index)\s+copy\s+of\s+[\w$./-]+`)
var mirrorExplanatory = regexp.MustCompile(`(?i)returns?\s+(?:a\s+)?copy\s+of\b|backup\s+mirrors?\b|mirror\s+of\s+what\b|reported\s+as\s+(?:a\s+)?copy\s+of\b`)

var mirrorVariableDecl = regexp.MustCompile(`^(?:(?:export|default|declare)\s+)*(?:const|let|var)\b|^(?:var|const)\s+[A-Za-z_][A-Za-z0-9_]*\b`)
var mirrorDecl = regexp.MustCompile(`^(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:const|let|var|function|type|interface|class)\b|^(?:func\s+(?:\([^)]*\)\s*)?[A-Za-z_][A-Za-z0-9_]*\s*\(|(?:var|const|type)\s+[A-Za-z_][A-Za-z0-9_]*\b)`)

func mirrorDeclaration(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	switch line[0] {
	case 'c':
		if !strings.HasPrefix(line, "const") && !strings.HasPrefix(line, "class") {
			return false
		}
	case 'd':
		if !strings.HasPrefix(line, "default") && !strings.HasPrefix(line, "declare") {
			return false
		}
	case 'e':
		if !strings.HasPrefix(line, "export") {
			return false
		}
	case 'f':
		if !strings.HasPrefix(line, "function") && !strings.HasPrefix(line, "func") {
			return false
		}
	case 'i':
		if !strings.HasPrefix(line, "interface") {
			return false
		}
	case 'l':
		if !strings.HasPrefix(line, "let") {
			return false
		}
	case 't':
		if !strings.HasPrefix(line, "type") {
			return false
		}
	case 'v':
		if !strings.HasPrefix(line, "var") {
			return false
		}
	default:
		return false
	}
	return mirrorDecl.MatchString(line)
}

// mirrorLineMayMatchPhrase checks the ASCII needles without allocating. The
// Unicode path keeps FoldLower's special case-folding behavior for Cyrillic
// and compatibility letters.
func mirrorLineMayMatchPhrase(line string) bool {
	checkedUnicodeStarts := false
	for i := 0; i < len(line); i++ {
		b := line[i]
		if b >= 0x80 {
			if !checkedUnicodeStarts {
				checkedUnicodeStarts = true
				if strings.ContainsAny(line, mirrorUnicodePhraseStarts) {
					return helpers.ContainsAny(helpers.FoldLower(line), mirrorPhraseNeedles)
				}
			}
			continue
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if i > 0 && mirrorASCIIWordByte(line[i-1]) {
			continue
		}
		switch b {
		case 'c':
			if mirrorASCIITokenSpaceAt(line, i, "copy") || mirrorASCIITokenSpaceAt(line, i, "copied") {
				return true
			}
		case 'p':
			if mirrorASCIITokenSpaceAt(line, i, "ported") {
				return true
			}
		case 'd':
			if mirrorASCIITokenSpaceAt(line, i, "duplicated") {
				return true
			}
		case 'm':
			if mirrorASCIITokenSpaceAt(line, i, "mirror") || mirrorASCIITokenSpaceAt(line, i, "mirrors") || mirrorASCIITokenSpaceAt(line, i, "must") {
				return true
			}
		case 'k':
			if mirrorASCIITokenSpaceAt(line, i, "keep") {
				return true
			}
		case 's':
			if mirrorASCIITokenSpaceAt(line, i, "same") {
				return true
			}
		}
	}
	return false
}

func mirrorASCIIWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func mirrorASCIITokenSpaceAt(line string, at int, token string) bool {
	if len(line)-at < len(token) {
		return false
	}
	for j := range token {
		b := line[at+j]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != token[j] {
			return false
		}
	}
	if len(line)-at == len(token) {
		return true // The joined comment inserts whitespace between lines.
	}
	b := line[at+len(token)]
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

func mirrorASCIIHasAt(line string, at int, needle string) bool {
	if len(line)-at < len(needle) {
		return false
	}
	for j := 1; j < len(needle); j++ {
		c := line[at+j]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != needle[j] {
			return false
		}
	}
	return true
}

func mirrorMayContainDataFile(comment string) bool {
	if !strings.Contains(comment, ".") {
		return false
	}
	for i := 0; i < len(comment); i++ {
		if comment[i] >= 0x80 {
			return mirrorDataFile.MatchString(comment)
		}
		if comment[i] != '.' {
			continue
		}
		if i+1 >= len(comment) {
			continue
		}
		first := comment[i+1]
		if first >= 'A' && first <= 'Z' {
			first += 'a' - 'A'
		}
		switch first {
		case 'c':
			if mirrorASCIIHasAt(comment, i+1, "csv") || mirrorASCIIHasAt(comment, i+1, "conf") || mirrorASCIIHasAt(comment, i+1, "cfg") || mirrorASCIIHasAt(comment, i+1, "crt") {
				return true
			}
		case 'd':
			if mirrorASCIIHasAt(comment, i+1, "db") {
				return true
			}
		case 'e':
			if mirrorASCIIHasAt(comment, i+1, "env") {
				return true
			}
		case 'i':
			if mirrorASCIIHasAt(comment, i+1, "ini") {
				return true
			}
		case 'j':
			if mirrorASCIIHasAt(comment, i+1, "json") || mirrorASCIIHasAt(comment, i+1, "jsonl") {
				return true
			}
		case 'k':
			if mirrorASCIIHasAt(comment, i+1, "key") {
				return true
			}
		case 'l':
			if mirrorASCIIHasAt(comment, i+1, "log") || mirrorASCIIHasAt(comment, i+1, "lock") {
				return true
			}
		case 'p':
			if mirrorASCIIHasAt(comment, i+1, "pem") {
				return true
			}
		case 's':
			if mirrorASCIIHasAt(comment, i+1, "sqlite") {
				return true
			}
		case 't':
			if mirrorASCIIHasAt(comment, i+1, "toml") || mirrorASCIIHasAt(comment, i+1, "txt") {
				return true
			}
		case 'x':
			if mirrorASCIIHasAt(comment, i+1, "xml") {
				return true
			}
		case 'y':
			if mirrorASCIIHasAt(comment, i+1, "yaml") || mirrorASCIIHasAt(comment, i+1, "yml") {
				return true
			}
		}
	}
	return false
}

func mirrorCommentText(lines []string, start, end int) (string, bool) {
	possiblePhrase := slices.ContainsFunc(lines[start:end], mirrorLineMayMatchPhrase)
	if !possiblePhrase {
		return "", false
	}
	comment := strings.Join(lines[start:end], " ")
	if mirrorGitFileCopy.MatchString(comment) {
		comment = mirrorGitFileCopy.ReplaceAllString(comment, "file version")
	}
	if mirrorMayContainDataFile(comment) {
		comment = mirrorDataFile.ReplaceAllString(comment, "file")
	}
	if !mirrorPhrase.MatchString(comment) || !mirrorCodeSource.MatchString(comment) {
		return comment, false
	}
	return comment, true
}

func mirrorInitializer(line string) string {
	if i := strings.IndexByte(line, '='); i >= 0 && !strings.Contains(line, "==") {
		return strings.TrimSpace(line[i+1:])
	}
	return ""
}

// NeedsTypedGoProject asks for Go types on every root: a Go function is left to
// the body rule only when that rule would take it, which needs the types; a
// rule that declines is not run at all, so TypeScript-only roots ask too.
func (r *MirrorCommentCopyRule) NeedsTypedGoProject([]*core.FileContext) bool { return true }

// ReportsOn reports whether this rule can find a declaration in this file.
func (r *MirrorCommentCopyRule) ReportsOn(ctx *core.FileContext) bool {
	return !ctx.IsTestFile() && (ctx.IsGoFile() || ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile())
}

// TypedGoProjectImports lists no imports: the need does not depend on them.
func (r *MirrorCommentCopyRule) TypedGoProjectImports() []string { return nil }

// AnalyzeFile reports production declarations that claim to copy another source.
func (r *MirrorCommentCopyRule) AnalyzeFile(c *core.FileContext) []*core.Violation {

	if c.IsTestFile() || (!c.IsGoFile() && patternkit.SkipFrontendPath(c)) {
		return nil
	}
	if !c.IsGoFile() && !c.IsTypeScriptFile() && !c.IsJavaScriptFile() {
		return nil
	}
	lines := c.Lines
	if !c.IsGoFile() {
		lines = helpers.MaskJSComments(lines)
	}
	funcAt := make(map[int]*ast.FuncDecl)
	if c.IsGoFile() && c.GoAST != nil && c.GoFileSet != nil {
		for _, decl := range c.GoAST.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok {
				funcAt[c.GoFileSet.Position(fd.Pos()).Line] = fd
			}
		}
	}
	var out []*core.Violation
	for i, line := range lines {
		if !mirrorDeclaration(line) {
			continue
		}
		if i == 0 {
			continue
		}
		start := i
		for start > 0 {
			commentLine := strings.TrimSpace(c.Lines[start-1])
			if !strings.HasPrefix(commentLine, "//") && !strings.HasPrefix(commentLine, "/*") && !strings.HasPrefix(commentLine, "*") {
				break
			}
			start--
		}
		// The block helper skips the regex pipeline when no phrase marker occurs.
		comment, possiblePhrase := mirrorCommentText(c.Lines, start, i)
		if !possiblePhrase {
			continue
		}
		if mirrorExplanatory.MatchString(comment) {
			continue
		}
		if mirrorVariableDecl.MatchString(strings.TrimSpace(line)) {
			rhs := mirrorInitializer(strings.TrimSpace(line))
			if rhs != "" && !mirrorLiteralInitializer.MatchString(rhs) {
				continue
			}
		}
		// A Go function copy the body rule takes (duplicate-func-across-packages)
		// is caught by its body: its comment is no cause for a finding, and
		// reporting it only teaches to delete the honest note while the copy stays.
		// A function that only calls the source its comment names holds no copy;
		// a call of anything else may carry the copied logic in its arguments.
		if fd := funcAt[i+1]; fd != nil && (callsNamedSource(fd, c.GoTypesInfo, comment) || duplication.IsDuplicateFuncBodyCandidate(fd, c.GoTypesInfo)) {
			continue
		}
		out = patternkit.JsReport(out, r.BaseRule, c, i+1, "Declaration comment says this code copies another source of truth", "Import or generate the value from its source of truth")
	}
	return out
}

// callsNamedSource reports a Go function whose body only calls the function
// or method the comment names as its source, as pkg.Name, alias.Name under the
// import alias of the call or, for a method, Type.Name.
func callsNamedSource(fd *ast.FuncDecl, info *types.Info, comment string) bool {
	callee, qualifier := duplication.DelegateCallee(fd, info)
	if callee == nil {
		return false
	}
	owners := []string{callee.Pkg().Name()}
	if qualifier != "" && callee.Signature().Recv() == nil {
		owners = append(owners, qualifier)
	}
	if recv := callee.Signature().Recv(); recv != nil {
		t := recv.Type()
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		if named, ok := t.(*types.Named); ok {
			owners = append(owners, named.Obj().Name())
		}
	}
	for _, owner := range owners {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(owner+"."+callee.Name()) + `\b`).MatchString(comment) {
			return true
		}
	}
	return false
}
