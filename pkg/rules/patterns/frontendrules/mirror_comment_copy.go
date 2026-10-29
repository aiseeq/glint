package frontendrules

import (
	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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

var mirrorPhrase = regexp.MustCompile(`(?i:\bmirrors?\s+(?:of\s+)?(?:(?:the|a|an)\s+)?(?:backend|back-end|server)\b|\bmirrors?\s+(?:of\s+)?[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bkeep\s+in\s+sync\s+with\s+(?:(?:the|a|an)\s+)?(?:backend|back-end|server)\b|\bkeep\s+in\s+sync\s+with\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bmust\s+match\s+(?:(?:the|a|an)\s+)?(?:backend|back-end|server)\b|\bmust\s+match\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bsame\s+as\s+(?:(?:the|a|an)\s+)?(?:backend|back-end|server)\b|\bsame\s+as\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bcopy\s+of\s+(?:(?:the|a|an)\s+)?(?:backend|back-end|server)\b|\bcopy\s+of\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|\bcopy\s+of\s+Go\s+(?:code|function|constant|type|value)\b|держать\s+в\s+синхроне\s+(?:backend|server|бэкенд|сервер)|зеркал[\pL]*\s+(?:backend|back-end|server|Go|бэкенд|сервер)|зеркал[\pL]*\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|копи[яиюей]\s+(?:backend|server|бэкенд|сервер)|копи[яиюей]\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|дублиру[\pL]*\s+(?:backend|back-end|server|Go|бэкенд|сервер)|дублиру[\pL]*\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*)`)
var mirrorCodeSource = regexp.MustCompile(`(?i:\b(?:backend|back-end|server|сервер|бэкенд|бэкэнд|go)\b|\b[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*\b|\b(?:src|pkg|internal|models|constants)/[\w./-]+)`)
var mirrorLiteralInitializer = regexp.MustCompile(`(?s)^\s*(?:['"\x60][^'"\x60]*['"\x60]|-?\d+(?:\.\d+)?|true|false|null|\[[\s\w$:'"\x60,.-]*\]|\{[\s\w$:'"\x60,.-]*\})\s*;?\s*$`)
var mirrorExplanatory = regexp.MustCompile(`(?i)returns?\s+(?:a\s+)?copy\s+of\b|backup\s+mirrors?\b|mirror\s+of\s+what\b|reported\s+as\s+(?:a\s+)?copy\s+of\b`)

var mirrorVariableDecl = regexp.MustCompile(`^(?:(?:export|default|declare)\s+)*(?:const|let|var)\b|^(?:var|const)\s+[A-Za-z_][A-Za-z0-9_]*\b`)
var mirrorDecl = regexp.MustCompile(`^(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:const|let|var|function|type|interface|class)\b|^(?:func\s+(?:\([^)]*\)\s*)?[A-Za-z_][A-Za-z0-9_]*\s*\(|(?:var|const|type)\s+[A-Za-z_][A-Za-z0-9_]*\b)`)

func mirrorInitializer(line string) string {
	if i := strings.IndexByte(line, '='); i >= 0 && !strings.Contains(line, "==") {
		return strings.TrimSpace(line[i+1:])
	}
	return ""
}

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
	var out []*core.Violation
	for i, line := range lines {
		if !mirrorDecl.MatchString(strings.TrimSpace(line)) {
			continue
		}
		if i == 0 {
			continue
		}
		start := i
		for start > 0 {
			commentLine := strings.TrimSpace(c.Lines[start-1])
			if !(strings.HasPrefix(commentLine, "//") || strings.HasPrefix(commentLine, "/*") || strings.HasPrefix(commentLine, "*")) {
				break
			}
			start--
		}
		comment := strings.Join(c.Lines[start:i], " ")
		if mirrorExplanatory.MatchString(comment) || !mirrorPhrase.MatchString(comment) {
			continue
		}
		if !mirrorCodeSource.MatchString(comment) {
			continue
		}
		if mirrorVariableDecl.MatchString(strings.TrimSpace(line)) {
			rhs := mirrorInitializer(strings.TrimSpace(line))
			if rhs != "" && !mirrorLiteralInitializer.MatchString(rhs) {
				continue
			}
		}

		out = patternkit.JsReport(out, r.BaseRule, c, i+1, "Declaration comment says this code copies another source of truth", "Import or generate the value from its source of truth")
	}
	return out
}
