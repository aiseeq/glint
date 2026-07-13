package patterns

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

var nginxHTTP2ListenPattern = regexp.MustCompile(`(?m)^\s*listen\s+[^;]*\bhttp2\b[^;]*;`)

func init() {
	rules.Register(NewDeprecatedNginxHTTP2ListenRule())
}

// DeprecatedNginxHTTP2ListenRule detects syntax deprecated by Nginx 1.25.1.
type DeprecatedNginxHTTP2ListenRule struct {
	*rules.BaseRule
}

// NewDeprecatedNginxHTTP2ListenRule creates the rule.
func NewDeprecatedNginxHTTP2ListenRule() *DeprecatedNginxHTTP2ListenRule {
	return &DeprecatedNginxHTTP2ListenRule{BaseRule: rules.NewBaseRule(
		"deprecated-nginx-http2-listen",
		"patterns",
		"Detects the deprecated Nginx 'listen ... http2' parameter",
		core.SeverityMedium,
	)}
}

// AnalyzeFile checks complete Nginx directives and ignores comments.
func (r *DeprecatedNginxHTTP2ListenRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if strings.ToLower(filepath.Ext(ctx.Path)) != ".conf" {
		return nil
	}
	content := stripNginxComments(string(ctx.Content))
	var violations []*core.Violation
	for _, match := range nginxHTTP2ListenPattern.FindAllStringIndex(content, -1) {
		lineNumber := strings.Count(content[:match[0]], "\n") + 1
		v := r.CreateViolation(ctx.RelPath, lineNumber, "Nginx 1.25.1+ deprecates the 'http2' parameter of the listen directive")
		v.WithCode(ctx.GetLine(lineNumber))
		v.WithSuggestion("Remove the 'http2' listen parameter and add a separate 'http2 on;' directive in the same server block")
		v.WithContext("pattern", "deprecated_nginx_http2_listen")
		violations = append(violations, v)
	}
	return violations
}

func stripNginxComments(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lines[i] = strings.SplitN(line, "#", 2)[0]
	}
	return strings.Join(lines, "\n")
}
