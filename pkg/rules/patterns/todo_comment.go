package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewTodoCommentRule())
}

// TodoCommentRule finds actionable TODO/FIXME/HACK/XXX comments in Go,
// TypeScript and JavaScript code. Markdown and other prose files are not code.
type TodoCommentRule struct {
	*rules.BaseRule
	pattern *regexp.Regexp
}

// NewTodoCommentRule creates the rule
func NewTodoCommentRule() *TodoCommentRule {
	// Match actionable patterns: TODO:, TODO(user):, FIXME:, etc.
	// The keyword must be at the start of comment text (after //)
	return &TodoCommentRule{
		BaseRule: rules.NewBaseRule(
			"todo-comment",
			"patterns",
			"Finds actionable TODO, FIXME, HACK, and XXX comments",
			core.SeverityLow,
		),
		// Match: TODO: message, TODO(author): message, TODO - message
		pattern: regexp.MustCompile(`^(TODO|FIXME|HACK|XXX)(?:\s*\([^)]*\))?[\s:\-]+(.*)$`),
	}
}

// AnalyzeFile finds actionable task comments
func (r *TodoCommentRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() && !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}

	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)

		// Must be a comment line
		if !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "/*") && !strings.HasPrefix(trimmed, "*") {
			continue
		}
		// A line of a multi-line string reads like a comment: the comment
		// mask blanks only real comments.
		start := strings.Index(line, trimmed)
		if text := helpers.FileJSText(ctx); lineNum < len(text) && start < len(text[lineNum]) && text[lineNum][start] == trimmed[0] {
			continue
		}

		// Extract comment text
		commentText := trimmed
		if after, ok := strings.CutPrefix(commentText, "//"); ok {
			commentText = after
		} else if after, ok := strings.CutPrefix(commentText, "/*"); ok {
			commentText = after
		} else if after, ok := strings.CutPrefix(commentText, "*"); ok {
			commentText = after
		}
		commentText = strings.TrimSpace(commentText)

		// The pattern is case-sensitive and has both groups: a match carries the
		// upper-case keyword and the (possibly empty) message.
		matches := r.pattern.FindStringSubmatch(commentText)
		if matches == nil {
			continue
		}
		keyword, message := matches[1], strings.TrimSpace(matches[2])

		v := r.CreateViolation(ctx.RelPath, lineNum+1, formatMessage(keyword, message))
		v.WithCode(trimmed)

		if keyword == "FIXME" || keyword == "HACK" {
			v.Severity = core.SeverityMedium
		}

		violations = append(violations, v)
	}

	return violations
}

func formatMessage(keyword, message string) string {
	if message == "" {
		return keyword + " comment found"
	}
	return keyword + ": " + message
}
