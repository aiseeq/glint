package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

const (
	matchesWithKeyword = 2 // Regex match with keyword
	matchesWithMessage = 3 // Regex match with keyword and message
)

func init() {
	rules.Register(NewTodoCommentRule())
}

// TodoCommentRule finds actionable TODO/FIXME/HACK/XXX comments in code
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
	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)

		// Must be a comment line
		if !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "/*") && !strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Extract comment text
		commentText := trimmed
		if strings.HasPrefix(commentText, "//") {
			commentText = strings.TrimPrefix(commentText, "//")
		} else if strings.HasPrefix(commentText, "/*") {
			commentText = strings.TrimPrefix(commentText, "/*")
		} else if strings.HasPrefix(commentText, "*") {
			commentText = strings.TrimPrefix(commentText, "*")
		}
		commentText = strings.TrimSpace(commentText)

		matches := r.pattern.FindStringSubmatch(commentText)
		if len(matches) >= matchesWithKeyword {
			keyword := strings.ToUpper(matches[1])
			message := ""
			if len(matches) >= matchesWithMessage {
				message = strings.TrimSpace(matches[2])
			}

			v := r.CreateViolation(ctx.RelPath, lineNum+1, formatMessage(keyword, message))
			v.WithCode(trimmed)

			if keyword == "FIXME" || keyword == "HACK" {
				v.Severity = core.SeverityMedium
			}

			violations = append(violations, v)
		}
	}

	return violations
}

func formatMessage(keyword, message string) string {
	if message == "" {
		return keyword + " comment found"
	}
	return keyword + ": " + message
}
