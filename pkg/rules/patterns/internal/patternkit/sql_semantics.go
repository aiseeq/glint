package patternkit

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// ProductionGoFile is a Go file the SQL rules read: parsed, not a test.
func ProductionGoFile(ctx *core.FileContext) bool {
	return ctx.IsGoFile() && ctx.HasGoAST() && !ctx.IsTestFile()
}

func SqlViolation(rule *rules.BaseRule, ctx *core.FileContext, line int, message, suggestion string) *core.Violation {
	v := rule.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(suggestion)
	return v
}
