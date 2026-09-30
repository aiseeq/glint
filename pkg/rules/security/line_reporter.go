package security

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// lineReporter collects a rule's violations for one file, one per line,
// skipping suppressed lines.
type lineReporter struct {
	ctx        *core.FileContext
	rule       *rules.BaseRule
	reported   map[int]bool
	violations []*core.Violation
}

func newLineReporter(ctx *core.FileContext, rule *rules.BaseRule) *lineReporter {
	return &lineReporter{ctx: ctx, rule: rule, reported: make(map[int]bool)}
}

// report adds a violation at the line of node, unless that line already has
// one or suppresses the rule.
func (lr *lineReporter) report(node ast.Node, message, suggestion, pattern string) {
	line := lr.ctx.LineFor(node)
	if lr.reported[line] || lr.ctx.IsSuppressed(line, lr.rule.Name()) {
		return
	}
	lr.reported[line] = true
	v := lr.rule.CreateViolation(lr.ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(lr.ctx.GetLine(line)))
	v.WithSuggestion(suggestion)
	v.WithContext("pattern", pattern)
	lr.violations = append(lr.violations, v)
}
