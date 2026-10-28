package patterntest

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func SqlFileRuleLines(t *testing.T, rule interface {
	AnalyzeFile(*core.FileContext) []*core.Violation
}, path, source string) []int {
	t.Helper()
	return rulestest.ViolationLines(rule.AnalyzeFile(rulestest.GoFile(t, path, source)))
}
