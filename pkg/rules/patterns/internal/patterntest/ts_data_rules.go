package patterntest

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func LinesOf(t *testing.T, rule rules.Rule, path, source string) []string {
	t.Helper()
	return FoundLines(rule.AnalyzeFile(rulestest.TextFile(t, path, source)))
}
