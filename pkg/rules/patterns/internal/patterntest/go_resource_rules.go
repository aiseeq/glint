package patterntest

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

// AppRuleLines runs a project rule on one file app.go and returns the lines
// it reports, in order.
func AppRuleLines(t *testing.T, rule GoProjectRule, source string) []int {
	t.Helper()
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, map[string]string{"app.go": source}))
	require.NoError(t, err)
	var got []int
	for _, v := range violations {
		got = append(got, v.Line)
	}
	return got
}
