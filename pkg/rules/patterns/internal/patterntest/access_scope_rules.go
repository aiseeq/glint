package patterntest

import (
	"fmt"
	"sort"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func TypedRuleFindings(t *testing.T, rule interface {
	AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
}, files map[string]string) []string {
	t.Helper()
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}
