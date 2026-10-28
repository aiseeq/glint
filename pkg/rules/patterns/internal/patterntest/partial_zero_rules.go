package patterntest

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/require"
)

func TypedFuncFindings(t *testing.T, rule rules.GoProjectRule, files map[string]string) []string {
	t.Helper()
	violations, err := rule.AnalyzeGoProject(DecimalProject(t, files))
	require.NoError(t, err)
	return FoundLines(violations)
}
