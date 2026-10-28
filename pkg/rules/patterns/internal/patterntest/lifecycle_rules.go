package patterntest

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

type GoProjectRule interface {
	AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
}

func ProjectRuleLines(t *testing.T, rule GoProjectRule, files map[string]string) []string {
	t.Helper()
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return FoundLines(violations)
}
