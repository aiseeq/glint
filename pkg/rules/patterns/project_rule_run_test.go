package patterns

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// runRuleOnProject runs rule the way the check flow does: a project rule gets
// the loaded project, a file rule gets every file in turn. Tests that pin the
// search scope of a rule (a declaration in one file, its use in another) go
// through here, so they stay meaningful whichever kind of rule it is.
func runRuleOnProject(t *testing.T, rule rules.Rule, project *core.GoProjectContext) []*core.Violation {
	t.Helper()
	if projectRule, ok := rule.(rules.GoProjectRule); ok {
		violations, err := projectRule.AnalyzeGoProject(project)
		require.NoError(t, err)
		return violations
	}
	var violations []*core.Violation
	for _, fileCtx := range project.Files {
		violations = append(violations, rule.AnalyzeFile(fileCtx)...)
	}
	return violations
}

// runRuleOnFiles writes files into a fresh module, loads it as a typed
// project and runs rule over it.
func runRuleOnFiles(t *testing.T, rule rules.Rule, files map[string]string) []*core.Violation {
	t.Helper()
	return runRuleOnProject(t, rule, rulestest.Project(t, files))
}

// runRuleOnBrokenFiles loads files the way --tolerant does, so packages that
// fail to type-check reach the rule without type information, and runs rule
// over the project. The files must break at least one package.
func runRuleOnBrokenFiles(t *testing.T, rule rules.Rule, files map[string]string) []*core.Violation {
	t.Helper()
	root, contexts := rulestest.Module(t, files)
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{TolerateBrokenPackages: true})
	require.NoError(t, err)
	require.NotEmpty(t, project.SkippedPackages, "the fixture must break a package to reach the untyped path")
	return runRuleOnProject(t, rule, project)
}
