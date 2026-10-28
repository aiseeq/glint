package patterntest

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

// RunRuleOnProject runs rule the way the check flow does: a project rule gets
// the loaded project, a file rule gets every file in turn. Tests that pin the
// search scope of a rule (a declaration in one file, its use in another) go
// through here, so they stay meaningful whichever kind of rule it is.
func RunRuleOnProject(t *testing.T, rule rules.Rule, project *core.GoProjectContext) []*core.Violation {
	t.Helper()
	return rulestest.RunRuleOnProject(t, rule, project)
}

// RunRuleOnFiles writes files into a fresh module, loads it as a typed
// project and runs rule over it.
func RunRuleOnFiles(t *testing.T, rule rules.Rule, files map[string]string) []*core.Violation {
	t.Helper()
	return rulestest.RunRuleOnFiles(t, rule, files)
}

// RunRuleOnBrokenFiles loads files the way --tolerant does, so packages that
// fail to type-check reach the rule without type information, and runs rule
// over the project. The files must break at least one package.
func RunRuleOnBrokenFiles(t *testing.T, rule rules.Rule, files map[string]string) []*core.Violation {
	t.Helper()
	root, contexts := rulestest.Module(t, files)
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{TolerateBrokenPackages: true, ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	require.NotEmpty(t, project.SkippedPackages, "the fixture must break a package to reach the untyped path")
	return RunRuleOnProject(t, rule, project)
}
