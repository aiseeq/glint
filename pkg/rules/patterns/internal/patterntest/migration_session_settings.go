package patterntest

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

// ProjectFileFindings runs a rule that reads the project's files over a
// module the way the check flow does: every file first, then each one.
func ProjectFileFindings(t *testing.T, rule interface {
	rules.Rule
	UseProjectFiles([]*core.FileContext)
}, files map[string]string) []string {
	t.Helper()
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	AssertFindingFiles(t, rule, contexts, violations)
	return FoundLines(violations)
}
