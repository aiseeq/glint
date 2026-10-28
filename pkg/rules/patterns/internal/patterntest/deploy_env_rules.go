package patterntest

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

// DeployFindings runs a registered rule over the files of a root: Go files
// with their syntax trees, make files with recipe indents.
func DeployFindings(t *testing.T, name string, files map[string]string) []string {
	t.Helper()
	rule, ok := rules.Get(name)
	require.True(t, ok, name)
	var contexts []*core.FileContext
	for path, source := range files {
		if strings.HasSuffix(path, ".go") {
			contexts = append(contexts, rulestest.GoFile(t, path, source))
			continue
		}
		if strings.HasSuffix(path, ".mk") || strings.HasSuffix(path, "Makefile") {
			source = Recipe(source)
		}
		contexts = append(contexts, rulestest.TextFile(t, path, source))
	}
	if project, ok := rule.(rules.ProjectFilesRule); ok {
		project.UseProjectFiles(contexts)
	}
	var found []*core.Violation
	for _, ctx := range contexts {
		found = append(found, rule.AnalyzeFile(ctx)...)
	}
	return FoundLines(found)
}
