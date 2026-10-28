package patterntest

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

// Recipe turns the two-space indent of a make file sample into the tab make
// requires.
func Recipe(source string) string { return strings.ReplaceAll(source, "\n  ", "\n\t") }

// ShellFindings runs a registered rule over the files of a root, the make
// files given with recipe indents.
func ShellFindings(t *testing.T, name string, files map[string]string) []string {
	t.Helper()
	rule, ok := rules.Get(name)
	require.True(t, ok, name)
	var contexts []*core.FileContext
	for path, source := range files {
		contexts = append(contexts, rulestest.TextFile(t, path, Recipe(source)))
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
