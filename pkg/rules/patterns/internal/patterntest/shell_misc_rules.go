package patterntest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/require"
)

// WriteFiles writes files under a root.
func WriteFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, source := range files {
		full := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(source), 0o644))
	}
}

// ShellFindingsIn runs a registered rule over files already written under a
// root, the root being the project.
func ShellFindingsIn(t *testing.T, name, root string, paths ...string) []string {
	t.Helper()
	rule, ok := rules.Get(name)
	require.True(t, ok, name)
	var found []*core.Violation
	for _, p := range paths {
		full := filepath.Join(root, p)
		data, err := os.ReadFile(full)
		require.NoError(t, err)
		ctx, err := core.NewFileContextChecked(full, root, data, core.DefaultConfig())
		require.NoError(t, err)
		found = append(found, rule.AnalyzeFile(ctx)...)
	}
	return FoundLines(found)
}
