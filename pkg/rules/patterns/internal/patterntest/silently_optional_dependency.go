package patterntest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func OptDepProject(t *testing.T, files map[string]string) *core.GoProjectContext {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/svc\n\ngo 1.24\n"), 0o644))

	var contexts []*core.FileContext
	for name, source := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(path, []byte(source), 0o644))
		ctx, err := core.NewFileContextChecked(path, root, []byte(source), core.DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}

	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	return project
}
