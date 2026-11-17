package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldSkipDirectoryRunsGitLsFilesOncePerDirectory(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "index"), []byte("index"), 0o600))
	path := filepath.Join(root, "bin")
	require.NoError(t, os.Mkdir(path, 0o755))

	oldRun := runGitLsFiles
	t.Cleanup(func() { runGitLsFiles = oldRun })
	calls := 0
	runGitLsFiles = func(gotRoot, rel string) ([]byte, error) {
		require.Equal(t, root, gotRoot)
		require.Equal(t, "bin", rel)
		calls++
		return nil, nil
	}

	for range 2 {
		skip, err := shouldSkipDirectory("bin", path, root, nil, true)
		require.NoError(t, err)
		require.True(t, skip)
	}
	require.Equal(t, 1, calls, "git ls-files calls for the same directory")

	// A changed index is a new state of the repository: git is asked again.
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "index"), []byte("index with one more entry"), 0o600))
	_, err := shouldSkipDirectory("bin", path, root, nil, true)
	require.NoError(t, err)
	require.Equal(t, 2, calls, "git ls-files calls after the index changed")
}
