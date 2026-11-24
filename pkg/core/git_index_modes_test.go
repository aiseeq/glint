package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitIndexModesRunsGitOncePerIndexState(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "index"), []byte("index"), 0o600))

	oldRun := runGitIndexModes
	t.Cleanup(func() { runGitIndexModes = oldRun })
	calls := 0
	runGitIndexModes = func(gotRoot, pathspec string) ([]byte, error) {
		require.Equal(t, root, gotRoot)
		require.Contains(t, []string{":(glob)**/bin/*", "bin"}, pathspec)
		calls++
		return []byte("100644 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0\tbin/run\x00" +
			"100755 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0\tbin/a b\x00"), nil
	}

	for range 3 {
		modes, err := GitIndexModes(root, ":(glob)**/bin/*")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"bin/run": "100644", "bin/a b": "100755"}, modes)
	}
	require.Equal(t, 1, calls, "git ls-files calls for one state of the index")
	// The caller owns its copy: a change to it does not reach the next one.
	first, err := GitIndexModes(root, ":(glob)**/bin/*")
	require.NoError(t, err)
	delete(first, "bin/run")
	again, err := GitIndexModes(root, ":(glob)**/bin/*")
	require.NoError(t, err)
	assert.Contains(t, again, "bin/run")

	// Another pathspec is another question.
	_, err = GitIndexModes(root, "bin")
	require.NoError(t, err)
	require.Equal(t, 2, calls, "git ls-files calls for another pathspec")

	// A changed index is a new state of the repository: git is asked again.
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "index"), []byte("index with one more entry"), 0o600))
	_, err = GitIndexModes(root, ":(glob)**/bin/*")
	require.NoError(t, err)
	require.Equal(t, 3, calls, "git ls-files calls after the index changed")
}

func TestGitIndexModesOutsideRepository(t *testing.T) {
	oldRun := runGitIndexModes
	t.Cleanup(func() { runGitIndexModes = oldRun })
	runGitIndexModes = func(string, string) ([]byte, error) {
		t.Fatal("git is not asked outside a repository")
		return nil, nil
	}
	modes, err := GitIndexModes(t.TempDir(), "bin")
	require.NoError(t, err)
	assert.Empty(t, modes)
}

func TestGitIndexModesReportsGitFailure(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".git"), 0o755))
	oldRun := runGitIndexModes
	t.Cleanup(func() { runGitIndexModes = oldRun })
	runGitIndexModes = func(string, string) ([]byte, error) {
		return nil, &exec.ExitError{Stderr: []byte("fatal: detected dubious ownership")}
	}
	_, err := GitIndexModes(root, "bin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dubious ownership")
}

func TestGitIndexModesWithoutGitOrWithBrokenOutput(t *testing.T) {
	oldRun := runGitIndexModes
	t.Cleanup(func() { runGitIndexModes = oldRun })
	repo := func() string {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, ".git"), 0o755))
		return root
	}

	// No git on the machine: no file has a mode.
	runGitIndexModes = func(string, string) ([]byte, error) {
		return nil, &exec.Error{Name: "git", Err: exec.ErrNotFound}
	}
	modes, err := GitIndexModes(repo(), "bin")
	require.NoError(t, err)
	assert.Empty(t, modes)

	// git that could not start otherwise is an error.
	runGitIndexModes = func(string, string) ([]byte, error) {
		return nil, &exec.Error{Name: "git", Err: os.ErrPermission}
	}
	_, err = GitIndexModes(repo(), "bin")
	require.ErrorIs(t, err, os.ErrPermission)

	// Output not in the form of ls-files -s is an error, not a guess.
	for _, output := range []string{"100644 bin/run\x00", "100644\tbin/run\x00", "100644 abc 0\t\x00"} {
		runGitIndexModes = func(string, string) ([]byte, error) { return []byte(output), nil }
		_, err = GitIndexModes(repo(), "bin")
		require.Error(t, err, "%q", output)
		assert.Contains(t, err.Error(), "unexpected entry")
	}
}

// A directory the run cannot look into is an error, not a project outside
// git.
func TestGitIndexModesUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "project")
	require.NoError(t, os.Mkdir(root, 0o755))
	require.NoError(t, os.Chmod(parent, 0o000))
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	_, err := GitIndexModes(root, "bin")
	require.Error(t, err)
}
