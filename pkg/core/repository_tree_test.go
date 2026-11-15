package core

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// treeWalkedDirs walks root the way a rule does with RepositoryTree and
// returns the directories it enters, relative to root.
func treeWalkedDirs(t *testing.T, root string) string {
	t.Helper()
	tree, err := NewRepositoryTree(root)
	require.NoError(t, err)
	var got []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		if err := tree.Enter(path); err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel != "." && filepath.Base(rel) != ".git" && !strings.Contains(rel, ".git"+string(filepath.Separator)) {
			got = append(got, filepath.ToSlash(rel))
		}
		return nil
	})
	require.NoError(t, err)
	sort.Strings(got)
	return strings.Join(got, ",")
}

// A rule walking the tree itself enters the directories the run's walk
// enters: not a linked worktree (a .git file) or a checkout of another
// repository (a .git directory) below the project.
func TestRepositoryTreeLeavesOutNestedRepositories(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, nestedRepoTree)
	if got, want := treeWalkedDirs(t, root), ".claude,.claude/worktrees,third_party,tools"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if got := walkedPaths(t, NewWalker(root, DefaultConfig())); got != "main.go,tools/run.sh" {
		t.Fatalf("the walk of the same tree: %s", got)
	}
}

// Below a subdirectory root inside the repository the nested repositories
// are left out all the same; the root itself, even a worktree, is entered.
func TestRepositoryTreeRootIsAlwaysEntered(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, nestedRepoTree)
	if got := treeWalkedDirs(t, filepath.Join(root, ".claude")); got != "worktrees" {
		t.Fatalf("got %s, want worktrees", got)
	}
	if got := treeWalkedDirs(t, filepath.Join(root, ".claude/worktrees/agent-1")); got != "tools" {
		t.Fatalf("got %s, want tools", got)
	}
}

// Outside any repository a directory with a .git is what the walk was
// pointed at.
func TestRepositoryTreeEntersRepositoriesOutsideAnyRepository(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a/.git/HEAD": "ref: refs/heads/main\n",
		"a/a.go":      "package a\n",
		"b/.git":      "gitdir: /elsewhere/.git/worktrees/b\n",
		"b/b.go":      "package b\n",
	})
	if got := treeWalkedDirs(t, root); got != "a,b" {
		t.Fatalf("got %s, want a,b", got)
	}
}

// The ignore files of the directories on the way apply below them, and an
// ignored directory is never opened: neither an unreadable one nor an
// ignored repository costs a look for its .git. A negated pattern of a
// deeper .gitignore re-includes a directory.
func TestRepositoryTreeSkipsIgnoredDirectoryBeforeLookingForRepository(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".git/HEAD":           "ref: refs/heads/main\n",
		".gitignore":          "/pgdata/\n",
		"main.go":             "package main\n",
		"pgdata/x.go":         "package x\n",
		"web/.gitignore":      "cache*/\n!cache-kept/\n",
		"web/cache-a/x.js":    "x\n",
		"web/cache-kept/x.js": "x\n",
	})
	locked := filepath.Join(root, "pgdata")
	require.NoError(t, os.Chmod(locked, 0))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if got := treeWalkedDirs(t, root); got != "web,web/cache-kept" {
		t.Fatalf("got %s, want web,web/cache-kept", got)
	}
}

// A directory the walk cannot look into for a .git fails the walk, as it
// does the run's: it may hold a repository or the project's code.
func TestRepositoryTreeReportsUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".git/HEAD":      "ref: refs/heads/main\n",
		"locked/inner/x": "x\n",
	})
	locked := filepath.Join(root, "locked")
	require.NoError(t, os.Chmod(locked, 0o600))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	tree, err := NewRepositoryTree(root)
	require.NoError(t, err)
	require.NoError(t, tree.Enter(root))
	require.ErrorContains(t, tree.Enter(filepath.Join(locked, "inner")), "look for a repository")
}
