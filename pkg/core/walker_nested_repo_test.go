package core

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func walkedPaths(t *testing.T, walker *Walker) string {
	t.Helper()
	contexts, errs := walker.WithGoParsing(false).WalkSync()
	if len(errs) > 0 {
		t.Fatalf("walk errors: %v", errs)
	}
	var got []string
	for _, ctx := range contexts {
		got = append(got, ctx.RelPath)
	}
	sort.Strings(got)
	return strings.Join(got, ",")
}

// nestedRepoTree is a repository holding a linked worktree of itself (a .git
// file, as an agent's isolated worktree has) and a checkout of another
// repository (a .git directory), both carrying copies of the project's file.
var nestedRepoTree = map[string]string{
	".git/HEAD":                              "ref: refs/heads/main\n",
	"tools/run.sh":                           "#!/bin/bash\necho run\n",
	"main.go":                                "package main\n",
	".claude/worktrees/agent-1/.git":         "gitdir: /elsewhere/.git/worktrees/agent-1\n",
	".claude/worktrees/agent-1/tools/run.sh": "#!/bin/bash\necho run\n",
	".claude/worktrees/agent-1/main.go":      "package main\n",
	"third_party/lib/.git/HEAD":              "ref: refs/heads/main\n",
	"third_party/lib/lib.go":                 "package lib\n",
}

func TestWalkerSkipsNestedWorktreesAndRepositories(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, nestedRepoTree)
	got := walkedPaths(t, NewWalker(root, DefaultConfig()))
	if want := "main.go,tools/run.sh"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestWalkerSkipsNestedRepositoryBelowSubdirectoryRoot(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, nestedRepoTree)
	got := walkedPaths(t, NewWalker(filepath.Join(root, ".claude"), DefaultConfig()))
	if got != "" {
		t.Fatalf("a project directory inside the repository walked the nested worktree: %s", got)
	}
}

func TestWalkerWalksRepositoriesUnderDirectoryOutsideAnyRepository(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a/.git/HEAD": "ref: refs/heads/main\n",
		"a/a.go":      "package a\n",
		"b/.git":      "gitdir: /elsewhere/.git/worktrees/b\n",
		"b/b.go":      "package b\n",
	})
	got := walkedPaths(t, NewWalker(root, DefaultConfig()))
	if want := "a/a.go,b/b.go"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestWalkerWalksNestedWorktreeNamedAsScope(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, nestedRepoTree)
	scope := filepath.Join(root, ".claude/worktrees/agent-1")
	got := walkedPaths(t, NewWalker(root, DefaultConfig()).WithScopes([]string{scope}))
	if want := ".claude/worktrees/agent-1/main.go,.claude/worktrees/agent-1/tools/run.sh"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestWalkerWalksNestedWorktreeAsProjectRoot(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, nestedRepoTree)
	got := walkedPaths(t, NewWalker(filepath.Join(root, ".claude/worktrees/agent-1"), DefaultConfig()))
	if want := "main.go,tools/run.sh"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestWalkerSkipsUnreadableIgnoredDirectoryBeforeLookingForRepository(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".git/HEAD":   "ref: refs/heads/main\n",
		".gitignore":  "pgdata/\n",
		"main.go":     "package main\n",
		"pgdata/x.go": "package x\n",
	})
	locked := filepath.Join(root, "pgdata")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if got := walkedPaths(t, NewWalker(root, DefaultConfig())); got != "main.go" {
		t.Fatalf("got %s, want main.go", got)
	}
}

func TestWalkerReportsUnreadableDirectoryOnce(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".git/HEAD":   "ref: refs/heads/main\n",
		"main.go":     "package main\n",
		"locked/x.go": "package x\n",
	})
	locked := filepath.Join(root, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	_, errs := NewWalker(root, DefaultConfig()).WithGoParsing(false).WalkSync()
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "locked") {
		t.Fatalf("want one error about the locked directory, got %v", errs)
	}
}

func TestWalkerWalksDirectoryWithDanglingGitLink(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".git/HEAD":  "ref: refs/heads/main\n",
		"main.go":    "package main\n",
		"sub/run.go": "package sub\n",
	})
	if err := os.Symlink(filepath.Join(root, "missing"), filepath.Join(root, "sub", ".git")); err != nil {
		t.Fatal(err)
	}
	if got := walkedPaths(t, NewWalker(root, DefaultConfig())); got != "main.go,sub/run.go" {
		t.Fatalf("a .git link to nothing is no repository, as for git: got %s", got)
	}
}

func TestWalkerReportsDirectoryItCannotLookIntoForRepository(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".git/HEAD":        "ref: refs/heads/main\n",
		"main.go":          "package main\n",
		"listed/notes.txt": "text\n",
	})
	listed := filepath.Join(root, "listed")
	if err := os.Chmod(listed, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(listed, 0o755) })
	_, errs := NewWalker(root, DefaultConfig()).WithGoParsing(false).WalkSync()
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "look for a repository") {
		t.Fatalf("want one error saying whether listed holds a repository is unknown, got %v", errs)
	}
}

func TestWalkerWalksDirectoryWithLoopingGitLink(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".git/HEAD":   "ref: refs/heads/main\n",
		"main.go":     "package main\n",
		"loop/run.go": "package loop\n",
	})
	if err := os.Symlink(".git", filepath.Join(root, "loop", ".git")); err != nil {
		t.Fatal(err)
	}
	if got := walkedPaths(t, NewWalker(root, DefaultConfig())); got != "loop/run.go,main.go" {
		t.Fatalf("a .git link into a loop is no repository, as for git: got %s", got)
	}
}
