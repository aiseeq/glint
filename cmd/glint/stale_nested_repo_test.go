package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nestedRepoExceptionConfig = `version: 1
categories:
  patterns:
    rules:
      error-string:
        exceptions:
          - files: ".claude/**"
            reason: the copy in an agent's worktree, checked when that tree is the scope
          - file: vendored/lib/loud.go
            reason: a nested repository's file
          - file: quiet.go
            reason: the file has no such finding
          - file: vendored/lib/pkg/deep.go
            reason: a file deeper in a nested repository
`

// A whole-root run does not analyze a nested repository, so it cannot tell
// whether an exception for its files silences anything: a run scoped to that
// repository can. Only exceptions of the files the run reaches are judged.
func TestStaleSuppressionLeavesExceptionsOfNestedRepositories(t *testing.T) {
	root := writeNestedRepoExceptionModule(t, true)
	_, stale := analyzeWithRules(t, root, nil, "error-string", "stale-suppression")
	assert.Equal(t, []string{".glint.yaml:11"}, foundAt(stale))
}

// Outside any repository the walk enters the nested ones, and their
// exceptions are judged like the rest.
func TestStaleSuppressionJudgesNestedRepositoriesOutsideAnyRepository(t *testing.T) {
	root := writeNestedRepoExceptionModule(t, false)
	_, stale := analyzeWithRules(t, root, nil, "error-string", "stale-suppression")
	assert.ElementsMatch(t, []string{".glint.yaml:11", ".glint.yaml:13"}, foundAt(stale))
}

func writeNestedRepoExceptionModule(t *testing.T, inRepository bool) string {
	t.Helper()
	root := t.TempDir()
	loud := "package check\n\nimport \"errors\"\n\nfunc Loud() error { return errors.New(\"Failed loudly\") }\n"
	files := map[string]string{
		"go.mod":                            "module example.com/check\n\ngo 1.24\n",
		".glint.yaml":                       nestedRepoExceptionConfig,
		"quiet.go":                          "package check\n\nfunc Quiet() {}\n",
		".claude/worktrees/agent-1/.git":    "gitdir: /elsewhere/.git/worktrees/agent-1\n",
		".claude/worktrees/agent-1/go.mod":  "module example.com/check\n\ngo 1.24\n",
		".claude/worktrees/agent-1/loud.go": loud,
		"vendored/lib/.git/HEAD":            "ref: refs/heads/main\n",
		"vendored/lib/loud.go":              loud,
		"vendored/lib/pkg/deep.go":          "package pkg\n\nfunc Deep() {}\n",
	}
	if inRepository {
		files[".git/HEAD"] = "ref: refs/heads/main\n"
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	return root
}
