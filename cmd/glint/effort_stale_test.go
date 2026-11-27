package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A marker of effort-below-high on a line the rule finds nothing on is
// stale: the rule asks whether a line is suppressed only for its findings,
// so stale-suppression still sees the marker that silences nothing.
func TestEffortBelowHighStaleMarker(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.com/judge\n\ngo 1.24\n",
		".glint.yaml": "version: 1\n",
		"judge.go": `package judge

import "os/exec"

func run(prompt string) *exec.Cmd {
	return exec.Command("claude", "-p", "--effort", "high", prompt) //nolint:effort-below-high // the judge runs on high
}

func low(prompt string) *exec.Cmd {
	return exec.Command("claude", "-p", "--effort", "low", prompt) //nolint:effort-below-high // a probe of the rule
}
`,
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
	}
	findings, stale := analyzeWithRules(t, root, nil, "effort-below-high", "stale-suppression")
	assert.Empty(t, foundAt(findings))
	assert.Equal(t, []string{"judge.go:6"}, foundAt(stale))
}
