package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The walk hands .graft.yaml to the rules: a pipeline step there reaches
// glint check, not only the rule's own test.
func TestGraftStepsReachTheRules(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.com/check\n\ngo 1.24\n",
		".glint.yaml": "version: 1\n",
		".graft.yaml": "tasks:\n  api-check:\n    run:\n      - sh: 'curl -fsS \"$URL\" | jq .'\n",
		// Only graft's own file is read as graft steps.
		"settings.yaml": "tasks:\n  api-check:\n    run:\n      - sh: 'curl -fsS \"$URL\" | jq .'\n",
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
	}
	findings, _ := analyzeWithRules(t, root, nil, "shell-status-of-pipe-tail")
	assert.Equal(t, []string{".graft.yaml:4"}, foundAt(findings))
	// With exception-ticket-closed on and a tickets directory configured, as
	// in a full run on the author's machine, the walk files YAML as tickets:
	// .graft.yaml must still reach the shell rules.
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	tickets := filepath.Join(home, "tickets")
	require.NoError(t, os.MkdirAll(tickets, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "glint"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(home, "glint", "config.yaml"), []byte("tickets_dir: "+tickets+"\n"), 0o644))
	findings, _ = analyzeWithRules(t, root, nil, "shell-status-of-pipe-tail", "exception-ticket-closed")
	assert.Equal(t, []string{".graft.yaml:4"}, foundAt(findings))
}
