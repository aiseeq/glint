package shellrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
)

// The checked substitution is the last one at the top of the assignment
// value: a substitution nested in its body does not replace it. A quoted
// sed script that quits is an early exit as the bare one is.
func TestShellStatusOfPipeTailReviewCaptures(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "nested.sh", `#!/bin/bash
x=$(curl -fsS u | jq "$(cat f)") || exit 1 # want
z=$(git log | sed 'q') || exit 1
q=$(git log | sed "5q") || exit 1
s=$(git log | sed 's/q/x/') || exit 1 # want
echo "$x$z$q$s"
`)
}

// In a folded scalar the finding is on the line where the pipeline starts,
// even when other commands come before it in the same scalar.
func TestShellStatusOfPipeTailReviewGraftLaterLine(t *testing.T) {
	root := t.TempDir()
	source := `tasks:
  a:
    run:
      - sh: >
          echo start;
          curl -fsS "$URL"
          | jq .
`
	require.NoError(t, os.WriteFile(filepath.Join(root, ".graft.yaml"), []byte(source), 0o600))
	got := patterntest.ShellFindingsIn(t, "shell-status-of-pipe-tail", root, ".graft.yaml")
	assert.ElementsMatch(t, []string{".graft.yaml:6"}, got)
}
