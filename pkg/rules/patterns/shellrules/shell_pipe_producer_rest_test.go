package shellrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
)

// A tail that stops reading before the end of its input (sed q, awk with
// exit) is head by another name: under pipefail the producer gets SIGPIPE
// and the pipeline fails with 141, so pipefail is no fix.
func TestShellStatusOfPipeTailEarlyExitTail(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "first.sh", `#!/bin/bash
v=$(git log --format=%H | sed q) || exit 1
w=$(git log --format=%H | sed -n 1p) || exit 1 # want
docker images | awk 'NR==2 {print $3; exit}'
docker images | awk 'NR==2 {print $3}' # want
`)
}

// pipefail set on the shebang line is in force for the whole script.
func TestShellStatusOfPipeTailShebangPipefail(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "short.sh", `#!/bin/bash -eo pipefail
curl -fsS "$URL" | jq .
`)
	shellWanted(t, "shell-status-of-pipe-tail", "env.sh", `#!/usr/bin/env -S bash -euo pipefail
curl -fsS "$URL" | jq .
`)
	shellWanted(t, "shell-status-of-pipe-tail", "plain.sh", `#!/bin/bash -e
curl -fsS "$URL" | jq . # want
`)
}

// The status a check reads is the status of the last command substitution
// of the assignment, and of the last command of its body: a pipeline that
// comes before them is not what || checks.
func TestShellStatusOfPipeTailCheckedStatusIsTheLast(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "last.sh", `#!/bin/bash
out="$(git describe --tags | sed 's/^v//')-$(date +%s)" || exit 1
out=$(curl -fsS "$URL" | jq -r .v; true) || echo never
out="$(date +%s)-$(git describe --tags | sed 's/^v//')" || exit 1 # want
a=$(curl -fsS u | jq .) || :
b=$(curl -fsS u | jq .) || b=
d=$(curl -fsS u | jq .) || { :; }
echo "$a$b$d$out"
`)
}

// Pipelines come from the parsed script, not from its text: a comment after
// $(, a group with a redirection and the time keyword hide no pipeline.
func TestShellStatusOfPipeTailPipelinesFromTheTree(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "tree.sh", `#!/bin/bash
out=$( # ask
  curl -fsS u | jq -r .v # want
) || exit 1
{ curl -fsS u | jq .; } > out.json # want
time curl -fsS u | jq . # want
`)
}

// In .graft.yaml a finding in a folded (>) or a quoted scalar that spans
// lines is on the line of the command, not on the line of the indicator.
func TestShellStatusOfPipeTailGraftScalarLines(t *testing.T) {
	root := t.TempDir()
	source := `tasks:
  a:
    run:
      - sh: >
          curl -fsS "$URL"
          | jq .
      - sh: "echo a
          ; curl -fsS u | jq ."
`
	require.NoError(t, os.WriteFile(filepath.Join(root, ".graft.yaml"), []byte(source), 0o600))
	got := patterntest.ShellFindingsIn(t, "shell-status-of-pipe-tail", root, ".graft.yaml")
	assert.ElementsMatch(t, []string{".graft.yaml:5", ".graft.yaml:8"}, got)
}
