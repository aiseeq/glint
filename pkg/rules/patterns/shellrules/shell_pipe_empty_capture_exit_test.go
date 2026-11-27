package shellrules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A helper that always exits nonzero ends the script like exit 1 does.
func TestShellStatusOfPipeTailEmptyCaptureExitingHelper(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "die.sh", `#!/bin/bash
die() { echo "$*" >&2; exit 1; }
warn() { echo "$*" >&2; }
[ -z "$(git ls-files | grep go.mod)" ] && die "no go.mod"
if [ -z "$(docker ps | grep web)" ]; then die "web is down"; fi
out=$(git ls-files | sort); [ -z "$out" ] && die "no files"
[ -z "$(git ls-files | grep go.mod)" ] && warn "no go.mod" # want
`)
}

// Only an exit that always runs makes the empty value a failure: not one
// behind || or &&, in a subshell, or with a status that may be zero.
func TestShellStatusOfPipeTailEmptyCaptureConditionalExit(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "cond.sh", `#!/bin/bash
if [ -z "$(git diff --name-only | grep '\.go$')" ]; then cp a b || exit 1; echo "nothing to format"; fi # want
if [ -z "$(git diff --name-only | grep '\.go$')" ]; then echo clean; [ "$strict" = 1 ] && exit 1; fi # want
if [ -z "$(git status --porcelain | grep -v '^??')" ]; then echo clean; ( exit 1 ); fi # want
if [ -z "$(git ls-files | grep x)" ]; then echo none; exit "$OK"; fi # want
out=$(git ls-files | sort); if [ -z "$out" ]; then echo none; mkdir d || exit 1; fi # want
if [ -z "$(git ls-files | grep x)" ]; then { echo none >&2; exit 1; }; fi
`)
}

// set -- -e sets the positional parameters, not errexit.
func TestShellStatusOfPipeTailEmptyCapturePositionalE(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "pos.sh", `#!/bin/bash
set -- -e
set -o pipefail
v=$(git ls-files | sort); test -z "$v" && echo clean # want
`)
}

// A value with a default is never empty, and |& sends the errors of the
// producer into the value.
func TestShellStatusOfPipeTailEmptyCaptureNeverEmpty(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "never.sh", `#!/bin/bash
out=$(git ls-files | sort); [ -z "${out:-none}" ] && echo clean
test -z "$(git ls-files |& sort)" && echo clean
`)
}

// Under errexit and pipefail a declaration still hides the status, so its
// hint splits the declaration from the assignment instead of naming
// errexit. A for loop has no emptiness check to name.
func TestShellStatusOfPipeTailEmptyCaptureDeclarationHintAndLoopMessage(t *testing.T) {
	got := pipeTailViolations(t, "decl.sh", `#!/bin/bash
set -euo pipefail
f() { local out=$(git ls-files | sort); test -z "$out" && echo clean; }
for m in $(find tools -name go.mod | sort); do echo "$m"; done
`)
	require.Len(t, got, 2)
	assert.Contains(t, got[0].Suggestion, "local out;")
	assert.NotContains(t, got[0].Suggestion, "errexit")
	assert.NotContains(t, got[1].Message, "emptiness")
}
