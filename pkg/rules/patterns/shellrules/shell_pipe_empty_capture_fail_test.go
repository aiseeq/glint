package shellrules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An empty value that the script treats as a failure shows the failed
// producer too: the script stops with a nonzero status either way.
func TestShellStatusOfPipeTailEmptyCaptureEmptyIsFailure(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "fail.sh", `#!/bin/bash
if [ -z "$(git ls-files | grep go.mod)" ]; then echo "no go.mod" >&2; exit 1; fi
if [ -z "$(git ls-files | grep go.mod)" ]; then exit 1; fi
[ -z "$(git ls-files | grep go.mod)" ] && { echo "no go.mod" >&2; exit 1; }
test -z "$(git ls-files | grep go.mod)" && exit 1
out=$(git ls-files | sort); if [ -z "$out" ]; then echo "no files" >&2; exit 1; fi
out=$(git ls-files | sort); [ -z "$out" ] && exit 1
if [ -z "$(git ls-files | grep go.mod)" ]; then echo clean; fi # want
[ -z "$(git ls-files | grep go.mod)" ] && echo clean # want
out=$(git ls-files | sort); [ -z "$out" ] && echo clean # want
`)
}

// ! before the test turns -z into -n, and a lookup of a command path runs
// no producer.
func TestShellStatusOfPipeTailEmptyCaptureNegatedStatementAndLookup(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "not.sh", `#!/bin/bash
! [ -z "$(git ls-files | sort)" ]
if ! test -z "$(git ls-files | sort)"; then echo has; fi
for p in $(command -v -a git | sort -u); do echo "$p"; done
[ -z "$(command -v docker | head -1)" ] && echo "no docker"
[ -z "$(type -P git | head -1)" ] && echo "no git"
`)
}

// local, export and declare return their own status, so errexit with
// pipefail does not stop at a failed capture inside them.
func TestShellStatusOfPipeTailEmptyCaptureDeclarationMasksStatus(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "decl.sh", `#!/bin/bash
set -euo pipefail
f() { local out=$(git ls-files | sort); test -z "$out" && echo clean; } # want
g() { export OUT=$(git ls-files | sort); test -z "$OUT" && echo clean; } # want
declare files=$(git ls-files | sort); test -z "$files" && echo clean # want
h() { local out; out=$(git ls-files | sort); test -z "$out" && echo clean; }
`)
}

// errexit is on in every spelling of set, and a function runs with the
// options of the place it is called from.
func TestShellStatusOfPipeTailEmptyCaptureMoreErrexitSpellings(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "x.sh", `#!/bin/bash
set -x -e
set -o pipefail
out=$(git ls-files | sort); test -z "$out" && echo clean
`)
	shellWanted(t, "shell-status-of-pipe-tail", "late.sh", `#!/bin/bash
set -o pipefail -e
out=$(git ls-files | sort); test -z "$out" && echo clean
`)
	shellWanted(t, "shell-status-of-pipe-tail", "func.sh", `#!/bin/bash
f() {
  out=$(git ls-files | sort); test -z "$out" && echo clean
}
set -eo pipefail
f
`)
}

// Make stops a recipe at a failed line when -e comes from SHELL or from
// .SHELLFLAGS in any order.
func TestShellStatusOfPipeTailEmptyCaptureMakeErrexit(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "Makefile", `SHELL := /bin/bash -eo pipefail
fmt:
  out=$$(git ls-files | sort); test -z "$$out"
`)
	shellWanted(t, "shell-status-of-pipe-tail", "GNUmakefile", `SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -ec
fmt:
  out=$$(git ls-files | sort); test -z "$$out"
`)
}

// Without pipefail, out=$(git … | sort) || exit 1 still reads the status of
// sort, so the hint captures the producer alone and filters the value later.
func TestShellStatusOfPipeTailEmptyCaptureHintCapturesProducerAlone(t *testing.T) {
	got := pipeTailViolations(t, "alone.sh", `#!/bin/bash
test -z "$(git ls-files '*.go' | xargs -r gofmt -l)"
for m in $(find tools -name go.mod | sort); do echo "$m"; done
out=$(git ls-files | sort); test -z "$out" && echo clean
`)
	require.Len(t, got, 3)
	for _, v := range got {
		assert.Regexp(t, `=\$\((git|find)[^|]*\) \|\| exit 1`, v.Suggestion)
		assert.NotRegexp(t, `\$\([^)]*\|[^)]*\) \|\| exit 1`, v.Suggestion)
	}
}
