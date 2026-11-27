package shellrules

import "testing"

// A pipeline from a command that can fail, inside $(…) whose empty value
// reads as success: a test -z of it, or the word list of a for loop. No one
// reads the status of such a substitution, pipefail or not, and errexit does
// not stop at it: when git, find or docker fails, the value is empty, the
// check passes and the loop does nothing.
func TestShellStatusOfPipeTailEmptyCaptureIsSuccess(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "check.sh", `#!/bin/bash
set -euo pipefail
test -z "$(git ls-files '*.go' | xargs -r gofmt -l)" # want
[ -z "$(git diff --name-only "$base" | grep -vE '\.md$')" ] && exit 0 # want
[[ -z $(docker ps --format '{{.Names}}' | grep "^$prefix") ]] || echo "still running" # want
for m in $(find tools -name go.mod | sort); do echo "$m"; done # want
for f in $(git diff --name-only HEAD^ | grep -xF "$mine" || true); do echo "$f"; done # want
`)
	// Without errexit the status of an assignment stops nothing: the empty
	// value goes on to the test.
	shellWanted(t, "shell-status-of-pipe-tail", "fmt.sh", `#!/bin/sh
out=$(git ls-files '*.go' | xargs -r gofmt -l); test -z "$out" # want
`)
}

// The same shapes are no lost failure when the producer cannot fail as one
// of the commands the rule knows, its errors are dropped on purpose, the
// value is not tested for emptiness, or errexit with pipefail stops at the
// assignment.
func TestShellStatusOfPipeTailEmptyCaptureNeighbours(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "ok.sh", `#!/bin/sh
test -z "$(git status --porcelain)" || exit 1
test -z "$(printf '%s\n' "$files" | sort)" || exit 1
for f in $(find . -name '*.go' 2>/dev/null | sort); do echo "$f"; done
for f in $(printf '%s\n' a b | sort); do echo "$f"; done
n=$(git ls-files | wc -l); echo "$n files"
# test -z "$(git ls-files | xargs gofmt -l)"
echo 'test -z "$(git ls-files | xargs gofmt -l)"'
`)
	shellWanted(t, "shell-status-of-pipe-tail", "strict.sh", `#!/bin/bash
set -eo pipefail
out=$(git ls-files '*.go' | xargs -r gofmt -l); test -z "$out"
files=$(find . -name '*.sql' | sort)
for f in $files; do psql -f "$f"; done
`)
}

// graft runs a step with sh -c: the loop over $(find … | sort) of a step
// loses a failed find the same way.
func TestShellStatusOfPipeTailEmptyCaptureGraftStep(t *testing.T) {
	graftWanted(t, ".graft.yaml", `tasks:
  vet-tools:
    run:
      - sh: 'for m in $(find tools -name go.mod | sort); do (cd "$(dirname "$m")" && go vet ./...); done' # want
  fmt-check:
    run:
      - sh: 'test -z "$(git ls-files "*.go" | xargs -r gofmt -l)"' # want
  fine:
    run:
      - sh: 'files=$(git ls-files "*.go") && test -z "$(printf "%s\n" "$files" | xargs -r gofmt -l)"'
`)
}
