package shellrules

import "testing"

// The assignment form asks about errexit at its own line: a set +e in a
// function that is not called before it leaves errexit on.
func TestShellStatusOfPipeTailEmptyCaptureErrexitOutsideFunction(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "fn.sh", `#!/bin/bash
set -eo pipefail
cleanup() { set +e; rm -f "$tmp"; }
out=$(git ls-files | sort); test -z "$out" && echo clean
`)
	shellWanted(t, "shell-status-of-pipe-tail", "envs.sh", `#!/usr/bin/env -S bash -e
set -o pipefail
out=$(git ls-files | sort); test -z "$out" && echo clean
`)
}

// A set inside a function or a subshell holds for the lines after it in the
// same body: the usual main() { set -euo pipefail; …; }; main stops at the
// failed assignment.
func TestShellStatusOfPipeTailEmptyCaptureErrexitInsideBody(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "main.sh", `#!/bin/bash
main() {
  set -euo pipefail
  out=$(git ls-files | sort); test -z "$out" && echo clean
}
main "$@"
`)
	shellWanted(t, "shell-status-of-pipe-tail", "sub.sh", `#!/bin/bash
(
  set -eo pipefail
  out=$(git ls-files | sort); test -z "$out" && echo clean
)
`)
	shellWanted(t, "shell-status-of-pipe-tail", "late.sh", `#!/bin/bash
main() {
  out=$(git ls-files | sort); test -z "$out" && echo clean # want
  set -euo pipefail
}
main "$@"
`)
}
