package shellrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pipeTailViolations runs shell-status-of-pipe-tail over one script.
func pipeTailViolations(t *testing.T, path, source string) []*core.Violation {
	t.Helper()
	rule, ok := rules.Get("shell-status-of-pipe-tail")
	require.True(t, ok)
	return rule.AnalyzeFile(rulestest.TextFile(t, path, source))
}

// The producer is the command a wrapper runs: sudo, command and env start
// docker or git, whose failure leaves the value empty.
func TestShellStatusOfPipeTailEmptyCaptureBehindWrappers(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "wrap.sh", `#!/bin/bash
test -z "$(sudo docker ps | grep web)" # want
test -z "$(sudo -n docker ps --format '{{.Names}}' | grep "^$prefix")" || echo "stopped" # want
test -z "$(command git ls-files | sort)" # want
test -z "$(env GIT_DIR=repo git ls-files | sort)" # want
test -z "$(sudo printf x | sort)"
`)
}

// The assignment form reads the empty value as success in an if and in
// [[ ]] too, quoted or not.
func TestShellStatusOfPipeTailEmptyCaptureAssignmentTests(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "if.sh", `#!/bin/sh
out=$(git ls-files | sort); if [ -z "$out" ]; then echo clean; fi # want
`)
	shellWanted(t, "shell-status-of-pipe-tail", "dbl.sh", `#!/bin/bash
out=$(git ls-files | sort); [[ -z "$out" ]] && echo clean # want
out=$(git ls-files | sort); [[ -z $out ]] && echo clean # want
`)
}

// errexit with pipefail stops at the failed assignment in every spelling:
// set -o errexit, set -e on a line of its own, the -e of the shebang. set +e
// turns it off again.
func TestShellStatusOfPipeTailEmptyCaptureErrexitSpellings(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "long.sh", `#!/bin/bash
set -o errexit -o pipefail
out=$(git ls-files | xargs -r gofmt -l); test -z "$out"
`)
	shellWanted(t, "shell-status-of-pipe-tail", "bang.sh", `#!/bin/bash -e
set -o pipefail
out=$(git ls-files | xargs -r gofmt -l); test -z "$out"
`)
	shellWanted(t, "shell-status-of-pipe-tail", "apart.sh", `#!/bin/bash
set -e
set -o pipefail
out=$(git ls-files | xargs -r gofmt -l); test -z "$out"
`)
	shellWanted(t, "shell-status-of-pipe-tail", "off.sh", `#!/bin/bash
set -eo pipefail
set +e
out=$(git ls-files | xargs -r gofmt -l); test -z "$out" # want
`)
}

// pipefail in .SHELLFLAGS of a Makefile does not help a test -z or a for
// loop over a substitution: nobody reads its status.
func TestShellStatusOfPipeTailEmptyCaptureMakePipefail(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "Makefile", `SHELL := /bin/bash
.SHELLFLAGS := -eo pipefail -c
fmt:
  test -z "$$(git ls-files '*.go' | xargs -r gofmt -l)" # want
  for m in $$(find tools -name go.mod | sort); do echo "$$m"; done # want
`)
}

// ! -z is -n; an error sent into the value (2>&1) makes it non-empty, and
// &>/dev/null drops the errors on purpose.
func TestShellStatusOfPipeTailEmptyCaptureNegatedAndRedirected(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "neg.sh", `#!/bin/bash
test ! -z "$(git ls-files | sort)" && echo some
[ ! -z "$(git ls-files | sort)" ] && echo some
[[ ! -z $(git ls-files | sort) ]] && echo some
test -z "$(git ls-files 2>&1 | sort)" || exit 1
test -z "$(git ls-files &>/dev/null | sort)"
`)
}

// The message names the producer; the hint fits the form. pipefail does not
// fix a test -z or a for loop over a substitution, so their hint checks the
// status of a separate assignment.
func TestShellStatusOfPipeTailEmptyCaptureMessageAndHint(t *testing.T) {
	got := pipeTailViolations(t, "hint.sh", `#!/bin/bash
set -euo pipefail
test -z "$(git ls-files '*.go' | xargs -r gofmt -l)"
for m in $(find tools -name go.mod | sort); do echo "$m"; done
`)
	require.Len(t, got, 2)
	assert.Contains(t, got[0].Message, "git")
	assert.Contains(t, got[1].Message, "find")
	for _, v := range got {
		assert.NotContains(t, v.Suggestion, "pipefail")
		assert.Contains(t, v.Suggestion, "|| exit 1")
	}
}
