package shellrules

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// graftWanted runs shell-status-of-pipe-tail over a .graft.yaml written as
// is (no recipe indents) and compares the findings with the lines marked
// "# want".
func graftWanted(t *testing.T, name, source string) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(source), 0o600))
	var want []string
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "# want") {
			want = append(want, fmt.Sprintf("%s:%d", name, i+1))
		}
	}
	got := patterntest.ShellFindingsIn(t, "shell-status-of-pipe-tail", root, name)
	sort.Slice(got, func(i, j int) bool { return lineOfFinding(got[i]) < lineOfFinding(got[j]) })
	if len(want) == 0 {
		assert.Empty(t, got)
		return
	}
	assert.Equal(t, want, got)
}

// A pipeline from a command that can fail into a filter, with no pipefail:
// the pipeline's status is the filter's 0. As the last command of a script
// it is the script's status, and the script exits 0 when ssh, curl or find
// failed.
func TestShellStatusOfPipeTailProducerLastCommand(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "check.sh", `#!/bin/sh
set -eu
filter=.data
ssh "$HOST" "bash -s" < probe.sh | jq "$filter" # want
`)
	// Not the last command, even under set -e: logs shown on the way to a
	// failure lose nothing the script reports.
	shellWanted(t, "shell-status-of-pipe-tail", "deploy.sh", `#!/bin/bash
set -e
wait_healthy() {
if ! curl -fsS "$URL/health"; then
echo "last logs:"
docker logs "$name" 2>&1 | tail -20
return 1
fi
}
curl -fsS "$URL/status" | jq -r .version
echo done
`)
	// grep exits 1 when it finds nothing: a help target listing its own
	// make file loses no failure.
	shellWanted(t, "shell-status-of-pipe-tail", "Makefile", `help:
  @grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "%-12s %s\n", $$1, $$2}'
`)
	// pipefail of a heredoc sent to a remote shell does not cover the script.
	shellWanted(t, "shell-status-of-pipe-tail", "remote.sh", `#!/bin/sh
ssh "$HOST" 'bash -s' <<'REMOTE'
set -o pipefail
ls /srv
REMOTE
curl -fsS "$URL" | jq . # want
`)
	// pipefail above covers the pipeline.
	shellWanted(t, "shell-status-of-pipe-tail", "check.sh", `#!/bin/bash
set -euo pipefail
ssh "$HOST" "bash -s" < probe.sh | jq .data
`)
	// The status is read from PIPESTATUS.
	shellWanted(t, "shell-status-of-pipe-tail", "check.sh", `#!/bin/bash
ssh "$HOST" "bash -s" < probe.sh | jq .data
exit "${PIPESTATUS[0]}"
`)
	// The answer is taken first, and the producer of the pipeline cannot fail.
	shellWanted(t, "shell-status-of-pipe-tail", "check.sh", `#!/bin/sh
set -eu
resp=$(ssh "$HOST" "bash -s" < probe.sh)
printf '%s\n' "$resp" | jq .data
`)
	// Not the last command and no set -e: nobody reads the status.
	shellWanted(t, "shell-status-of-pipe-tail", "report.sh", `#!/bin/sh
ssh "$HOST" uptime | sort
echo done
`)
}

// A pipeline captured with $(...) whose status is read by && or ||: the
// capture's status is the last command's, and a failed find passes.
func TestShellStatusOfPipeTailProducerCapture(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "fmt.sh", `#!/bin/sh
out=$(find . -name "*.go" -print0 | xargs -0 -r gofmt -l) && test -z "$out" || { echo "$out"; exit 1; } # want
`)
	shellWanted(t, "shell-status-of-pipe-tail", "fmt.sh", `#!/bin/sh
files=$(find . -name "*.go") && out=$(printf '%s\n' "$files" | xargs -r gofmt -l) && test -z "$out" || exit 1
`)
	shellWanted(t, "shell-status-of-pipe-tail", "fmt.sh", `#!/bin/bash
set -o pipefail
out=$(find . -name "*.go" -print0 | xargs -0 -r gofmt -l) && test -z "$out" || exit 1
`)
}

// graft runs each sh: step of .graft.yaml with sh -c, a shell of its own:
// the step is a script, and pipefail set in one step does not cover another.
func TestShellStatusOfPipeTailGraftSteps(t *testing.T) {
	graftWanted(t, ".graft.yaml", `tasks:
  api-check:
    desc: ask the API
    run:
      - sh: |
          set -eu
          ssh "$HOST" "bash -s" < probe.sh | jq "$filter" # want
  fmt-check:
    run:
      - sh: 'out=$(find . -name "*.go" -print0 | xargs -0 -r gofmt -l) && test -z "$out" || { echo "$out"; exit 1; }' # want
  separate:
    run:
      - sh: 'set -o pipefail'
      - sh: 'curl -fsS "$URL" | jq .' # want
  safe:
    run:
      - sh: |
          set -o pipefail
          ssh "$HOST" uptime | jq .
      - sh: 'printf "%s\n" "$resp" | jq .'
      - sh: 'git ls-files | wc -l; echo done'
      - sh: 'resp=$(ssh "$HOST" uptime) && printf "%s\n" "$resp" | jq .'
`)
	// Only graft's own file is read as graft steps.
	graftWanted(t, "settings.yaml", `tasks:
  api-check:
    run:
      - sh: 'curl -fsS "$URL" | jq .'
`)
}

// pipefail is set by a command anywhere on a line: after ; or &&, behind a
// guard, indented in a function or an if. It covers the pipelines below it,
// in the new forms and in the $? form alike.
func TestShellStatusOfPipeTailPipefailAnywhereOnTheLine(t *testing.T) {
	for name, source := range map[string]string{
		"semi.sh": `#!/bin/bash
cd /srv; set -o pipefail
curl -fsS "$URL" | jq .
`,
		"and.sh": `#!/bin/bash
cd /srv && set -o pipefail && curl -fsS "$URL" | jq .
`,
		"guard.sh": `#!/bin/bash
[ -n "$BASH_VERSION" ] && set -o pipefail
curl -fsS "$URL" | jq .
`,
		"func.sh": `#!/bin/bash
fetch() {
    set -euo pipefail
    out=$(curl -fsS "$URL" | jq .) && printf '%s\n' "$out"
}
fetch
`,
		"if.sh": `#!/bin/bash
if [ -n "$BASH_VERSION" ]; then
    set -o pipefail
fi
ssh "$HOST" uptime | sort
`,
		"status.sh": `#!/bin/bash
cd /srv; set -o pipefail
make test | tee log
[ $? -eq 0 ] || exit 1
`,
	} {
		t.Run(name, func(t *testing.T) { shellWanted(t, "shell-status-of-pipe-tail", name, source) })
	}
	shellWanted(t, "shell-status-of-pipe-tail", "Makefile", `test:
  cd x && set -o pipefail && go test ./... | tee log; test $$? -eq 0
`)
}

// A fallback to the empty string is what the filter gives anyway when the
// producer fails; a fallback to another value is lost.
func TestShellStatusOfPipeTailCaptureFallback(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "deploy.sh", `#!/bin/bash
version=$(ssh "$HOST" "cat /app/VERSION" | tr -d '[:space:]') || version=""
[ "$version" = "$want" ] || exit 1
`)
	shellWanted(t, "shell-status-of-pipe-tail", "deploy.sh", `#!/bin/bash
version=$(ssh "$HOST" "cat /app/VERSION" | tr -d '[:space:]') || version=unknown # want
echo "$version"
`)
}

// More shapes of a checked capture.
func TestShellStatusOfPipeTailCaptureShapes(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "fmt.sh", `#!/bin/sh
out="$(find . -name '*.go' | xargs -r gofmt -l)" && test -z "$out" # want
`)
	shellWanted(t, "shell-status-of-pipe-tail", "fetch.sh", `#!/bin/sh
if ! out=$(curl -fsS "$URL" | jq .); then # want
exit 1
fi
`)
}

// A pipeline that does not give the status of the script.
func TestShellStatusOfPipeTailNotTheScriptStatus(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "bg.sh", `#!/bin/sh
curl -fsS "$URL" | jq . &
`)
	shellWanted(t, "shell-status-of-pipe-tail", "Makefile", `.ONESHELL:
check:
  curl -fsS "$URL" | jq .
  echo done
`)
}

// graft runs the steps of its top-level gate like the steps of a task.
func TestShellStatusOfPipeTailGraftGate(t *testing.T) {
	graftWanted(t, ".graft.yaml", `gate:
  - sh: 'curl -fsS "$URL" | jq .' # want
tasks:
  x:
    run:
      - sh: 'echo ok'
`)
}

// pipefail set among other options, or with shopt, covers the script as it
// did before the new forms: the old forms stay as they were.
func TestShellStatusOfPipeTailPipefailOptionForms(t *testing.T) {
	for name, set := range map[string]string{
		"e-o.sh":   "set -e -o pipefail",
		"long.sh":  "set -o errexit -o nounset -o pipefail",
		"shopt.sh": "shopt -so pipefail",
	} {
		t.Run(name, func(t *testing.T) {
			shellWanted(t, "shell-status-of-pipe-tail", name, "#!/bin/bash\n"+set+`
make test | tee log
[ $? -eq 0 ] || exit 1
curl -fsS "$URL" | jq .
`)
		})
	}
}

// pipefail acts when the script runs: a function declared above it and
// called below runs under it.
func TestShellStatusOfPipeTailPipefailBeforeTheCall(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "late.sh", `#!/bin/bash
fetch() {
    ssh "$HOST" cat /etc/v | head -1 | cut -d= -f2-
}
main() {
    v="$(fetch)"
    echo "$v"
}
set -o pipefail
main
`)
}

// A checked capture anywhere in the script, not only at its start.
func TestShellStatusOfPipeTailCheckedCaptureMidScript(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "fetch.sh", `#!/bin/sh
echo start
if ! out=$(curl -fsS "$URL" | jq .); then # want
exit 1
fi
if [ -n "$A" ]; then
echo a
elif v=$(ssh "$HOST" uptime | sort); then # want
echo "$v"
fi
`)
}

// The old $? form inside a heredoc for a remote shell is reported as before:
// the remote shell runs without pipefail too.
func TestShellStatusOfPipeTailStatusInRemoteHeredoc(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "remote.sh", `#!/bin/sh
ssh "$HOST" bash -s <<'R'
cd /srv
make build | tee log
echo $? # want
R
`)
}

// A script the parser cannot read keeps the old forms' pipefail reading.
func TestShellStatusOfPipeTailUnparsedScript(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "parse.sh", `#!/bin/bash
set -euo pipefail
make test | tee log
echo $?
x=$(( 1 + ))
`)
}

// Shapes that are not a lost failure: the author drops the failure on
// purpose, and head ends the producer with SIGPIPE, so pipefail would fail a
// good run.
func TestShellStatusOfPipeTailNotALostFailure(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "ignore.sh", `#!/bin/sh
e=$(curl -fsS "$URL" | jq .) || true
echo "$e"
`)
	shellWanted(t, "shell-status-of-pipe-tail", "log.sh", `#!/bin/sh
git log --oneline | head -5
`)
}

// Only a .ONESHELL: line makes a recipe one shell; the word in a comment
// does not.
func TestShellStatusOfPipeTailOneShellDirectiveOnly(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "Makefile", `# no .ONESHELL: here, each line is a shell of its own
check:
  curl -fsS "$URL" | jq . # want
  echo done
`)
}

// head on the tail of a captured pipeline is not a lost failure either: with
// pipefail the producer ends on SIGPIPE with 141 and a good run fails.
func TestShellStatusOfPipeTailCaptureHeadTail(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "tag.sh", `#!/bin/sh
v=$(git tag --list | head -n1) && echo "$v"
files=$(find . -name '*.go' | head -n 3) && echo "$files"
`)
}

// Each graft step is a shell of its own: $? of the next step is not the
// status of the pipeline in the step before, and pipefail of one step does
// not cover another.
func TestShellStatusOfPipeTailGraftStepsAreShellsApart(t *testing.T) {
	graftWanted(t, ".graft.yaml", `tasks:
  t:
    run:
      - sh: 'set -o pipefail'
      - sh: 'make test | tee log; test $? -eq 0' # want
      - sh: 'make build | tee b.log'
      - sh: 'echo $?'
`)
}

// local, export and readonly return their own status, not the
// substitution's: pipefail would not make the check see a failure.
func TestShellStatusOfPipeTailDeclarationCapture(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "decl.sh", `#!/bin/bash
f() {
    local v=$(curl -fsS "$URL" | jq .) || return 1
    export w=$(ssh "$HOST" uptime | sort) && echo "$w"
    readonly x=$(git log | sort) || exit 1
}
f
`)
}

// || : drops the failure as || true does; || VAR= with nothing after the
// sign sets the same empty value.
func TestShellStatusOfPipeTailCaptureDroppedOnPurpose(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "drop.sh", `#!/bin/sh
a=$(curl -fsS "$URL" | jq .) || :
b=$(ssh "$HOST" uptime | sort) || b=
echo "$a$b"
`)
}

// A | in a comment is not a pipeline; quoted pipefail, builtin set and the
// pipefail query of shopt read as the shell reads them.
func TestShellStatusOfPipeTailCommentsAndOptionWords(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "comment.sh", `#!/bin/sh
curl -fsS "$URL" -o out.json # then | jq .
`)
	shellWanted(t, "shell-status-of-pipe-tail", "quoted.sh", `#!/bin/bash
set -o "pipefail"
curl -fsS "$URL" | jq .
`)
	shellWanted(t, "shell-status-of-pipe-tail", "builtin.sh", `#!/bin/bash
builtin set -o pipefail
curl -fsS "$URL" | jq .
`)
	shellWanted(t, "shell-status-of-pipe-tail", "query.sh", `#!/bin/bash
shopt -qo pipefail || echo "no pipefail"
curl -fsS "$URL" | jq . # want
`)
}

// jq -e fails on empty input by itself: a failed producer leaves jq nothing
// to read, and the pipeline fails without pipefail.
func TestShellStatusOfPipeTailJqExitStatusTail(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "ok.sh", `#!/bin/sh
ok=$(curl -fsS "$URL" | jq -re '.ok') && echo "$ok"
v=$(ssh "$HOST" cat /etc/v.json | jq --exit-status .v) || exit 1
w=$(curl -fsS "$URL" | jq -r .w) || exit 1 # want
curl -fsS "$URL" | jq -e '.ok == true'
`)
}
