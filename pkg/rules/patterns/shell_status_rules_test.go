package patterns

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// shellWanted runs a rule over one file and compares its findings with the
// lines marked "# want".
func shellWanted(t *testing.T, rule, path, source string) {
	t.Helper()
	var want []string
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "# want") {
			want = append(want, fmt.Sprintf("%s:%d", path, i+1))
		}
	}
	got := shellFindings(t, rule, map[string]string{path: source})
	sort.Slice(got, func(i, j int) bool { return lineOfFinding(got[i]) < lineOfFinding(got[j]) })
	if len(want) == 0 {
		assert.Empty(t, got)
		return
	}
	assert.Equal(t, want, got)
}

func lineOfFinding(finding string) int {
	_, line, _ := strings.Cut(finding, ":")
	n, _ := strconv.Atoi(line)
	return n
}

// Repro from a real project: a match run by a sibling script was captured
// with || true, and a crashed run counted as a game with zero kills.
func TestShellFailureFallbackValueSiblingScript(t *testing.T) {
	shellWanted(t, "shell-failure-fallback-value", "series.sh", `#!/bin/bash
repo=$(cd "$(dirname "$0")/.." && pwd)
for i in 1 2 3; do
  out=$("$repo/tools/match.sh" "$1" "$2" 2>&1) || true # want
  kills=$(echo "$out" | grep -o 'kills=[0-9]*' | cut -d= -f2)
  printf '%s %s\n' "$i" "${kills:-0}" >> "$tmp/res"
done
total=$(./count.sh "$tmp/res" 2>&1 || true) # want
viewer=$(ssh "$host" '~/bin/viewer.sh' 2>/dev/null || true) # want
if [ -z "$viewer" ]; then
  pkill -9 -f stream
  start_stream
fi
`)
}

// Repro from a real project: the parallel runs of a series wrote their logs
// with || true, and the totals defaulted every missing figure to 0 - a crashed
// match entered the averages as a game with no kills.
func TestShellFailureFallbackValueRunLog(t *testing.T) {
	shellWanted(t, "shell-failure-fallback-value", "series.sh", `#!/bin/bash
run_one() {
    WORKER=$(( base + ($1 - 1) % jobs + 1 )) "$repo/tools/match.sh" "$v" "$foe" > "$tmp/$1.log" 2>&1 || true # want
}
for i in 1 2 3; do run_one "$i" & done
wait
for i in 1 2 3; do
    k=$(grep -o 'kills=[0-9]*' "$tmp/$i.log" | cut -d= -f2); k=${k:-0}
    kills=$((kills + k))
done
`)
	shellWanted(t, "shell-failure-fallback-value", "keep.sh", `#!/bin/bash
"$repo/tools/match.sh" "$v" > "$tmp/run.log" 2>&1 || true
grep -c ERROR "$tmp/run.log" || true
`)
}

// Repro from a real project: a count read from a log or a remote query fell
// back to a literal 0, and the 0 then started a restart or named a file.
func TestShellFailureFallbackValueLiteral(t *testing.T) {
	shellWanted(t, "shell-failure-fallback-value", "save.sh", `#!/bin/bash
loop=$(grep -o 'loop=[0-9]*' "$work/log" | tail -1 | grep -o '[0-9]*' || echo 0) # want
sessions=$(ssh "$host" 'sudo -n curl -s http://localhost/api' 2>/dev/null || echo 0) # want
probe() { sudo -n docker exec "$1" python3 /probe.py 2>/dev/null || echo "0 0 0"; } # want
read -r a b c <<< "$(probe "$name")"
shot() { # shot <box> -> "<menu> <hud>"
  sudo -n docker exec "$1" bash -c '
    grab /tmp/s.ppm
    python3 - <<"PY"
print(1, 2)
PY' 2>/dev/null || echo "0 0" # want
}
read -r m h <<< "$(shot "$name")"
`)
	// A fallback for a command whose failure is an answer: no file, no
	// config key, a count of zero.
	shellWanted(t, "shell-failure-fallback-value", "ok.sh", `#!/bin/bash
v=$(cat VERSION 2>/dev/null || echo dev)
user=$(git config user.name || echo unknown)
n=$(wc -l < "$f" || echo 0)
css=$(printf '%s' "$body" | grep -o 'assets/[^"]*\.css' | head -n 1 || true)
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 https://example.test/health || true)
domain=$(docker exec app printenv BASE_DOMAIN 2>/dev/null || true)
if [ -z "$domain" ]; then
  echo "no BASE_DOMAIN" >&2
  exit 1
fi
for i in 1 2 3; do
  body=$(ssh "$host" "curl -sf http://127.0.0.1/health" || echo "")
  if echo "$body" | grep -q ok; then break; fi
  sleep 1
done
`)
}

// Repro from a real project: the wait counter was compared with the steps of
// a retry ladder, not with the bound - the loop still fell through on timeout.
func TestShellPollLoopFallsThroughLadder(t *testing.T) {
	shellWanted(t, "shell-poll-loop-falls-through", "wait.sh", `#!/bin/bash
for i in $(seq 1 90); do # want
  ready && break
  if [ "$i" -gt 20 ]; then
    nudge
  elif [ "$i" -gt 35 ]; then
    nudge harder
  fi
  sleep 1
done
stage "appeared"
for i in $(seq 1 30); do
  ready && break
  [ "$i" -eq 30 ] && echo "gave up" >&2
  sleep 1
done
stage "second"
`)
	// The check after the loop is a command with a failure branch, or stands
	// after the if that closes around the loop.
	shellWanted(t, "shell-poll-loop-falls-through", "checked.sh", `#!/bin/bash
for i in $(seq 1 40); do
    docker exec "$c" sh -c 'grep -q ":1388" /proc/net/tcp' 2>/dev/null && break
    sleep 2
done
docker exec "$c" sh -c 'grep -q ":1388" /proc/net/tcp' 2>/dev/null \
    || { echo "api did not come up" >&2; exit 1; }
if [ -z "$tgt" ]; then
    case "$mode" in a) echo a;; *) echo b;; esac
    for i in $(seq 1 50); do
        if ready "$a"; then tgt=$a; break; fi
        sleep 3
    done
fi
if [ -z "$tgt" ]; then
    tgt=$fallback
fi
`)
}

// Repro from a real project: two timelines made by a sibling script with its
// stderr dropped were diffed - two failed runs compared equal.
func TestShellPipeProducerStderrSiblingScript(t *testing.T) {
	shellWanted(t, "shell-pipe-producer-stderr-discarded", "diff.sh", `#!/bin/bash
"$repo/tools/timeline.sh" "$a" "$map" 2>/dev/null | pick > "$work/a" # want
"$repo/tools/timeline.sh" "$a" "$map" | pick > "$work/b"
diff "$work/a" "$work/b"
`)
	// The output goes to a file the next steps read: without set -e and a
	// status check a failure leaves an empty file that compares as a result.
	shellWanted(t, "shell-pipe-producer-stderr-discarded", "check.sh", `#!/bin/bash
set -uo pipefail
fact=$(mktemp)
"$repo/tools/render.sh" "$replay" "$map" > "$fact" 2>/dev/null # want
docker run --rm -v "$dir:/data" parser /data/a.bin 2>/dev/null > "$out" # want
"$repo/tools/render.sh" "$replay" > "$checked" 2>/dev/null || exit 1
if "$repo/tools/render.sh" "$replay" > "$tested" 2>/dev/null; then cat "$tested"; fi
"$repo/tools/render.sh" "$replay" > "$sized" 2>/dev/null
[ -s "$sized" ] || exit 1
engine=docker
docker info > /dev/null 2>&1 || engine=podman
run_one() {
    $engine run --rm --entrypoint /work/parse "$image" -in "$1" 2>/dev/null > "$2" # want
}
awk -f compare.awk "$fact" "$out" "$checked" "$sized"
`)
	shellWanted(t, "shell-pipe-producer-stderr-discarded", "strict.sh", `#!/bin/bash
set -euo pipefail
"$repo/tools/render.sh" "$replay" "$map" > "$fact" 2>/dev/null
`)
}

// Repro from a real project: a make target ran the tests piped into grep,
// and the target's status was grep's - failed tests passed the target.
func TestShellStatusOfPipeTailMakeRecipe(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "Makefile", `spec:
  SPEC=1 go test -count=1 -run 'TestSpec' -v ./spec/ 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL)' # want

lint:
  go vet ./... 2>&1 | tee vet.log; exit $${PIPESTATUS[0]}
`)
	shellWanted(t, "shell-status-of-pipe-tail", "Makefile", `SHELL := /bin/bash
.SHELLFLAGS := -eo pipefail -c

spec:
  go test ./spec/ 2>&1 | grep -E '^(--- |ok|FAIL)'
`)
}

// Repro from a real project: under set -e and pipefail a list of names
// grepped from a text stopped the script when the text named none, though an
// empty list was a valid answer the next line iterated over.
func TestShellSetEExitsBeforeHandlerList(t *testing.T) {
	shellWanted(t, "shell-set-e-exits-before-failure-handler", "names.sh", `#!/bin/bash
# usage: names.sh <<'EOF'
#   text
# EOF
set -euo pipefail
named=$(printf '%s\n' "$body" | grep -oE '[a-z]+\.log' | sort -u) # want
items=$(for l in $named; do echo "$l"; done)
`)
}

// Repro from a real project: read <<< "$(finder)" || { not found } - the
// status is read's, which succeeds on the newline the here-string adds, so a
// failed finder went on with empty fields.
func TestShellReadFromSubstitutionStatus(t *testing.T) {
	shellWanted(t, "shell-read-status-of-substitution", "form.sh", `#!/bin/bash
read -r FIELD BUTTON <<< "$(python3 find.py shot.ppm)" || { echo 'form not found'; exit 3; } # want
if read -r x y <<< "$(probe "$c")"; then # want
  echo "$x"
fi
found=$(python3 find.py shot.ppm) || found=
read -r FIELD BUTTON <<< "$found"
read -r a b <<< "$line" || true
read -r p q <<< "$(probe "$c")"
read -r base from <<< "$(chain "$br")" || true
if ready && read -r m h <<< "$(probe "$c")" && [ "${h:-0}" -gt 3 ]; then echo up; fi
`)
}

// Repro from a real project: cmd | grep -v noise || true under pipefail -
// meant to excuse grep's empty result, it also excused the container's crash.
func TestShellPipelineOrTrueHidesProducer(t *testing.T) {
	shellWanted(t, "shell-pipeline-or-true-hides-producer", "run.sh", `#!/bin/bash
set -euo pipefail
docker run --rm img 2>&1 | grep -vE "INFO started" || true # want
docker run --rm -v "$w:/w" img \
  -map "$map" 2>&1 |
  grep -vE "INFO started" || true # want
docker run --rm img 2>&1 | { grep -vE "INFO started" || true; }
grep -c x "$f" || true
`)
	// Without pipefail the status is grep's alone.
	shellWanted(t, "shell-pipeline-or-true-hides-producer", "plain.sh", `#!/bin/bash
set -eu
docker run --rm img 2>&1 | grep -v "INFO" || true
`)
}

// Repro from a real project: under set -e a container's output was filtered
// with grep -v, and a run whose every line was filtered out stopped the
// script.
func TestShellGrepFilterExitsOnEmpty(t *testing.T) {
	shellWanted(t, "shell-grep-filter-exits-on-empty", "run.sh", `#!/bin/bash
set -euo pipefail
docker run --rm img 2>&1 | grep -v 'INFO' # want
rest=$(sort "$f" | grep -v '^#') # want
docker run --rm img 2>&1 | { grep -v 'INFO' || true; }
if docker ps | grep -v NAMES; then echo running; fi
docker ps | grep -v NAMES || echo none
grep -q ready "$log"
bad=$(gofmt -l . | grep -vE '^vendor/' || true)
`)
	shellWanted(t, "shell-grep-filter-exits-on-empty", "loose.sh", `#!/bin/bash
docker run --rm img 2>&1 | grep -v 'INFO'
`)
}

// Repro from a real project: a match's status was saved with || rc=$? into a
// .rc file that nothing read, and a crashed match was scored as a loss.
func TestShellSavedStatusUnread(t *testing.T) {
	shellWanted(t, "shell-saved-status-unread", "series.sh", `#!/bin/bash
run_one() {
  local rc=0
  ./match.sh "$1" > "$tmp/$1.log" 2>&1 || rc=$? # want
  echo "$rc" > "$tmp/$1.rc"
}
run_two() {
  local code=0
  ./match.sh "$1" > "$tmp/$1.log" 2>&1 || code=$? # want
}
run_one a
`)
	shellWanted(t, "shell-saved-status-unread", "read.sh", `#!/bin/bash
run_one() {
  local rc=0
  ./match.sh "$1" > "$tmp/$1.log" 2>&1 || rc=$?
  echo "$rc" > "$tmp/$1.rc"
}
for n in a b; do
  [ "$(cat "$tmp/$n.rc")" = 0 ] || echo "$n failed"
done
step || st=$?
[ "${st:-0}" -eq 0 ] || exit "$st"
filter() {
  local rc=0
  grep -v '^TAG=' "$1" > "$2" || rc=$?
  if (( rc > 1 )); then return 1; fi
}
echo "run exit=$?"
`)
}

// Repro from a real project: a queue of runs with no set -e ran each step
// into a log and never looked at its status - a failed run printed "(no
// totals)" and the queue reported done.
func TestShellLoopIgnoresStepFailure(t *testing.T) {
	shellWanted(t, "shell-loop-ignores-step-failure", "queue.sh", `#!/bin/bash
set -uo pipefail
for pair in "$@"; do
  "$repo/tools/ab.sh" "$pair" > "$log" 2>&1 # want
  grep -E 'total:' "$log" || echo '  (no totals)'
done
echo 'queue done'
`)
	shellWanted(t, "shell-loop-ignores-step-failure", "checked.sh", `#!/bin/bash
set -uo pipefail
fail=0
for pair in "$@"; do
  "$repo/tools/ab.sh" "$pair" > "$log" 2>&1 || fail=1
  ./step.sh "$pair" > "$log" 2>&1
  [ $? -eq 0 ] || fail=1
  ./job.sh "$pair" > "$out/$pair.log" 2>&1 &
done
wait
echo "queue done"
exit $fail
`)
	shellWanted(t, "shell-loop-ignores-step-failure", "strict.sh", `#!/bin/bash
set -euo pipefail
for pair in "$@"; do
  "$repo/tools/ab.sh" "$pair" > "$log" 2>&1
done
echo 'queue done'
`)
}

// Repro from a real project: under set -e the tests ran with stdout to
// /dev/null - a failure stopped the script with no word of which test.
func TestShellCheckOutputDiscarded(t *testing.T) {
	shellWanted(t, "shell-check-output-discarded", "gate.sh", `#!/bin/bash
set -euo pipefail
go test ./... >/dev/null 9>&- # want
go vet ./... > /dev/null 2>&1 # want
go test ./... > "$testlog" 2>&1 || { grep FAIL "$testlog" >&2; exit 1; }
go build ./... >/dev/null || { echo "build failed" >&2; exit 1; }
if go test ./x/ >/dev/null 2>&1; then echo ok; fi
go test ./...
`)
	shellWanted(t, "shell-check-output-discarded", "loose.sh", `#!/bin/bash
go test ./... >/dev/null
`)
}

// Repro from a real project: a loop that ended the script closed with
// [ $mark -eq 1 ] && echo ... - the last unmarked id made the script exit 1.
func TestShellTestAndLastStatus(t *testing.T) {
	shellWanted(t, "shell-test-and-last-status", "mark.sh", `#!/bin/bash
emit() {
  [ -n "$1" ] && echo "$1" # want
}
emit_ok() {
  [ -n "$1" ] && echo "$1"
  return 0
}
emit_if() {
  if [ -n "$1" ]; then echo "$1"; fi
}
changed() {
  [ "$a" != "$(h)" ] && [ "$b" != "$(h)" ]
}
fresh() {
  [ -f "$1" ] && find "$1" -mmin -5 | grep -q .
}
if fresh "$f"; then echo ok; fi
for id in "${ids[@]}"; do
  mark=0
  process "$id" && mark=1
  [ $mark -eq 1 ] && echo "$id" >> "$done_f" # want
done
`)
	shellWanted(t, "shell-test-and-last-status", "mid.sh", `#!/bin/bash
for id in "${ids[@]}"; do
  [ -n "$id" ] && echo "$id"
done
echo finished
`)
	shellWanted(t, "shell-test-and-last-status", "verdict.sh", `#!/bin/bash
run
[ "$played" -gt 0 ] && [ "$won" -eq "$played" ]
`)
	shellWanted(t, "shell-test-and-last-status", "tail.sh", `#!/bin/bash
build
[ -f stale.lock ] && rm stale.lock # want
`)
}
