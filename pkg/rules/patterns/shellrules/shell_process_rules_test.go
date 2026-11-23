package shellrules

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Repro from a real project: every worker of a parallel series built the bot
// straight into the shared bots directory, and a worker started a binary
// another one was writing.
func TestShellBinaryBuiltInPlaceByWorkers(t *testing.T) {
	shellWanted(t, "shell-binary-copied-over-in-place", "match-lib.sh", `#!/bin/bash
worker=${RUN_WORKER:-0}
install_version() {
  mkdir -p "$bots/$name"
  CGO_ENABLED=0 go build -o "$bots/$name/$name" ./cmd/bot # want
  go build -o "$bots/$name/$name.new" ./cmd/bot
  mv -f "$bots/$name/$name.new" "$bots/$name/$name"
  go build -o "$out/w$worker/tool" ./cmd/tool
}
`)
	// One build at a time: no worker, no parallel jobs (the word in a
	// comment is none); a directory made per run is no shared one.
	shellWanted(t, "shell-binary-copied-over-in-place", "build.sh", `#!/bin/bash
# Build server and seed in parallel.
go build -o bin/app ./cmd/app &
`)
	shellWanted(t, "shell-binary-copied-over-in-place", "own.sh", `#!/bin/bash
worker=${RUN_WORKER:-0}
built=$(mktemp -d)
go build -o "$built/$name/$name" ./cmd/bot
`)
}

// Repro from a real project: scripts were copied with scp over the copies a
// host was running, and bash read the half-written file.
func TestShellScriptsCopiedOverRunning(t *testing.T) {
	shellWanted(t, "shell-binary-copied-over-in-place", "push.sh", `#!/bin/bash
scp -q "$repo"/tools/pc/*.sh "$host:tools/" # want
scp -q "$repo"/tools/pc/*.sh "$host:tools/.incoming/"
scp -q "$repo/README.md" "$host:docs/"
`)
}

// Repro from a real project: names from $(date +%H%M%S) alone - the logs of
// parallel workers in one directory collided, and the log and the replay of
// one game got stamps a second apart.
func TestShellFileNameFromTimeOfDay(t *testing.T) {
	shellWanted(t, "shell-file-name-from-time-of-day", "match.sh", `#!/bin/bash
ts=$(date +%H%M%S)
log="$logs/match-$ts-p1.log" # want
dst="$out/game_$(date +%H%M%S).rep" # want
mv -f "$rep" "$dst"
run > "$log" 2>&1
stamp=$(date +%H%M%S)-$$
other="$logs/other-$stamp.log"
hh=$(date +%H)
pid="$logs/pid-$hh-$$.log"
when=$(date +%Y%m%d-%H%M%S)
dated="$logs/dated-$when.log"
day="$logs/day-$(date +%Y%m%d-%H%M%S).log"
echo "started at $(date +%H:%M:%S)"
dst="$replays/${mark}_$(bot_name "$ver")_vs_cpu_$(date +%H%M%S).rep" # want
log="$logs/cpu-$ver$([ "$build" = random ] || echo "-$build")-$(date +%H%M%S).log" # want
`)
}

// Two time-of-day stamps in one name give one finding, and it names the
// stamp that comes first in the name: the stamps were walked as a map, so
// the message named either from run to run.
func TestShellFileNameFromTimeOfDayNamesFirstStamp(t *testing.T) {
	rule, ok := rules.Get("shell-file-name-from-time-of-day")
	require.True(t, ok)
	source := `#!/bin/bash
mm=$(date +%M)
hh=$(date +%H)
log="$logs/run-$hh-$mm.log"
`
	for run := range 32 {
		violations := rule.AnalyzeFile(rulestest.TextFile(t, "run.sh", source))
		require.Len(t, violations, 1)
		assert.Contains(t, violations[0].Message, "time of day ($hh)", "run %d", run)
	}
}

// Repro from a real project: a script took the time twice for the log and
// the replay of one game, and a second boundary between them broke the
// match by stamp.
func TestShellFileNameStampTakenTwice(t *testing.T) {
	shellWanted(t, "shell-file-name-from-time-of-day", "pair.sh", `#!/bin/bash
log="$logs/match-$(date +%Y%m%d-%H%M%S)-$$.log"
run > "$log"
dst="$replays/game_$(date +%Y%m%d-%H%M%S).rep" # want
`)
}

// Repro from a real project: pgrep -f inside bash -c found the bash -c that
// carried the same pattern on its command line.
func TestShellPgrepMatchesOwnWrapper(t *testing.T) {
	shellWanted(t, "shell-pgrep-matches-own-wrapper", "env.sh", `#!/bin/bash
docker exec "$c" bash -c 'P=$(pgrep -f session.sh | head -1); cat /proc/$P/environ' # want
ssh "$host" "pgrep -f 'worker --queue'" # want
docker exec "$c" bash -c 'P=$(pgrep -f "[s]ession.sh" | head -1); echo $P'
pids=$(pgrep -f session.sh)
docker exec "$c" sh -c 'for p in $(pgrep -f "^C:.*game.exe"); do echo $p; done'

ssh "$host" "pgrep -x sway"
`)
	// The pattern names the script itself: the $( ) subshell carries the
	// script's command line, and pgrep finds it. A class does not help: the
	// command line holds the name, and the class matches it.
	shellWanted(t, "shell-pgrep-matches-own-wrapper", "stream-watch.sh", `#!/bin/bash
P=$(pgrep -f stream-watch.sh | head -1) # want
S=$(pgrep -f other-session.sh | head -1)
Q=$(pgrep -f '[s]tream-watch.sh' | head -1) # want
`)
	// The script spans lines, or is a heredoc captured and passed to bash -c:
	// the wrapper's command line still carries the pattern.
	shellWanted(t, "shell-pgrep-matches-own-wrapper", "multiline.sh", `#!/bin/bash
run_in() {
    docker exec -d "$1" bash -c '
        cwd="$1"; shift
        P=$(pgrep -f session.sh | head -1) # want
        export $(tr "\0" "\n" < /proc/$P/environ | grep ^DISPLAY=)
        cd "$cwd" && exec "$@"' _ "$2" "$3"
}

inner=$(cat <<INNER
set -e
P=\$(pgrep -f session.sh | head -1) # want
exec ./server -port $port
INNER
)
docker exec -d "$c" bash -c "$inner"
notes=$(cat <<EOF
pgrep -f session.sh finds the wrapper when run through bash -c
EOF
)
echo "$notes"
docker exec "$c" bash -s <<EOF
P=\$(pgrep -f session.sh | head -1)
EOF
probe_in() {
    docker exec "$1" bash -c '
        python3 - <<"PY"
print(open("/tmp/frame.ppm","rb").read()[:2])
PY' 2>/dev/null || echo "0"
}
shot_in() {
    docker exec "$1" bash -c '
        P=$(pgrep -f session.sh | head -1) # want
        grim /tmp/shot.png'
}
`)
}

func TestShellPkillMatchesOwnWrapper(t *testing.T) {
	shellWanted(t, "shell-pgrep-matches-own-wrapper", "stop-worker.sh", `#!/bin/bash
bash -c 'pkill -f worker-loop' # want
ssh host "pkill -f worker-loop" # want
sh -c 'pgrep -f worker-loop | xargs kill' # want
pkill -f stop-worker # want
pkill -x worker
pkill worker
sh -c "pkill -f '^/usr/bin/worker'"
pattern=worker-loop
sh -c "pkill -f $pattern"
pkill -f worker-loop
echo "$(cat worker.pid)" | xargs kill
`)
	rule, ok := rules.Get("shell-pgrep-matches-own-wrapper")
	require.True(t, ok)
	ctx := rulestest.TextFile(t, "stop-worker.sh", "pkill -f stop-worker\n")
	violations := rule.AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Suggestion, "pidfile")
	assert.Contains(t, violations[0].Suggestion, "pkill -x")
}

func TestShellPkillMatchesOwnWrapperGoExec(t *testing.T) {
	project := rulestest.Project(t, map[string]string{"main.go": `package main
import "os/exec"
func main() {
	exec.Command("sh", "-c", "pkill -f worker-loop")
}
`})
	rule, ok := rules.Get("shell-pgrep-matches-own-wrapper")
	require.True(t, ok)
	goRule, ok := rule.(interface {
		AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
	})
	require.True(t, ok, "rule must inspect Go exec.Command shell scripts")
	got, err := goRule.AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, got, 1)
}

// Repro from a real project: a server started in the background was stopped
// only at the end of the normal path - a timeout or Ctrl-C left it running.
func TestShellBackgroundJobWithoutTrap(t *testing.T) {
	shellWanted(t, "shell-background-job-without-trap", "api.sh", `#!/bin/bash
./api-server.sh 5000 > "$log" 2>&1 & # want
pid=$!
wait_ready
run_checks
kill "$pid"
`)
	// This trap protects the background job; swallowing signals is checked
	// separately by shell-trap-signal-without-exit.
	shellWanted(t, "shell-background-job-without-trap", "trapped.sh", `#!/bin/bash
./api-server.sh 5000 > "$log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT INT TERM
run_checks
`)
	// The suggested form exits on INT and TERM, so a signal is not swallowed,
	// and the rule takes it as a guard.
	assert.Contains(t, backgroundJobTrapSuggestion, "trap 'exit 130' INT")
	assert.Contains(t, backgroundJobTrapSuggestion, "trap 'exit 143' TERM")
	_, form, _ := strings.Cut(backgroundJobTrapSuggestion, ": ")
	shellWanted(t, "shell-background-job-without-trap", "suggested.sh", "#!/bin/bash\n./api-server.sh 5000 > \"$log\" 2>&1 &\n"+
		strings.Replace(form, "; ", "\n", 1)+"\nwait_ready\nrun_checks\nkill \"$pid\"\n")
	shellWanted(t, "shell-background-job-without-trap", "failing.sh", `#!/bin/bash
./api-server.sh 5000 > /tmp/api.log 2>&1 & # want
for i in $(seq 1 40); do ready && break; sleep 2; done
ready || { echo "api did not come up" >&2; exit 1; }
exec ./client.sh
`)
	shellWanted(t, "shell-background-job-without-trap", "waited.sh", `#!/bin/bash
./a.sh > a.log 2>&1 &
./b.sh > b.log 2>&1 &
wait
[ -s a.log ] || exit 1
`)
	shellWanted(t, "shell-background-job-without-trap", "fanout.sh", `#!/bin/bash
(ssh "$a" "echo ok" &>/dev/null && echo OK > "$ta" || echo FAIL > "$ta") &
pid_a=$!
scp config.yaml "$host":/srv/ &
local pid_b=$!
wait $pid_a $pid_b
grep -q OK "$ta" || exit 1
`)
	// Waiting for the one job at the end of the normal path does not stop it on
	// Ctrl-C: the containers it brought up keep the ports of the worker.
	shellWanted(t, "shell-background-job-without-trap", "match.sh", `#!/bin/bash
docker compose -f "$compose" up --abort-on-container-exit > "$log" 2>&1 & # want
up=$!
while kill -0 "$up" 2> /dev/null; do
    sleep 5
    [ $(($(date +%s) - started)) -ge "$max" ] && { docker compose -f "$compose" kill; break; }
done
wait "$up" 2> /dev/null || true
docker compose -f "$compose" down --remove-orphans > /dev/null 2>&1 || true
grep -q '"type"' results.json || exit 1
`)
	shellWanted(t, "shell-background-job-without-trap", "detached.sh", `#!/bin/bash
nohup ./warm.sh > /dev/null 2>&1 &
echo started
`)
}

// Repro from a real project: trap ... EXIT set in a loop replaced the trap
// of the previous iteration, and only the last temp dir was removed.
func TestShellTrapInLoop(t *testing.T) {
	shellWanted(t, "shell-trap-in-loop", "each.sh", `#!/bin/bash
for name in "$@"; do
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT # want
  build "$name" "$tmp"
done
trap 'rm -rf "$all"' EXIT
awk '
  for (k in seen) print k
' "$f" > "$tmp_file"
trap 'rm -f "$tmp_file"' EXIT
`)
}

// The subshell of a trap is told by the syntax tree: parentheses in a heredoc,
// a string, a parameter expansion or a regular expression open nothing, and
// $( … ) in double quotes is a subshell still.
func TestShellTrapInLoopSyntax(t *testing.T) {
	shellWanted(t, "shell-trap-in-loop", "forms.sh", `#!/usr/bin/env bash
for host in alpha beta; do
	cat >"$tmp" <<EOF
note: generated (do not edit
EOF
	trap 'rm -f "$tmp"' EXIT # want
done
for t in a b; do
	msg="first line
(second line"
	trap 'echo real' EXIT # want
done
(
	for t in a b; do
		case "$t" in a) echo a ;; esac
		trap 'echo real' EXIT # want
	done
)
for t in a b; do
	out="$(
		trap - EXIT
		"$t"
	)"
	(
		case "$t" in a) echo a ;; esac
		trap - EXIT
	)
	(
		case "$t" in # pick the mode
		a) echo a ;;
		esac
		cat <<'EOF'
closing paren in a heredoc )
EOF
		trap - EXIT
	)
done
ls | while read -r l; do
	LC_ALL=C trap 'echo real' EXIT # want
done
for t in a b; do (
	trap - EXIT
); done
for t in a b; do
	( for u in c; do
		echo "$u"
	done )
	trap 'echo real' EXIT # want
done
`)
	shellWanted(t, "shell-trap-in-loop", "odd.sh", `#!/usr/bin/env bash
for t in a b; do
	v=${t#(}
	[[ $t =~ ^a[)]$ ]] && echo q
	trap 'echo real' EXIT # want
done
`)
}

// Repro from a real project: every test ran in its own subshell inside the
// loop and dropped the parent's trap there; a trap set in a subshell replaces
// neither the parent's trap nor the one of the previous iteration.
func TestShellTrapInLoopSubshell(t *testing.T) {
	shellWanted(t, "shell-trap-in-loop", "subshell.sh", `#!/bin/bash
for t in a b; do
	(
		trap - EXIT
		"$t"
	)
	out=$(
		trap 'rm -f "$t.tmp"' EXIT
		"$t"
	)
	trap 'rm -f "$t.log"' EXIT # want
done
(
	for t in a b; do
		trap 'rm -f "$t"' EXIT # want
	done
)
for t in a b; do
	case "$t" in
	a) run ;;
	esac
	trap 'rm -f "$t"' EXIT # want
done
for t in a b; do
	( # each test in its own subshell)
		case "$t" in
		a) run ;;
		esac
		trap - EXIT
		"$t"
	)
done
for t in a b; do
	case "$t" in
	a) run ;;
	esac
	(
		trap - EXIT
		"$t" )
	trap 'rm -f "$t"' EXIT # want
done
for t in a b; do
	case "$t" in a) run ;; esac
	echo "(" '('
	trap 'rm -f "$t"' EXIT # want
done
`)
}

// The signals of a trap are its words, not the text of its line: a trap
// continued over a line break or with a command string of several lines is
// still trap ... EXIT, and a pipeline element, a background job or a coprocess
// runs in a subshell of its own.
func TestShellTrapInLoopWords(t *testing.T) {
	shellWanted(t, "shell-trap-in-loop", "words.sh", `#!/bin/bash
for t in a b; do
	tmp=$(mktemp)
	trap 'rm -f "$tmp" # want' \
		EXIT
done
for t in a b; do
	trap 'echo done # want
		rm -f "$t"' EXIT
done
for t in a b; do
	trap "rm -f $( # want
		echo "$t"
	)" EXIT
done
for t in a b; do
	trap -- 'rm -f "$t"' 0 # want
done
for t in a b; do
	trap 'rm -f "$t"' exit # want
done
for t in a b; do
	trap EXIT # want
done
for t in a b; do
	trap -- EXIT # want
done
for t in a b; do
	trap "rm -f '$t'" "EXIT" # want
	trap 'rm -f "$t"' 'INT' "TERM" "EXIT" # want
	trap 'rm -f "$t"' $'EXIT' # want
	trap 'rm -f "$t"' E"XIT" # want
	trap - "0" # want
	trap 'rm -f "$t"' 00 # want
	trap 0 INT # want
	builtin trap 'rm -f "$t"' EXIT # want
	command trap 'rm -f "$t"' EXIT # want
	\trap 'rm -f "$t"' EXIT # want
done
for t in a b; do
	trap -P EXIT
	trap 'rm -f "$t"' "$sig"
	trap 'rm -f "$t"' "${pre}EXIT"
	trap 'rm -f "$t"' ${pre}EXIT
	trap 'exit 0' INT
	trap 'echo EXIT' TERM
	trap -- 0 INT # want
	trap -- EXIT INT
	trap -p EXIT
	trap 'rm -f "$t"' SIGEXIT
	echo 'rm -f' EXIT
done
for t in a b; do
	trap 'rm -f "$t"' EXIT | cat
	trap 'rm -f "$t"' EXIT &
	coproc { trap 'rm -f "$t"' EXIT; }
done
`)
}

// Repro from a real project: the work directory was removed by trap on exit,
// and a failed run exited before the step that copied its log out - the log
// of the failure was lost.
func TestShellTrapRemovesResults(t *testing.T) {
	shellWanted(t, "shell-trap-removes-results", "run.sh", `#!/bin/bash
work=${TMPDIR:-/tmp}/run-$$
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT # want
cp "$bin" "$work/engine"
engine run > "$work/log" 2>&1
rc=$?
[ $rc -eq 0 ] || { echo 'run failed'; exit $rc; }
cp "$work/log" "$logs/run.log"
`)
	shellWanted(t, "shell-trap-removes-results", "kept.sh", `#!/bin/bash
work=$(mktemp -d)
trap 'cp "$work/log" "$logs/" 2>/dev/null; rm -rf "$work"' EXIT
engine run > "$work/log" 2>&1 || exit 1
cp "$work/log" "$logs/run.log"
`)
	shellWanted(t, "shell-trap-removes-results", "scratch.sh", `#!/bin/bash
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fetch "$work" || exit 1
build "$work"
`)
	// A copy whose source and destination are both inside the directory
	// does not take anything out of it.
	shellWanted(t, "shell-trap-removes-results", "inside.sh", `#!/usr/bin/env bash
set -euo pipefail
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
printf 'a\n' > "$tmp_dir/in.txt"
cp "$tmp_dir/in.txt" "$tmp_dir/copy.txt"
mv -f "${tmp_dir}/copy.txt" "$tmp_dir/out.txt" 2>/dev/null
cp "$tmp_dir/out.txt" "$tmp_dir/last.txt" > "$log"
cat "$tmp_dir/out.txt"
`)
	shellWanted(t, "shell-trap-removes-results", "out.sh", `#!/usr/bin/env bash
set -euo pipefail
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT # want
cp "$tmp_dir/in.txt" "$tmp_dir/copy.txt"
build "$tmp_dir"
cp "$tmp_dir/out.txt" "$dest/out.txt"
`)
	// A quoted path with blanks is one argument, and a ; inside quotes ends
	// no command.
	shellWanted(t, "shell-trap-removes-results", "blanks.sh", `#!/usr/bin/env bash
set -euo pipefail
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
cp "$tmp_dir/in.txt" "$tmp_dir/my copy.txt"
mv "$tmp_dir/a;b.txt" "$tmp_dir/c d.txt" && cat "$tmp_dir/c d.txt"
`)
	// -t and --target-directory name the destination; every other argument
	// is a source.
	shellWanted(t, "shell-trap-removes-results", "target.sh", `#!/usr/bin/env bash
set -euo pipefail
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT # want
cp -t "$dest" "$tmp_dir/out.txt"
`)
	shellWanted(t, "shell-trap-removes-results", "target_long.sh", `#!/usr/bin/env bash
set -euo pipefail
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT # want
mv -f --target-directory="$dest" "$tmp_dir/a.txt" "$tmp_dir/b.txt"
`)
	shellWanted(t, "shell-trap-removes-results", "target_inside.sh", `#!/usr/bin/env bash
set -euo pipefail
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
cp -at "$tmp_dir/keep" "$tmp_dir/a.txt"
mv --target-directory "${tmp_dir}/keep" "$tmp_dir/b.txt" 2>&1 | tee -a "$log"
`)
}

// Repro from a real project: flock held the lock for the script, and a
// background job the script started inherited the lock and held it for
// minutes after the script was done.
func TestShellLockInheritedByBackground(t *testing.T) {
	shellWanted(t, "shell-lock-inherited-by-background", "carousel.sh", `#!/bin/bash
[ -n "${LOCKED:-}" ] || exec env LOCKED=1 flock -w 300 "$LOCK" "$0" "$@" # want
open_replay
nohup "$0" __warm "$other" > /dev/null 2>&1 &
`)
	shellWanted(t, "shell-lock-inherited-by-background", "closed.sh", `#!/bin/bash
[ -n "${LOCKED:-}" ] || exec env LOCKED=1 flock -o -w 300 "$LOCK" "$0" "$@"
nohup "$0" __warm "$other" > /dev/null 2>&1 &
exec 9>"$LOCK"
flock -w "${2:-150}" 9
nohup ./warm.sh 9>&- > /dev/null 2>&1 &
`)
	shellWanted(t, "shell-lock-inherited-by-background", "slots.sh", `#!/bin/bash
ssh "$host" 'exec 9>>"$HOME/slot.lock"; flock -n 9 && echo free'
(
  flock 9
  ./run.sh > "$log" 2>&1
) 9> "$dir/locks/$name"
./other.sh &
`)
}

// Repro from a real project: the locked entry restarted itself in the
// background, and the background branch changed the same containers with no
// lock at all.
func TestShellSelfRelaunchOutsideLock(t *testing.T) {
	shellWanted(t, "shell-self-relaunch-outside-lock", "carousel.sh", `#!/bin/bash
# Concurrent opens are serialized with flock.
[ -n "${LOCKED:-}" ] || exec env LOCKED=1 flock -o -w 300 "$LOCK" "$0" "$@"
open_replay
nohup "$0" __warm "$other" > /dev/null 2>&1 & # want
`)
	shellWanted(t, "shell-self-relaunch-outside-lock", "locks.sh", `#!/bin/bash
[ -n "${LOCKED:-}" ] || exec env LOCKED=1 flock -o -w 300 "$LOCK" "$0" "$@"
box_lock() { exec 8>"$RC/$1.lock"; flock -w 150 8; }
nohup "$0" __warm "$other" > /dev/null 2>&1 &
`)
	shellWanted(t, "shell-self-relaunch-outside-lock", "plain.sh", `#!/bin/bash
nohup "$0" __warm "$other" > /dev/null 2>&1 &
`)
}

// Repro from a real project: flock -w 30 ... || true went on without the
// lock after the timeout, as if it held it.
func TestShellLockFailureIgnored(t *testing.T) {
	shellWanted(t, "shell-lock-failure-ignored", "lobby.sh", `#!/bin/bash
lock_lobby() {
  exec 8>"$RC/lobby-$1.lock"
  flock -w 30 8
}
flock -w 30 9 || true # want
lock_lobby "$l" || : # want
lock_lobby "$l" || { echo busy >&2; exit 1; }
flock -n 9 || exit 0
`)
}

// Repro from a real project: a script checked out and rebased branches in a
// fixed shared worktree with no lock, and two runs rebased over each other.
func TestShellSharedWorktreeWithoutLock(t *testing.T) {
	shellWanted(t, "shell-shared-worktree-without-lock", "merge.sh", `#!/bin/bash
wt=${MERGE_WT:-$repo-98}
lock=$(git -C "$repo" rev-parse --git-path index.lock)
[ -e "$lock" ] && exit 2
cd "$wt"
git checkout -q -B merging "origin/$br" # want
git rebase origin/main
`)
	shellWanted(t, "shell-shared-worktree-without-lock", "locked.sh", `#!/bin/bash
wt=${MERGE_WT:-$repo-98}
exec 9>"$wt.lock"
flock -n 9 || exit 1
cd "$wt"
git checkout -q -B merging "origin/$br"
`)
	shellWanted(t, "shell-shared-worktree-without-lock", "own.sh", `#!/bin/bash
wt=$(mktemp -d)
git worktree add "$wt" origin/main
cd "$wt"
git checkout -q -B merging "origin/$br"
`)
}

// Repro from a real project: grep for "-launch -uid s2" in /proc/$p/cmdline -
// the arguments there are separated by NUL, so a pattern with a space never
// matched and every process was killed.
func TestShellCmdlinePatternWithSpace(t *testing.T) {
	shellWanted(t, "shell-cmdline-pattern-with-space", "kill.sh", `#!/bin/bash
for p in $(pgrep -f game); do
  grep -a -q -- "-launch -uid s2" /proc/$p/cmdline || kill -9 "$p" # want
  tr '\0' ' ' < /proc/$p/cmdline | grep -q -- "-launch -uid s2" || kill -9 "$p"
  grep -a -q -- "-launch" /proc/$p/cmdline || kill -9 "$p"
done
`)
}

// Repro from a real project: a wait loop started the menu again on every
// second it did not see the process, and the copies piled up.
func TestShellPollLoopRelaunches(t *testing.T) {
	shellWanted(t, "shell-poll-loop-relaunches", "menu.sh", `#!/bin/bash
for i in $(seq 1 60); do
  menu_ready && return 0
  [ -z "$(menu_proc)" ] && launch_menu # want
  sleep 1
done
for i in $(seq 1 60); do
  menu_ready && return 0
  if [ -z "$(menu_proc)" ] && [ $((i - last)) -ge 20 ]; then launch_menu; last=$i; fi
  sleep 1
done
for i in $(seq 1 10); do
  ping -c1 host && break
  sleep 1
done
`)
}

// Repro from a real project: a fixed sleep 8 after starting the stream, and
// the next step needed the viewer session that sometimes took longer.
func TestShellFixedSleepAfterStart(t *testing.T) {
	shellWanted(t, "shell-fixed-sleep-after-start", "watch.sh", `#!/bin/bash
start_stream "$app" &
sleep 8 # want
join_session
docker compose up -d
sleep 10 # want
curl -fs localhost/health
start_stream "$app" &
for i in $(seq 1 30); do session_up && break; sleep 1; done
sleep 1
say "opening"; start_stream "$app"; sleep 8 # want
for i in $(seq 1 20); do c=$(box_id); [ -n "$c" ] && break; sleep 2; done
[ -n "$c" ] || { echo "no box" >&2; return 1; }
sleep 8 # want
for i in $(seq 1 15); do gone && break; sleep 2; done
sleep 4
`)
	// Clicks on a timer: act, wait a fixed time, look once — a miss is a silent
	// wait, and a slow screen reads as a refusal.
	shellWanted(t, "shell-fixed-sleep-after-start", "clicks.sh", `#!/bin/bash
probe() {
    docker exec "$1" bash -c '
        python3 - <<"PY"
for y in range(28, 46, 2):
    print(y)
PY' 2>/dev/null || echo "0"
}
open_menu() {
    if [ -z "$(game_pid "$c")" ]; then
        click_at "$c" 'Launcher' 160 1078
        for i in $(seq 1 20); do [ -n "$(game_pid "$c")" ] && break; sleep 2; done
        [ -n "$(game_pid "$c")" ] || { echo "game did not start (click Play)"; return 1; }
        sleep 22 # want
    fi
    for try in 1 2 3 4 5; do
        click_at "$c" 'Game' 810 740
        sleep 8 # want
        menu_up "$c" && menu_shown "$c" && return 0
    done
    for i in 1 2 3; do
        click_at "$c" 'Login' 958 714; sleep 6 # want
        windows "$c" | grep -qx 'Launcher' && break
    done
    for try in $(seq 1 12); do sleep 8; menu_shown "$c" && break; done
    for i in $(seq 1 50); do
        ready "$a" && break
        sleep 3
    done
}
`)
}

func TestShellPgrepMatchesOwnScript(t *testing.T) {
	shellWanted(t, "shell-pgrep-matches-own-wrapper", "stream-watch.sh", `#!/bin/bash
P=$(pgrep -f stream-watch.sh) # want
Q=$(pgrep -f 'stream-watch.*' | head -1) # want
S=$(pgrep -f "bash stream-watch.sh" | head -1) # want
T=$(pgrep -f stream.watch | head -1) # want
U=$(pgrep -f "watch --child" | head -1)
V=$(pgrep -Af stream-watch.sh | head -1)
W=$(pgrep -vf stream-watch.sh | head -1)
X=$(pgrep -f '[s]tream-watch.sh' | head -1) # want
Y=$(pgrep -f stream-watch.sh|head -1) # want
Z=$(pgrep -f "stream-watch.sh") # want
B=$(pgrep -f stream-watch.sh	| head -1) # want
C=$(pgrep -f stream\.watch | head -1) # want
D=$(pgrep -f "stream\.watch" | head -1)
E=$(pgrep -f '^stream-watch' | head -1)
F=$(pgrep -f 'stream(watch' | head -1)
G=$(pgrep -lf stream-watch.sh | head -1) # want
`)
	// The path the script is started by is the one relative to the root,
	// not where the checkout lies: the root of a test is a temporary
	// directory named after the test.
	shellWanted(t, "shell-pgrep-matches-own-wrapper", "scripts/stream-watch.sh", `#!/bin/bash
P=$(pgrep -f scripts/stream-watch.sh | head -1) # want
Q=$(pgrep -f TestShellPgrepMatchesOwnScript | head -1)
`)
}

func TestPgrepExcludesSelf(t *testing.T) {
	for options, want := range map[string]bool{
		"pgrep -Af ":      true,
		"pgrep -v -f ":    true,
		"pgrep -lf ":      false,
		"pgrep -n -f ":    false,
		"pgrep --env -f ": false,
	} {
		if got := pgrepExcludesSelf(options); got != want {
			t.Errorf("pgrepExcludesSelf(%q) = %v, want %v", options, got, want)
		}
	}
}
