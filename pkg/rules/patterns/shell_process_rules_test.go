package patterns

import "testing"

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
day="$logs/day-$(date +%Y%m%d-%H%M%S).log"
echo "started at $(date +%H:%M:%S)"
`)
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
	shellWanted(t, "shell-background-job-without-trap", "trapped.sh", `#!/bin/bash
./api-server.sh 5000 > "$log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT INT TERM
run_checks
`)
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
}
