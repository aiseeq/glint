package shellrules

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestShellTrapSignalWithoutExit(t *testing.T) {
	shellWanted(t, "shell-trap-signal-without-exit", "watch.sh", `#!/bin/bash
some-daemon --port 9000 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT INT TERM # want
while pgrep -x other-service >/dev/null; do sleep 3; done
echo done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "session.sh", `#!/bin/bash
lock=$(mktemp)
cleanup() {
  rm -f "$lock"
  pkill -P $$ 2>/dev/null || true
}
trap cleanup INT TERM # want
session-client --profile "$1"
while [ -e "$lock" ]; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "fn_exit.sh", `#!/bin/bash
some-daemon &
pid=$!
stop() {
  kill "$pid" 2>/dev/null || true
  exit 143
}
trap stop INT TERM
while pgrep -x other-service >/dev/null; do sleep 3; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "inline_exit.sh", `#!/bin/bash
some-daemon &
pid=$!
trap 'kill "$pid" 2>/dev/null; exit 130' INT TERM
while pgrep -x other-service >/dev/null; do sleep 3; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "exit_only.sh", `#!/bin/bash
some-daemon &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
while pgrep -x other-service >/dev/null; do sleep 3; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "wait_last.sh", `#!/bin/bash
some-daemon &
pid=$!
trap 'kill "$pid" 2>/dev/null' INT TERM
wait "$pid"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "reset.sh", `#!/bin/bash
tmp=$(mktemp)
trap 'rm -f "$tmp"' INT TERM
write-state > "$tmp"
mv "$tmp" state.json
trap - INT TERM
while true; do poll-state; sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "ignore.sh", `#!/bin/bash
trap '' INT TERM
migrate-database --all
echo migrated
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_loop.sh", `#!/bin/bash
stop=0
trap 'stop=1' INT TERM
trap 'kill "$pid" 2>/dev/null' EXIT
probe-link --interval 1 > probe.log &
pid=$!
while [ "$stop" = 0 ]; do
  sample-stats >> stats.log
  sleep 2
done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_func.sh", `#!/bin/bash
interrupted=0
trap 'interrupted=1' INT TERM
run_profile() {
  stress-tool "$@" > out.txt 2>&1
}
for p in cache memory cpu; do
  run_profile "$p"
  [ "$interrupted" = 1 ] && break
done
echo "summary"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "reraise.sh", `#!/bin/bash
tmp=$(mktemp -d)
on_term() {
  rm -rf "$tmp"
  trap - TERM
  kill -TERM $$
}
trap on_term TERM
trap 'rm -rf "$tmp"; trap - INT; kill -INT $$' INT
while sync-once "$tmp"; do sleep 10; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_if.sh", `#!/bin/bash
failed=0
interrupted=0
trap 'interrupted=1' INT TERM
step() {
  "$@" > out.txt 2>&1 || failed=1
  if [ "$interrupted" = 1 ]; then
    echo "stopped by signal"
    return 1
  fi
}
step load-tool --phase one
if [ "$interrupted" != 1 ]; then
  step load-tool --phase two
fi
[ "$failed" = 1 ] && exit 1
echo ok
`)
	shellWanted(t, "shell-trap-signal-without-exit", "p3.sh", `#!/bin/bash
tmp=$(mktemp)
cleanup() {
  local rc=$?
  rm -f "$tmp"
  return $rc
}
trap cleanup INT TERM # want
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "p4.sh", `#!/bin/bash
tmp=$(mktemp)
cleanup() {
  status=$?
  rm -f "$tmp"
  echo "cleanup after status $status" >&2
}
trap cleanup INT TERM # want
while poll-once; do sleep 5; done
`)
}

func TestShellTrapSignalWithoutExitBoundaries(t *testing.T) {
	shellWanted(t, "shell-trap-signal-without-exit", "local_shadow.sh", `#!/bin/bash
cleanup() { local stop=1; echo "$stop"; }
trap cleanup TERM # want
while [ "$stop" != 1 ]; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "nested_handler_read.sh", `#!/bin/bash
log_status() { echo "$status"; }
cleanup() { status=$?; log_status; }
trap cleanup TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "local_helper.sh", `#!/bin/bash
set_stop() { stop=1; }
cleanup() { local stop; set_stop; }
trap cleanup TERM # want
while [ "$stop" != 1 ]; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "declare_local.sh", `#!/bin/bash
cleanup() { declare stop=1; }
trap cleanup TERM # want
while [ "$stop" != 1 ]; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "inline_handler_read.sh", `#!/bin/bash
trap 'status=$?; echo "$status"' TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "exec.sh", `#!/bin/bash
tmp=$(mktemp)
trap 'rm -f "$tmp"' INT TERM # want
render-config > "$tmp"
exec my-server --config "$tmp"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_unused.sh", `#!/bin/bash
trap 'stop=1' TERM # want
while true; do echo "$stop"; sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_logged.sh", `#!/bin/bash
trap 'stop=1' TERM # want
while echo "$stop"; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "inner_break.sh", `#!/bin/bash
trap 'stop=1' TERM
while true; do
  for item in a b; do [ "$stop" = 1 ] && break; done
done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "unread.sh", `#!/bin/bash
trap 'stop=1' TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "mixed.sh", `#!/bin/bash
trap 'stop=1; echo stopped' TERM # want
while true; do echo "$stop"; sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "function_read.sh", `#!/bin/bash
trap 'stop=1' TERM # want
report() { echo "${stop}"; }
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "multiple_flags.sh", `#!/bin/bash
trap 'first=1; second=1' TERM # want
show() { echo "${second}"; }
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "let_flag.sh", `#!/bin/bash
trap 'let stop++' TERM
while (( ! stop )); do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "declare_flag.sh", `#!/bin/bash
trap 'declare stopped=1' TERM
while [ "$stopped" != 1 ]; do sleep 1; done
`)

	shellWanted(t, "shell-trap-signal-without-exit", "wrong_signal.sh", `#!/bin/bash
trap 'trap - INT; kill -INT $$' TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "wrong_pid.sh", `#!/bin/bash
trap 'trap - TERM; kill -TERM "$pid"' TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_function.sh", `#!/bin/bash
stop_now() { stopping=1; }
trap stop_now TERM
while [ "$stopping" != 1 ]; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_exit.sh", `#!/bin/bash
trap 'stopping=1' TERM
long_command
[ "$stopping" = 1 ] && exit 143
`)
	shellWanted(t, "shell-trap-signal-without-exit", "terminal.sh", `#!/bin/bash
trap 'echo stopped' TERM
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replaced.sh", `#!/bin/bash
trap 'echo stopped' TERM
trap 'exit 143' TERM
while true; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "long.sh", `#!/bin/bash
trap 'echo stopped' TERM # want
sleep 30
`)
	shellWanted(t, "shell-trap-signal-without-exit", "loop_before_reset.sh", `#!/bin/bash
trap 'echo stopped' TERM # want
while true; do sleep 5; done
trap - TERM
`)
}

func TestShellTrapSignalWithoutExitMessage(t *testing.T) {
	rule, ok := rules.Get("shell-trap-signal-without-exit")
	if !ok {
		t.Fatal("rule not registered")
	}
	for _, signal := range []string{"INT", "TERM", "INT TERM"} {
		ctx := rulestest.TextFile(t, "signal.sh", "#!/bin/bash\ntrap 'echo stop' "+signal+"\nwhile true; do sleep 1; done\n")
		findings := rule.AnalyzeFile(ctx)
		if len(findings) != 1 {
			t.Fatalf("%s: got %d findings", signal, len(findings))
		}
		for name := range strings.FieldsSeq(signal) {
			if !strings.Contains(findings[0].Message, name) {
				t.Errorf("%s: message %q omits signal", signal, findings[0].Message)
			}
		}
		for _, text := range []string{"exit 130", "exit 143", "EXIT", "flag", "trap - SIG; kill -SIG $$"} {
			if !strings.Contains(findings[0].Suggestion, text) {
				t.Errorf("suggestion %q omits %q", findings[0].Suggestion, text)
			}
		}
	}
}

// Synthetic neighbors from the consumer review.
func TestShellTrapSignalWithoutExitReview(t *testing.T) {
	shellWanted(t, "shell-trap-signal-without-exit", "rn01_graceful_echo_flag.sh", `#!/bin/bash
running=true
trap 'echo "stopping..." >&2; running=false' INT TERM
while $running; do
  poll-queue --once
  sleep 2
done
echo "stopped cleanly"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn02_arith_flag.sh", `#!/bin/bash
stop=0
trap 'stop=1' INT TERM
while (( ! stop )); do
  sync-once
  sleep 5
done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn03_counter_flag.sh", `#!/bin/bash
interrupted=0
trap '((interrupted++))' INT TERM
for host in a b c; do
  deploy-to "$host"
  [ "$interrupted" -gt 0 ] && break
done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn04_reraise_generic.sh", `#!/bin/bash
tmp=$(mktemp -d)
on_signal() {
  rm -rf "$tmp"
  trap - "$1"
  kill -s "$1" $$
}
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
while sync-once "$tmp"; do sleep 10; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn05_reraise_default_kill.sh", `#!/bin/bash
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"; trap - TERM; kill $$' TERM
trap 'exit 130' INT
while sync-once "$tmp"; do sleep 10; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn06_reraise_dashdash.sh", `#!/bin/bash
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"; trap - TERM; kill -TERM -- $$' TERM
trap 'exit 130' INT
while sync-once "$tmp"; do sleep 10; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn07_sourced_die.sh", `#!/bin/bash
. "$(dirname "$0")/lib/common.sh"
trap die_on_signal INT TERM
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn08_forward_wait_cleanup.sh", `#!/bin/bash
tmp=$(mktemp)
trap 'kill -TERM "$child" 2>/dev/null' INT TERM
my-server --state "$tmp" &
child=$!
wait "$child"
status=$?
rm -f "$tmp"
exit "$status"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn09_bg_loop.sh", `#!/bin/bash
trap 'kill $(jobs -p) 2>/dev/null' INT TERM
while true; do collect-metrics; sleep 10; done &
while true; do rotate-logs; sleep 60; done &
wait
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn11_trap_print.sh", `#!/bin/bash
trap -p INT TERM
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn12_die_chain.sh", `#!/bin/bash
die() { echo "$*" >&2; exit 1; }
cleanup() { rm -f "$tmp"; die "interrupted"; }
tmp=$(mktemp)
trap cleanup INT TERM
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn13_set_e_cleanup_exit.sh", `#!/bin/bash
set -euo pipefail
tmp=$(mktemp -d)
cleanup() {
  local rc=$?
  rm -rf "$tmp"
  exit "$rc"
}
trap cleanup EXIT INT TERM
build-assets "$tmp"
upload "$tmp"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn14_ignore_then_restore.sh", `#!/bin/bash
trap '' INT TERM
migrate-database --all
trap - INT TERM
while true; do serve-once; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn16_handler_defined_later.sh", `#!/bin/bash
trap on_stop INT TERM
main() {
  while poll-once; do sleep 5; done
}
on_stop() { echo "bye"; exit 0; }
main "$@"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn17_local_flag_fn_with_log.sh", `#!/bin/bash
request_stop() {
  echo "got signal, finishing current batch" >&2
  stop_requested=1
}
trap request_stop INT TERM
while [ -z "${stop_requested:-}" ]; do
  process-batch
done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "rn18_sleep_wait_idiom.sh", `#!/bin/bash
trap 'echo "stopping"; running=0' TERM
running=1
while [ "$running" = 1 ]; do
  check-health
  sleep 30 & wait $!
done
`)
}
