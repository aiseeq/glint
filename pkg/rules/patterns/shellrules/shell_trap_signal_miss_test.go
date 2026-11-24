package shellrules

import "testing"

// Work after the trap that is not a plain command: a pipeline, a chain, a
// command substitution and a loop nested in a compound command.
func TestShellTrapSignalWithoutExitMissWork(t *testing.T) {
	shellWanted(t, "shell-trap-signal-without-exit", "m01_pipeline_work.sh", `#!/bin/bash
trap 'rm -f "$tmp"' INT TERM # want
tail -F /var/log/app.log | grep --line-buffered ERROR > "$tmp"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "m02_or_true_work.sh", `#!/bin/bash
trap 'rm -f "$tmp"' INT TERM # want
long-migration --all || true
`)
	shellWanted(t, "shell-trap-signal-without-exit", "m03_and_chain.sh", `#!/bin/bash
trap 'echo interrupted' INT TERM # want
build-all && deploy-all && notify-done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "m04_cmdsubst_assign.sh", `#!/bin/bash
trap 'echo interrupted' INT TERM # want
result=$(run-benchmark --duration 600)
echo "$result"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "m05_loop_in_if.sh", `#!/bin/bash
trap 'kill "$pid" 2>/dev/null' INT TERM # want
some-daemon &
pid=$!
if [ "${1:-}" = watch ]; then
  while pgrep -x other-service >/dev/null; do sleep 3; done
fi
`)
	shellWanted(t, "shell-trap-signal-without-exit", "m10_case_loop.sh", `#!/bin/bash
trap 'kill "$pid" 2>/dev/null' INT TERM # want
some-daemon &
pid=$!
case "${1:-run}" in
  run) while poll-once; do sleep 5; done ;;
esac
`)
	shellWanted(t, "shell-trap-signal-without-exit", "m12_brace_group.sh", `#!/bin/bash
trap 'rm -f "$tmp"' INT TERM # want
{
  while poll-once; do sleep 5; done
} > "$tmp.log" 2>&1
`)
	shellWanted(t, "shell-trap-signal-without-exit", "other_signal_in_if.sh", `#!/bin/bash
trap 'echo interrupted' TERM # want
if [ -n "$strict" ]; then
  trap 'exit 130' INT
fi
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "subshell_replace.sh", `#!/bin/bash
trap 'echo interrupted' TERM # want
( trap 'exit 143' TERM; prepare-cache )
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "loop_in_if_before_replace.sh", `#!/bin/bash
trap 'echo interrupted' TERM # want
if [ -n "$watch" ]; then
  while :; do :; done
fi
trap 'exit 143' TERM
`)
	shellWanted(t, "shell-trap-signal-without-exit", "echo_subst.sh", `#!/bin/bash
trap 'echo interrupted' TERM # want
echo "$(run-benchmark --duration 600)"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "local_subst.sh", `#!/bin/bash
run() {
  trap 'echo interrupted' TERM # want
  local out=$(run-benchmark --duration 600)
  echo "$out"
}
run
`)
}

// Where nothing after the trap is work, the trap stays silent.
func TestShellTrapSignalWithoutExitMissWorkNeighbors(t *testing.T) {
	for name, source := range map[string]string{
		"arith_assign.sh": `#!/bin/bash
trap 'echo interrupted' TERM
n=$((n + 1))
echo "$n"
`,
		"test_only.sh": `#!/bin/bash
trap 'echo interrupted' TERM
[ -n "$tmp" ] && echo "$tmp"
`,
		"bg_brace_loop.sh": `#!/bin/bash
trap 'kill $(jobs -p) 2>/dev/null' INT TERM
{
  while true; do collect-metrics; sleep 10; done
} &
wait
`,
		"test_builtin.sh": `#!/bin/bash
trap 'echo interrupted' TERM
test -n "$tmp" || echo "no tmp"
`,
		"top_return.sh": `#!/bin/bash
trap 'echo interrupted' TERM
return 0 2>/dev/null
while true; do sleep 1; done
`,
		"bg_in_if.sh": `#!/bin/bash
trap 'kill $(jobs -p) 2>/dev/null' TERM
if [ -n "$metrics" ]; then
  collect-metrics &
fi
wait
`,
		"if_quiet.sh": `#!/bin/bash
trap 'echo interrupted' TERM
if [ -n "$verbose" ]; then
  echo "verbose"
fi
`,
		"exit_before_work.sh": `#!/bin/bash
trap 'echo interrupted' TERM
exit 0
while true; do sleep 1; done
`,
		"conditional_replace.sh": `#!/bin/bash
trap 'echo interrupted' TERM
if [ -n "$strict" ]; then
  trap 'exit 143' TERM
fi
while true; do sleep 1; done
`,
		"func_def_after.sh": `#!/bin/bash
trap 'echo interrupted' TERM
worker() {
  while true; do sleep 1; done
}
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// A trap set inside an if, a case, a setup function or a function whose
// body is a subshell is checked with the work that follows it.
func TestShellTrapSignalWithoutExitMissPlace(t *testing.T) {
	shellWanted(t, "shell-trap-signal-without-exit", "m06_trap_in_setup_fn.sh", `#!/bin/bash
setup_traps() {
  trap cleanup INT TERM # want
}
cleanup() { rm -f "$tmp"; }
tmp=$(mktemp)
setup_traps
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "m07_trap_in_if.sh", `#!/bin/bash
if [ -n "${KEEP_TMP:-}" ]; then
  trap 'echo keeping "$tmp"' INT TERM # want
else
  trap 'rm -f "$tmp"' INT TERM # want
fi
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "m14_until_loop_after_trap_in_main.sh", `#!/bin/bash
main() (
  trap 'echo bye' INT TERM # want
  until poll-once; do sleep 5; done
)
main "$@"
`)
	shellWanted(t, "shell-trap-signal-without-exit", "trap_in_case.sh", `#!/bin/bash
case "$1" in
  keep) trap 'echo keeping' TERM ;; # want
  *) trap 'rm -f "$tmp"; exit 143' TERM ;;
esac
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "trap_in_elif.sh", `#!/bin/bash
if [ "$1" = a ]; then
  trap 'exit 143' TERM
elif [ "$1" = b ]; then
  trap 'echo b' TERM # want
fi
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "setup_returns.sh", `#!/bin/bash
setup_traps() {
  trap 'echo bye' TERM # want
  return 0
  echo unreachable
}
setup_traps
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "setup_returns_in_branch.sh", `#!/bin/bash
setup_traps() {
  if [ -n "$1" ]; then
    trap 'echo bye' TERM # want
    return 0
  fi
  exit 1
}
setup_traps x
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "brace_group_trap.sh", `#!/bin/bash
{ trap 'echo bye' TERM; } 2>/dev/null # want
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "recursive_setup.sh", `#!/bin/bash
setup() {
  trap 'echo bye' TERM # want
  [ -n "$again" ] && return
  again=1
  setup
}
setup
`)
	shellWanted(t, "shell-trap-signal-without-exit", "nested_setup.sh", `#!/bin/bash
install_traps() {
  trap 'echo bye' TERM # want
}
setup() {
  install_traps
}
setup
while poll-once; do sleep 5; done
`)
}

// Neighbors of a trap in a nested place that stay silent.
func TestShellTrapSignalWithoutExitMissPlaceNeighbors(t *testing.T) {
	for name, source := range map[string]string{
		"branch_exits.sh": `#!/bin/bash
if [ -n "$dry" ]; then
  trap 'echo dry' TERM
  exit 0
fi
while poll-once; do sleep 5; done
`,
		"replaced_after_if.sh": `#!/bin/bash
if [ -n "$debug" ]; then
  trap 'echo debug' TERM
fi
trap 'exit 143' TERM
while poll-once; do sleep 5; done
`,
		"setup_never_called.sh": `#!/bin/bash
setup_traps() {
  trap 'echo bye' TERM
}
while poll-once; do sleep 5; done
`,
		"setup_then_quiet.sh": `#!/bin/bash
setup_traps() {
  trap 'echo bye' TERM
}
setup_traps
echo ready
`,
		"setup_in_condition.sh": `#!/bin/bash
setup_traps() {
  trap 'echo bye' TERM
}
setup_traps || echo "no traps"
while poll-once; do sleep 5; done
`,
		"subshell_in_setup_returns.sh": `#!/bin/bash
setup() {
  (
    if [ -n "$x" ]; then
      trap 'echo bye' TERM
      return 0
    fi
  )
}
setup
while poll-once; do sleep 5; done
`,
		"subst_in_setup_returns.sh": `#!/bin/bash
setup() {
  out=$(
    if [ -n "$x" ]; then
      trap 'echo bye' TERM
      return 0
    fi
  )
}
setup
while poll-once; do sleep 5; done
`,
		"setup_in_background.sh": `#!/bin/bash
setup_traps() {
  trap 'echo bye' TERM
}
setup_traps &
while poll-once; do sleep 5; done
`,
		"trap_in_subst.sh": `#!/bin/bash
out=$(trap 'echo bye' TERM; echo x)
echo "$out"
`,
		"subshell_trap_exits.sh": `#!/bin/bash
(
  trap 'exit 143' TERM
  while poll-once; do sleep 5; done
)
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// Only an exit that runs on every path of the handler exits it.
func TestShellTrapSignalWithoutExitMissExit(t *testing.T) {
	shellWanted(t, "shell-trap-signal-without-exit", "m08_conditional_exit.sh", `#!/bin/bash
cleanup() { rm -rf "$dir" || exit 1; }
dir=$(mktemp -d)
trap cleanup INT TERM # want
while sync-once "$dir"; do sleep 10; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "m09_subshell_exit.sh", `#!/bin/bash
trap '(rm -f "$tmp"; exit 1)' INT TERM # want
tmp=$(mktemp)
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "m13_exit_in_unrelated_branch.sh", `#!/bin/bash
cleanup() {
  rm -f "$tmp"
  if [ "${DEBUG:-0}" = 1 ]; then
    echo "debug cleanup" >&2
    exit 0
  fi
}
tmp=$(mktemp)
trap cleanup INT TERM # want
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "uncalled_inner.sh", `#!/bin/bash
outer() {
  inner() { exit 1; }
  rm -f "$tmp"
}
trap outer INT TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "and_exit.sh", `#!/bin/bash
trap 'rm -f "$tmp" && exit 143' TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "subst_exit.sh", `#!/bin/bash
trap 'msg=$(echo bye; exit 1); echo "$msg"' TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "pipe_exit.sh", `#!/bin/bash
trap 'echo bye | exit 1' TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "bg_exit.sh", `#!/bin/bash
trap 'exit 1 &' TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "recursive_handler.sh", `#!/bin/bash
a() { b; }
b() { a; }
trap a INT # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "case_partial_item_in_if.sh", `#!/bin/bash
trap 'if [ -n "$x" ]; then case "$m" in a) rm -f "$tmp" || exit 1 ;; *) exit 2 ;; esac; fi' TERM
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "case_all_exit_in_if.sh", `#!/bin/bash
trap 'if [ -n "$x" ]; then case "$m" in a) exit 1 ;; *) exit 2 ;; esac; fi' TERM # want
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "case_no_default_in_if.sh", `#!/bin/bash
trap 'if [ -n "$x" ]; then case "$m" in a) exit 1 ;; b) exit 2 ;; esac; fi' TERM
while true; do sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "case_no_exit.sh", `#!/bin/bash
trap 'case "$mode" in a) echo a ;; *) echo other ;; esac' TERM # want
while true; do sleep 1; done
`)
}

// A handler that exits on every path, or whose paths the rule cannot tell,
// stays silent.
func TestShellTrapSignalWithoutExitMissExitNeighbors(t *testing.T) {
	for name, source := range map[string]string{
		"if_else_exit.sh": `#!/bin/bash
cleanup() {
  if [ -n "$keep" ]; then
    echo "keeping $tmp"
    exit 0
  else
    rm -f "$tmp"
    exit 1
  fi
}
trap cleanup INT TERM
while poll-once; do sleep 5; done
`,
		"elif_else_exit.sh": `#!/bin/bash
cleanup() {
  if [ "$1" = a ]; then exit 1; elif [ "$1" = b ]; then exit 2; else exit 3; fi
}
trap cleanup INT TERM
while poll-once; do sleep 5; done
`,
		"or_true_then_exit.sh": `#!/bin/bash
trap 'rm -rf "$dir" || true; exit 143' TERM
while sync-once "$dir"; do sleep 10; done
`,
		"exit_or_fallback.sh": `#!/bin/bash
trap 'exit 143 || echo never' TERM
while true; do sleep 1; done
`,
		"brace_exit.sh": `#!/bin/bash
trap '{ rm -f "$tmp"; exit 143; }' TERM
while true; do sleep 1; done
`,
		"case_all_exit.sh": `#!/bin/bash
trap 'case "$mode" in a) exit 1 ;; *) exit 2 ;; esac' TERM
while true; do sleep 1; done
`,
		"case_signal_param.sh": `#!/bin/bash
on_signal() {
  case "$1" in
    INT) exit 130 ;;
    TERM) exit 143 ;;
  esac
}
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
while poll-once; do sleep 5; done
`,
		"case_mixed.sh": `#!/bin/bash
on_signal() {
  case "$1" in
    INT) exit 130 ;;
    TERM) rm -f "$tmp" ;;
  esac
}
trap 'on_signal INT' INT
while poll-once; do sleep 5; done
`,
		"reentry_guard.sh": `#!/bin/bash
cleanup() {
  [ -n "$cleaned" ] && return
  cleaned=1
  rm -f "$tmp"
  exit 1
}
trap cleanup EXIT INT TERM
while poll-once; do sleep 5; done
`,
		"inline_return_guard.sh": `#!/bin/bash
trap '[ -n "$done" ] && return; exit 1' TERM
while poll-once; do sleep 5; done
`,
		"eval_then_echo.sh": `#!/bin/bash
trap 'eval "$on_stop"; echo stopped' TERM
while poll-once; do sleep 5; done
`,
		"cond_exit_then_return.sh": `#!/bin/bash
cleanup() {
  rm -f "$tmp" || exit 1
  return 0
}
trap cleanup TERM
while poll-once; do sleep 5; done
`,
		"guard_then_cond_exit.sh": `#!/bin/bash
cleanup() {
  [ -n "$cleaned" ] && return
  rm -f "$tmp" || exit 1
}
trap cleanup TERM
while poll-once; do sleep 5; done
`,
		"inline_guard_cond_exit.sh": `#!/bin/bash
trap '[ -n "$done" ] && return; rm -f "$tmp" || exit 1' TERM
while poll-once; do sleep 5; done
`,
		"exit_then_unreachable.sh": `#!/bin/bash
trap 'rm -f "$tmp"; exit 143; echo unreachable' TERM
while poll-once; do sleep 5; done
`,
		"if_eval_then_echo.sh": `#!/bin/bash
trap 'if [ -n "$x" ]; then eval "$y"; fi; echo done' TERM
while poll-once; do sleep 5; done
`,
		"else_eval.sh": `#!/bin/bash
trap 'if [ -n "$x" ]; then echo x; else eval "$y"; fi' TERM
while poll-once; do sleep 5; done
`,
		"if_eval_cond.sh": `#!/bin/bash
trap 'if eval "$check"; then echo ok; fi' TERM
while poll-once; do sleep 5; done
`,
		"case_eval_item.sh": `#!/bin/bash
trap 'case "$m" in a) eval "$x" ;; *) echo other ;; esac' TERM
while poll-once; do sleep 5; done
`,
		"fn_returns_then_exit.sh": `#!/bin/bash
cleanup() {
  rm -f "$tmp"
  return 0
}
trap 'cleanup; exit 143' TERM
while poll-once; do sleep 5; done
`,
		"cond_exit_in_if_then_return.sh": `#!/bin/bash
cleanup() {
  if ! rm -f "$tmp" || exit 1; then
    return 0
  fi
}
trap cleanup TERM
while poll-once; do sleep 5; done
`,
		"loop_exit.sh": `#!/bin/bash
cleanup() {
  for pid in $pids; do kill "$pid" || exit 1; done
}
trap cleanup TERM
while poll-once; do sleep 5; done
`,
		"eval_exit.sh": `#!/bin/bash
trap 'eval "$on_stop"' TERM
while poll-once; do sleep 5; done
`,
		"called_inner_exit.sh": `#!/bin/bash
outer() {
  inner() { exit 1; }
  rm -f "$tmp"
  inner
}
trap outer INT TERM
while true; do sleep 1; done
`,
		"negated_exit.sh": `#!/bin/bash
trap '! exit 1' TERM
while true; do sleep 1; done
`,
		"time_exit.sh": `#!/bin/bash
trap 'time exit 1' TERM
while true; do sleep 1; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// A flag the script only prints does not stop it.
func TestShellTrapSignalWithoutExitMissFlag(t *testing.T) {
	shellWanted(t, "shell-trap-signal-without-exit", "m11_flag_written_never_checked_in_loop.sh", `#!/bin/bash
trap 'stopping=1' INT TERM # want
log() { echo "stopping=${stopping:-0} $*"; }
while true; do
  log "tick"
  poll-once
  sleep 5
done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_printf_stderr.sh", `#!/bin/bash
trap 'stop=1' TERM # want
while true; do printf 'stop=%s\n' "$stop" >&2; sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_echo_stderr_file.sh", `#!/bin/bash
trap 'stop=1' TERM # want
while true; do echo "$stop" 2>> err.log; sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_echo_all_devnull.sh", `#!/bin/bash
trap 'stop=1' TERM # want
while true; do echo "$stop" &> /dev/null; sleep 1; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "flag_echo_devnull.sh", `#!/bin/bash
trap 'stop=1' TERM # want
while true; do echo "$stop" > /dev/null; sleep 1; done
`)
}

// A flag whose printed value the script captures or keeps is a read.
func TestShellTrapSignalWithoutExitMissFlagNeighbors(t *testing.T) {
	for name, source := range map[string]string{
		"flag_subst_fn.sh": `#!/bin/bash
trap 'stop=1' TERM
is_stopped() { echo "${stop:-0}"; }
while [ "$(is_stopped)" != 1 ]; do sleep 1; done
`,
		"flag_subst_nested_fn.sh": `#!/bin/bash
trap 'stop=1' TERM
show() { echo "${stop:-0}"; }
is_stopped() { show; }
while [ "$(is_stopped)" != 1 ]; do sleep 1; done
`,
		"flag_pipe.sh": `#!/bin/bash
trap 'stop=1' TERM
while true; do echo "$stop" | grep -q 1 && break; sleep 1; done
`,
		"flag_file.sh": `#!/bin/bash
trap 'stop=1' TERM
while true; do echo "$stop" > state; sleep 1; check-state state || break; done
`,
		"flag_fn_redirect.sh": `#!/bin/bash
trap 'stop=1' TERM
show() { echo "$stop"; }
while true; do show > state; sleep 1; check-state state || break; done
`,
		"flag_all_file.sh": `#!/bin/bash
trap 'stop=1' TERM
while true; do echo "$stop" &> state; sleep 1; check-state state || break; done
`,
		"flag_fd3.sh": `#!/bin/bash
trap 'stop=1' TERM
exec 3> state
while true; do echo "$stop" >&3; sleep 1; check-state state || break; done
`,
		"flag_pipe_all.sh": `#!/bin/bash
trap 'stop=1' TERM
while true; do echo "$stop" |& grep -q 1 && break; sleep 1; done
`,
		"flag_echo_procsubst.sh": `#!/bin/bash
trap 'stop=1' TERM
while true; do echo >(check-stop "$stop"); sleep 1; done
`,
		"flag_printf_v.sh": `#!/bin/bash
trap 'stop=1' TERM
while true; do printf -v seen '%s' "$stop"; [ "$seen" = 1 ] && break; sleep 1; done
`,
		"flag_echo_subst.sh": `#!/bin/bash
trap 'stop=1' TERM
while true; do echo "$(check-stop "$stop")"; sleep 1; done
`,
		"flag_procsubst.sh": `#!/bin/bash
trap 'stop=1' TERM
while read -r v < <(echo "$stop"); [ "$v" != 1 ]; do sleep 1; done
`,
		"flag_condition.sh": `#!/bin/bash
trap 'stop=1' TERM
while true; do echo "$stop"; [ "$stop" = 1 ] && break; sleep 1; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}
