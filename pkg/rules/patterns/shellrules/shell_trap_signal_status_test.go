package shellrules

import "testing"

// An exit on each outcome of an && / || chain exits on every path: the
// left side falls through only with the status that runs the other exit.
func TestShellTrapSignalWithoutExitStatusChain(t *testing.T) {
	for name, source := range map[string]string{
		"y01_ternary_signal.sh": `#!/bin/bash
on_signal() {
  rm -f "$lock"
  [ "$1" = INT ] && exit 130 || exit 143
}
lock=/var/lock/deploy.lock
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
for host in $(cat hosts); do deploy "$host"; done
`,
		"y02_or_and.sh": `#!/bin/bash
trap 'rm -f "$tmp" || exit 1 && exit 0' TERM
while poll-once; do sleep 5; done
`,
		"x03_and_exit_or_exit_fn.sh": `#!/bin/bash
cleanup() {
  rm -rf "$workdir" && exit 130 || exit 1
}
trap cleanup INT TERM
for f in "$@"; do convert "$f" "$workdir"; done
`,
		"f01_and_or_exit.sh": `#!/bin/bash
trap 'rm -rf "$tmp" && exit 0 || exit 1' INT TERM
while rsync -a src/ "$tmp"/; do sleep 10; done
`,
		"f19_exit_ternary.sh": `#!/bin/bash
trap '[ -f "$lock" ] && rm -f "$lock" && exit 0 || exit 1' TERM
while poll-once; do sleep 5; done
`,
		"negated_or_exit.sh": `#!/bin/bash
trap '! rm -f "$tmp" && exit 1 || exit 0' TERM
while poll-once; do sleep 5; done
`,
		"if_else_status_or_exit.sh": `#!/bin/bash
trap 'if [ -n "$x" ]; then rm -f "$x"; else false; fi && exit 0 || exit 1' TERM
while poll-once; do sleep 5; done
`,
		"negated_block_or_exit.sh": `#!/bin/bash
trap '! { rm -f "$tmp" || exit 1; } || exit 2' TERM
while poll-once; do sleep 5; done
`,
		"if_cond_exits_on_zero.sh": `#!/bin/bash
trap 'if rm -f "$tmp" && exit 0; then echo kept; else exit 1; fi' TERM
while poll-once; do sleep 5; done
`,
		"if_cond_exits_on_nonzero.sh": `#!/bin/bash
trap 'if rm -f "$tmp" || exit 1; then exit 0; else echo kept; fi' TERM
while poll-once; do sleep 5; done
`,
		"if_no_branch_and_exit.sh": `#!/bin/bash
trap 'if [ -n "$x" ]; then exit 1; fi && exit 0' TERM
while poll-once; do sleep 5; done
`,
		"exit_and_echo.sh": `#!/bin/bash
trap 'rm -f "$tmp"; exit 1 && echo unreachable' TERM
while poll-once; do sleep 5; done
`,
		"eval_or_cleanup.sh": `#!/bin/bash
trap 'eval "$on_stop" || rm -f "$tmp"' TERM
while poll-once; do sleep 5; done
`,
		"true_and_exit.sh": `#!/bin/bash
trap 'rm -f "$tmp"; true && exit 0' TERM
while poll-once; do sleep 5; done
`,
		"colon_and_exit.sh": `#!/bin/bash
trap 'rm -f "$tmp"; : && exit 0' TERM
while poll-once; do sleep 5; done
`,
		"eval_in_then_branch.sh": `#!/bin/bash
trap 'if [ -n "$on_stop" ]; then eval "$on_stop"; else rm -f "$tmp"; fi' TERM
while poll-once; do sleep 5; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
	shellWanted(t, "shell-trap-signal-without-exit", "or_exit_then_and_echo.sh", `#!/bin/bash
trap 'rm -f "$tmp" || exit 1 && echo cleaned' TERM # want
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "and_exit_and_exit.sh", `#!/bin/bash
trap 'rm -f "$tmp" && exit 0 && exit 1' TERM # want
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "if_no_branch_or_exit.sh", `#!/bin/bash
trap 'if [ -n "$x" ]; then exit 1; fi || exit 2' TERM # want
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "or_or_exit.sh", `#!/bin/bash
trap 'rm -f "$tmp" || echo failed || exit 1' TERM # want
while poll-once; do sleep 5; done
`)
	// A bare return goes on with the status of the last command, zero or not.
	shellWanted(t, "shell-trap-signal-without-exit", "return_and_exit.sh", `#!/bin/bash
stop() {
  kill "$pid" 2>/dev/null
  return
}
trap 'stop && exit 0' TERM # want
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "return_or_exit.sh", `#!/bin/bash
stop() {
  kill "$pid" 2>/dev/null
  return
}
trap 'stop || exit 1' TERM # want
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "u01_and_exit_or_echo.sh", `#!/bin/bash
trap 'rm -f "$tmp" && exit 0 || echo "cleanup failed" >&2' TERM # want
tmp=$(mktemp)
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "case_and_exit.sh", `#!/bin/bash
trap 'case "$1" in a) rm -f "$tmp" ;; esac && exit 0' TERM # want
while poll-once; do sleep 5; done
`)
}

// exec with a command replaces the shell: nothing after it runs.
func TestShellTrapSignalWithoutExitExecEndsPath(t *testing.T) {
	for name, source := range map[string]string{
		"f02_exec_in_branch.sh": `#!/bin/bash
cfg=$(mktemp)
if [ "${1:-}" = serve ]; then
  trap 'rm -f "$cfg"' TERM
  exec my-server --config "$cfg"
fi
while poll-once; do sleep 5; done
`,
		"f14_nested_if_trap_exec.sh": `#!/bin/bash
if [ -n "${DEBUG:-}" ]; then
  trap 'echo "debug: signal" >&2' TERM
fi
exec my-server "$@"
`,
		"y03_entrypoint_exec_if.sh": `#!/bin/bash
cfg=$(mktemp)
render-config > "$cfg"
if [ -n "${DEBUG:-}" ]; then
  trap 'rm -f "$cfg"' TERM
  exec dlv exec /app/server -- --config "$cfg"
else
  exec /app/server --config "$cfg"
fi
`,
		"x01_top_exec.sh": `#!/bin/bash
trap 'echo debug' TERM
exec my-server "$@"
`,
		"exec_in_if_after_trap.sh": `#!/bin/bash
trap 'echo debug' TERM
if [ -n "$debug" ]; then
  exec dlv exec ./server
else
  exec ./server
fi
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
	shellWanted(t, "shell-trap-signal-without-exit", "exec_redirect_only.sh", `#!/bin/bash
trap 'echo debug' TERM # want
exec > run.log 2>&1
while poll-once; do sleep 5; done
`)
}

// A later trap takes a signal off only where it is set on every path.
func TestShellTrapSignalWithoutExitConditionalReplace(t *testing.T) {
	shellWanted(t, "shell-trap-signal-without-exit", "l01_cond_replace_case.sh", `#!/bin/bash
trap 'echo "got TERM" >&2' TERM # want
case "${1:-}" in
  --strict) trap 'exit 143' TERM ;;
esac
while true; do sync-once; sleep 10; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "l02_cond_replace_if.sh", `#!/bin/bash
trap 'rm -f "$tmp"' INT TERM # want
if [ -n "${STRICT:-}" ]; then
  trap 'rm -f "$tmp"; exit 1' INT TERM
fi
for host in $(cat hosts.txt); do deploy "$host"; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "l08_and_trap_replace.sh", `#!/bin/bash
trap 'echo bye' TERM # want
[ -n "$STRICT" ] && trap 'exit 143' TERM
while true; do poll-once; sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replace_one_signal_both_branches.sh", `#!/bin/bash
trap 'echo bye' INT TERM # want
if [ -n "$strict" ]; then
  trap 'exit 143' TERM
else
  trap - TERM
fi
while true; do poll-once; sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replace_in_subshell_branch.sh", `#!/bin/bash
trap 'echo bye' TERM # want
if [ -n "$strict" ]; then
  ( trap 'exit 143' TERM )
else
  trap - TERM
fi
while true; do poll-once; sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replace_in_background_brace.sh", `#!/bin/bash
trap 'echo bye' TERM # want
{ trap - TERM & } 2>/dev/null
while true; do poll-once; sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replace_elif_no_else.sh", `#!/bin/bash
trap 'echo bye' TERM # want
if [ "$1" = a ]; then
  trap 'exit 143' TERM
elif [ "$1" = b ]; then
  trap - TERM
fi
while true; do poll-once; sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replace_case_default_one_item.sh", `#!/bin/bash
trap 'echo bye' TERM # want
case "$1" in
  strict) trap 'exit 143' TERM ;;
  *) echo lenient ;;
esac
while true; do poll-once; sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replace_after_work_in_branch.sh", `#!/bin/bash
trap 'echo bye' TERM # want
if [ -n "$strict" ]; then
  prepare-cache
  trap - TERM
else
  prepare-cache
fi
`)
	for name, source := range map[string]string{
		"replace_both_branches.sh": `#!/bin/bash
trap 'echo bye' TERM
if [ -n "$strict" ]; then
  trap 'exit 143' TERM
else
  trap - TERM
fi
while true; do poll-once; sleep 5; done
`,
		"replace_elif_else.sh": `#!/bin/bash
trap 'echo bye' TERM
if [ "$1" = a ]; then
  trap 'exit 143' TERM
elif [ "$1" = b ]; then
  trap - TERM
else
  trap 'exit 1' TERM
fi
while true; do poll-once; sleep 5; done
`,
		"replace_case_default.sh": `#!/bin/bash
trap 'echo bye' TERM
case "$1" in
  strict) trap 'exit 143' TERM ;;
  *) trap - TERM ;;
esac
while true; do poll-once; sleep 5; done
`,
		"replace_in_brace.sh": `#!/bin/bash
trap 'echo bye' TERM
{ echo resetting; trap - TERM; } >&2
while true; do poll-once; sleep 5; done
`,
		"replace_in_condition.sh": `#!/bin/bash
trap 'echo bye' TERM
if trap - TERM; then echo reset; fi
while true; do poll-once; sleep 5; done
`,
		"replace_case_default_int.sh": `#!/bin/bash
trap 'echo bye' INT
case "$1" in
  strict) trap 'exit 130' INT ;;
  *) trap - INT ;;
esac
while true; do poll-once; sleep 5; done
`,
		"replace_first_in_brace.sh": `#!/bin/bash
trap 'echo bye' TERM
{ trap - TERM; echo reset; } >&2
while true; do poll-once; sleep 5; done
`,
		"replace_in_elif_condition.sh": `#!/bin/bash
trap 'echo bye' TERM
if [ "$1" = a ]; then
  trap - TERM
elif trap - TERM; then
  echo reset
fi
while true; do poll-once; sleep 5; done
`,
		"replace_left_of_or.sh": `#!/bin/bash
trap 'echo bye' TERM
trap - TERM || echo failed
while true; do poll-once; sleep 5; done
`,
		"replace_left_of_and.sh": `#!/bin/bash
trap 'echo bye' TERM
trap - TERM && echo reset
while true; do poll-once; sleep 5; done
`,
		"replace_after_work_both.sh": `#!/bin/bash
trap 'echo bye' TERM
if [ -n "$strict" ]; then
  prepare-cache
  trap - TERM
else
  trap 'exit 143' TERM
fi
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// A loop in the handler that can only return or go on does not exit.
func TestShellTrapSignalWithoutExitLoopReturn(t *testing.T) {
	shellWanted(t, "shell-trap-signal-without-exit", "l03_loop_return_handler.sh", `#!/bin/bash
stop_children() {
  for p in $pids; do
    kill "$p" 2>/dev/null || return 0
  done
}
trap stop_children INT TERM # want
worker-a & pids="$!"
worker-b & pids="$pids $!"
while true; do check-health; sleep 30; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "loop_return_then_exit.sh", `#!/bin/bash
stop_children() {
  for p in $pids; do
    kill "$p" 2>/dev/null || return 0
  done
  exit 143
}
trap stop_children INT TERM
while true; do check-health; sleep 30; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "while_loop_return.sh", `#!/bin/bash
drain() {
  while read -r job; do
    cancel "$job" || return 1
  done < jobs.txt
}
trap drain TERM # want
while true; do check-health; sleep 30; done
`)
}

// A return inside a subshell of a setup function ends only the subshell,
// and the trap set there is gone with it.
func TestShellTrapSignalWithoutExitSubshellReturn(t *testing.T) {
	shellWanted(t, "shell-trap-signal-without-exit", "g01_subshell_return.sh", `#!/bin/bash
setup() {
  ( trap 'echo bye' TERM; return 0 )
}
setup
while poll-once; do sleep 5; done
`)
}

// Inside if, case and { } the branches run in order: a loop that comes
// after the trap is replaced in the same branch runs under the new handler.
func TestShellTrapSignalWithoutExitReplaceThenLoop(t *testing.T) {
	for name, source := range map[string]string{
		"t01_replace_then_loop_in_if.sh": `#!/bin/bash
trap 'echo "interrupted" >&2' TERM
if [ "${1:-}" = daemon ]; then
  trap 'echo "stopping" >&2; exit 143' TERM
  while poll-once; do sleep 5; done
fi
`,
		"t02_reset_then_loop_in_brace.sh": `#!/bin/bash
trap 'echo "interrupted" >&2' TERM
{
  trap - TERM
  while poll-once; do sleep 5; done
} >> watch.log 2>&1
`,
		"t04_case_replace_then_loop.sh": `#!/bin/bash
trap 'rm -f "$pidfile"' TERM
case "${1:-}" in
  watch)
    trap 'rm -f "$pidfile"; exit 143' TERM
    while poll-once; do sleep 5; done
    ;;
  *) echo "usage: $0 watch" ;;
esac
`,
		"replace_in_condition_then_loop.sh": `#!/bin/bash
trap 'echo bye' TERM
if trap - TERM; then
  while poll-once; do sleep 5; done
fi
`,
		"replace_left_of_and_then_loop.sh": `#!/bin/bash
trap 'echo bye' TERM
trap - TERM && while poll-once; do sleep 5; done
`,
		"replace_in_elif_branch_then_loop.sh": `#!/bin/bash
trap 'echo bye' TERM
if [ "$1" = a ]; then
  echo a
elif [ "$1" = b ]; then
  trap - TERM
  while poll-once; do sleep 5; done
fi
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
	shellWanted(t, "shell-trap-signal-without-exit", "t03_loop_then_reset_in_brace.sh", `#!/bin/bash
trap 'echo "interrupted" >&2' TERM # want
{
  while poll-once; do sleep 5; done
  trap - TERM
} >> watch.log 2>&1
`)
	shellWanted(t, "shell-trap-signal-without-exit", "loop_in_other_branch.sh", `#!/bin/bash
trap 'echo bye' TERM # want
if [ -n "$strict" ]; then
  trap - TERM
else
  while poll-once; do sleep 5; done
fi
`)
	shellWanted(t, "shell-trap-signal-without-exit", "loop_in_else_after_elif_replace.sh", `#!/bin/bash
trap 'echo bye' TERM # want
if [ "$1" = a ]; then
  trap - TERM
elif [ "$1" = b ]; then
  trap - TERM
else
  while poll-once; do sleep 5; done
fi
`)
	shellWanted(t, "shell-trap-signal-without-exit", "case_no_match_then_loop.sh", `#!/bin/bash
trap 'echo bye' TERM # want
case "$1" in
  strict) trap - TERM ;;
esac
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replace_other_signal_then_loop.sh", `#!/bin/bash
trap 'echo bye' INT TERM # want
{
  trap - INT
  while poll-once; do sleep 5; done
}
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replace_right_of_and_then_loop.sh", `#!/bin/bash
trap 'echo bye' TERM # want
[ -n "$strict" ] && trap - TERM
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replace_in_subshell_then_loop.sh", `#!/bin/bash
trap 'echo bye' TERM # want
( trap - TERM; while poll-once; do sleep 5; done )
`)
	shellWanted(t, "shell-trap-signal-without-exit", "work_then_echo_in_brace.sh", `#!/bin/bash
trap 'echo bye' TERM # want
{ prepare-cache; echo done; } >&2
`)
	shellWanted(t, "shell-trap-signal-without-exit", "work_in_then_only.sh", `#!/bin/bash
trap 'echo bye' TERM # want
if [ -n "$warm" ]; then
  prepare-cache
fi
`)
	shellWanted(t, "shell-trap-signal-without-exit", "work_in_if_condition.sh", `#!/bin/bash
trap 'echo bye' TERM # want
if prepare-cache; then
  echo ready
fi
`)
	shellWanted(t, "shell-trap-signal-without-exit", "loop_in_if_condition.sh", `#!/bin/bash
trap 'echo bye' TERM # want
if until ready; do sleep 1; done; then
  echo ready
fi
`)
	// The right of && runs with what its left side kept, and its own
	// replacement does not carry over the path where it does not run.
	shellWanted(t, "shell-trap-signal-without-exit", "replace_and_replace_rest.sh", `#!/bin/bash
trap 'echo bye' INT TERM
trap - TERM && trap - INT
trap - INT
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "replace_cond_then_branch_rest.sh", `#!/bin/bash
trap 'echo bye' INT TERM
if trap - TERM; then
  trap - INT
fi
trap - INT
while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "loop_right_of_and.sh", `#!/bin/bash
trap 'echo bye' TERM # want
[ "$1" = watch ] && while poll-once; do sleep 5; done
`)
	shellWanted(t, "shell-trap-signal-without-exit", "case_word_subst.sh", `#!/bin/bash
trap 'echo bye' TERM # want
case $(long-fetch) in a) echo a ;; esac
`)
	// As in a sequence, work before the handler is replaced everywhere
	// does not count.
	shellWanted(t, "shell-trap-signal-without-exit", "replace_in_case_after_word_subst.sh", `#!/bin/bash
trap 'echo bye' TERM
case $(long-fetch) in
  *) trap - TERM ;;
esac
`)
	shellWanted(t, "shell-trap-signal-without-exit", "case_word_subst_other_item.sh", `#!/bin/bash
trap 'echo bye' TERM # want
case $(long-fetch) in
  a) trap - TERM ;;
  *) echo other ;;
esac
`)
	shellWanted(t, "shell-trap-signal-without-exit", "loop_in_case_word.sh", `#!/bin/bash
trap 'echo bye' TERM # want
case $(while ! ready; do sleep 1; done) in
  *) trap - TERM ;;
esac
`)
	shellWanted(t, "shell-trap-signal-without-exit", "if_cond_subst.sh", `#!/bin/bash
trap 'echo bye' TERM # want
if [ -n "$(long-fetch)" ]; then echo a; fi
`)
	shellWanted(t, "shell-trap-signal-without-exit", "loop_in_cmdsubst.sh", `#!/bin/bash
trap 'echo bye' TERM # want
out=$(while poll-once; do sleep 5; done)
`)
}
