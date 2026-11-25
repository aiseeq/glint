package shellrules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
)

// A function called as a command of its own runs in the script's shell: a
// trap it replaces or resets on every path, and an exit it runs on every
// path, hold for the commands after the call.
func TestShellTrapSignalWithoutExitFunctionCall(t *testing.T) {
	for name, source := range map[string]string{
		"o01_fn_reset_then_loop.sh": `#!/bin/bash
trap 'echo "interrupted" >&2' TERM
f() { trap - TERM; }
f
while poll-once; do sleep 5; done
`,
		"t05_fn_replace_then_loop.sh": `#!/bin/bash
trap 'rm -f "$pidfile"' TERM
watch_mode() {
  trap 'rm -f "$pidfile"; exit 143' TERM
  while poll-once; do sleep 5; done
}
[ "${1:-}" = watch ] || exit 0
watch_mode
`,
		"case_die_other_branch.sh": `#!/bin/bash
die() { echo "$*" >&2; exit 1; }
trap 'rm -f "$pidfile"' TERM
case "${1:-}" in
  watch) trap 'rm -f "$pidfile"; exit 143' TERM ;;
  *) die "usage: $0 watch" ;;
esac
while poll-once; do sleep 5; done
`,
		"fn_reset_both_branches.sh": `#!/bin/bash
trap 'echo bye' TERM
quiet() {
  if [ -n "$verbose" ]; then trap 'echo stop; exit 143' TERM; else trap - TERM; fi
}
quiet
while poll-once; do sleep 5; done
`,
		"fn_calls_fn_reset.sh": `#!/bin/bash
trap 'echo bye' TERM
reset_traps() { trap - INT TERM; }
setup() { echo setup; reset_traps; }
setup
while poll-once; do sleep 5; done
`,
		"fn_reset_left_of_or.sh": `#!/bin/bash
trap 'echo bye' TERM
reset_traps() { trap - TERM; }
reset_traps || exit 1
while poll-once; do sleep 5; done
`,
		"fn_die_right_of_or_then_reset.sh": `#!/bin/bash
die() { echo "$*" >&2; exit 1; }
trap 'echo bye' TERM
[ -n "${1:-}" ] || die "usage"
trap - TERM
while poll-once; do sleep 5; done
`,
		"fn_die_in_else.sh": `#!/bin/bash
die() { echo "$*" >&2; exit 1; }
trap 'echo bye' TERM
if [ -n "${STRICT:-}" ]; then trap 'exit 143' TERM; else die "STRICT is required"; fi
while poll-once; do sleep 5; done
`,
		"fn_trailing_return.sh": `#!/bin/bash
trap 'echo bye' TERM
f() { trap - TERM; return 0; }
f
while poll-once; do sleep 5; done
`,
		"fn_redirected_call.sh": `#!/bin/bash
trap 'echo bye' TERM
f() { trap - TERM; }
f > /dev/null 2>&1
while poll-once; do sleep 5; done
`,
		"true_and_reset.sh": `#!/bin/bash
trap 'echo bye' TERM
true && trap - TERM
while poll-once; do sleep 5; done
`,
		"false_or_reset.sh": `#!/bin/bash
trap 'echo bye' TERM
false || trap - TERM
while poll-once; do sleep 5; done
`,
		"false_and_loop.sh": `#!/bin/bash
trap 'echo bye' TERM
false && while poll-once; do sleep 5; done
trap - TERM
`,
		"fn_called_for_two_traps.sh": `#!/bin/bash
trap 'echo int' INT
reset_traps() { trap - INT TERM; }
reset_traps
trap 'echo term' TERM
reset_traps
while poll-once; do sleep 5; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// Neighbours of a call that replaces the trap: a call that does not run in
// the script's shell, a function never called or replacing on one path, a
// return before the reset, a function defined twice and recursion.
func TestShellTrapSignalWithoutExitFunctionCallNeighbors(t *testing.T) {
	for name, source := range map[string]string{
		"fn_reset_one_path.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { if [ -n "$1" ]; then trap - TERM; fi; }
f "$mode"
while poll-once; do sleep 5; done
`,
		"fn_declared_not_called.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { trap - TERM; }
while poll-once; do sleep 5; done
`,
		"fn_background.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { trap - TERM; }
f &
while poll-once; do sleep 5; done
`,
		"fn_subst.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { trap - TERM; }
out=$(f)
while poll-once; do sleep 5; done
`,
		"fn_pipeline.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { trap - TERM; }
f | cat
while poll-once; do sleep 5; done
`,
		"fn_subshell_body.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() ( trap - TERM )
f
while poll-once; do sleep 5; done
`,
		"fn_redefined_after_call.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { echo start; }
f
while poll-once; do sleep 5; done
f() { trap - TERM; }
`,
		"fn_redefined_before_call.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { trap - TERM; }
f() { echo start; }
f
while poll-once; do sleep 5; done
`,
		"fn_return_before_reset.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { [ -n "$1" ] || return 0; trap - TERM; }
f "$mode"
while poll-once; do sleep 5; done
`,
		"fn_return_then_reset.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { return 0; trap - TERM; }
f
while poll-once; do sleep 5; done
`,
		"fn_exit_one_path.sh": `#!/bin/bash
need() { [ -n "$1" ] || exit 1; }
trap 'echo bye' TERM # want
case "${1:-}" in
  watch) trap 'exit 143' TERM ;;
  *) need "$2" ;;
esac
while poll-once; do sleep 5; done
`,
		"fn_and_reset_may_skip.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { trap - TERM; }
[ -n "$1" ] && f
while poll-once; do sleep 5; done
`,
		"fn_loop_then_reset.sh": `#!/bin/bash
trap 'echo bye' TERM # want
wait_ready() { while ! ready; do sleep 1; done; }
wait_ready
trap - TERM
`,
		"fn_work_then_die.sh": `#!/bin/bash
die() { echo "$*" >&2; exit 1; }
trap 'rm -f "$tmp"' TERM # want
download "$url" > "$tmp" || die "download failed"
trap - TERM
`,
		"fn_recursive.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { [ -n "$1" ] && f "${1#?}"; echo "$1"; }
f abc
while poll-once; do sleep 5; done
`,
		"fn_mutual_recursion.sh": `#!/bin/bash
trap 'echo bye' TERM # want
a() { [ -n "$1" ] && b "${1#?}"; }
b() { a "$1"; }
a abc
while poll-once; do sleep 5; done
`,
		"command_bypasses_fn.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { trap - TERM; }
command f
while poll-once; do sleep 5; done
`,
		"eval_and_reset.sh": `#!/bin/bash
trap 'echo bye' TERM # want
eval "$setup" && trap - TERM
while poll-once; do sleep 5; done
`,
		"true_or_reset.sh": `#!/bin/bash
trap 'echo bye' TERM # want
true || trap - TERM
while poll-once; do sleep 5; done
`,
		"return_and_reset.sh": `#!/bin/bash
g() {
  trap 'echo bye' TERM # want
  return 0 && trap - TERM
}
g
while poll-once; do sleep 5; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// Each function is followed once for the signals that keep the handler
// before its call: a chain of functions that each call the next twice and
// replace nothing is walked in linear time, not in 2^n.
func TestShellTrapSignalWithoutExitFunctionCallChain(t *testing.T) {
	const n = 40
	var b strings.Builder
	b.WriteString("#!/bin/bash\ntrap 'echo bye' TERM # want\n")
	fmt.Fprintf(&b, "step_%d() { echo step; }\n", n)
	for i := n - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "step_%d() { step_%d; step_%d; }\n", i, i+1, i+1)
	}
	b.WriteString("step_0\nwhile poll-once; do sleep 5; done\n")
	done := make(chan []string, 1)
	go func() {
		done <- patterntest.ShellFindings(t, "shell-trap-signal-without-exit", map[string]string{"chain.sh": b.String()})
	}()
	select {
	case got := <-done:
		assert.Equal(t, []string{"chain.sh:2"}, got)
	case <-time.After(5 * time.Second):
		t.Fatal("the calls of a chain of functions are walked again for every caller")
	}
}

// A call is followed only into the function the script surely runs: one
// defined once, at the top level of the script, before the call, never
// unset and not hidden by an alias. Otherwise the call is work and its
// status is unknown, as in main.
func TestShellTrapSignalWithoutExitFunctionVisibility(t *testing.T) {
	for name, source := range map[string]string{
		"d02_call_before_def.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f 2>/dev/null
f() { trap - TERM; }
while poll-once; do sleep 5; done
`,
		"d03_unset_f.sh": `#!/bin/bash
f() { trap - TERM; }
trap 'echo bye' TERM # want
unset -f f
f 2>/dev/null
while poll-once; do sleep 5; done
`,
		"unset_no_option.sh": `#!/bin/bash
f() { trap - TERM; }
trap 'echo bye' TERM # want
unset f
f 2>/dev/null
while poll-once; do sleep 5; done
`,
		"d04_def_in_subshell.sh": `#!/bin/bash
( f() { trap - TERM; } )
trap 'echo bye' TERM # want
f 2>/dev/null
while poll-once; do sleep 5; done
`,
		"d05_def_in_uncalled_fn.sh": `#!/bin/bash
outer() { f() { trap - TERM; }; }
trap 'echo bye' TERM # want
f 2>/dev/null
while poll-once; do sleep 5; done
`,
		"d15_def_in_if_false.sh": `#!/bin/bash
if false; then f() { trap - TERM; }; fi
trap 'echo bye' TERM # want
f 2>/dev/null
while poll-once; do sleep 5; done
`,
		"d12_alias.sh": `#!/bin/bash
shopt -s expand_aliases
f() { trap - TERM; }
alias f=':'
trap 'echo bye' TERM # want
f
while poll-once; do sleep 5; done
`,
		"d10_twice_status_late_def.sh": `#!/bin/bash
f() { true; }
trap 'echo bye' TERM # want
f || trap - TERM
f() { false; }
while poll-once; do sleep 5; done
`,
		"d11_and_before_def.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f 2>/dev/null && trap - TERM
f() { true; }
while poll-once; do sleep 5; done
`,
		"unset_variable_keeps_fn.sh": `#!/bin/bash
f() { trap - TERM; }
trap 'echo bye' TERM
unset -v f
f
while poll-once; do sleep 5; done
`,
		"alias_other_name.sh": `#!/bin/bash
f() { trap - TERM; }
alias ll='ls -l'
trap 'echo bye' TERM
f
while poll-once; do sleep 5; done
`,
		"b13_nested_def_called_in_body.sh": `#!/bin/bash
outer() { inner() { trap - TERM; }; inner; }
trap 'echo bye' TERM
outer
while poll-once; do sleep 5; done
`,
		"nested_call_before_def.sh": `#!/bin/bash
outer() { inner 2>/dev/null; inner() { trap - TERM; }; }
trap 'echo bye' TERM # want
outer
while poll-once; do sleep 5; done
`,
		"b24_chain_defined_below.sh": `#!/bin/bash
trap 'echo bye' TERM
f1() { f2; }
f2() { f3; }
f3() { trap - TERM; }
f1
while poll-once; do sleep 5; done
`,
		"e10_exit_two_deep.sh": `#!/bin/bash
trap 'echo bye' TERM
f() { g; }
g() { exit 0; }
f
while poll-once; do sleep 5; done
`,
		"trap_in_fn_callee_defined_below.sh": `#!/bin/bash
g() { trap 'echo bye' TERM; f; while poll-once; do sleep 5; done; }
f() { trap - TERM; }
g
`,
		"trap_in_fn_called_before_callee_def.sh": `#!/bin/bash
g() { trap 'echo bye' TERM; f 2>/dev/null; while poll-once; do sleep 5; done; } # want
g
f() { trap - TERM; }
g
`,
		"same_fn_called_before_and_after_def.sh": `#!/bin/bash
trap 'echo bye' TERM
g() { f 2>/dev/null; }
g
f() { trap - TERM; }
g
while poll-once; do sleep 5; done
`,
		"redefined_by_called_fn.sh": `#!/bin/bash
outer() { f() { :; }; }
f() { trap - TERM; }
trap 'echo bye' TERM # want
outer
f
while poll-once; do sleep 5; done
`,
		"trap_in_fn_called_through_fn.sh": `#!/bin/bash
g() { trap 'echo bye' TERM; f; while poll-once; do sleep 5; done; }
h() { g; }
f() { trap - TERM; }
h
`,
		"trap_in_fn_reached_two_ways.sh": `#!/bin/bash
g() { trap 'echo bye' TERM; f; while poll-once; do sleep 5; done; }
b() { g; }
a() { g; b; }
f() { trap - TERM; }
a
`,
		"trap_in_call_cycle.sh": `#!/bin/bash
a() { trap 'echo bye' TERM; b; } # want
b() { [ -n "$1" ] && a; }
a
while poll-once; do sleep 5; done
`,
		"status_fn_defined_before.sh": `#!/bin/bash
f() { false; }
trap 'echo bye' TERM
f || trap - TERM
while poll-once; do sleep 5; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// A function named as a builtin replaces it: true, false, exit and their
// kin then neither give a known status nor end the path, unless command or
// builtin skips the function.
func TestShellTrapSignalWithoutExitShadowedBuiltin(t *testing.T) {
	for name, source := range map[string]string{
		"d06_true_overridden.sh": `#!/bin/bash
true() { return 1; }
trap 'echo bye' TERM # want
true && trap - TERM
while poll-once; do sleep 5; done
`,
		"d09_false_overridden.sh": `#!/bin/bash
false() { :; }
trap 'echo bye' TERM # want
false || trap - TERM
while poll-once; do sleep 5; done
`,
		"d16_fn_exit_overridden.sh": `#!/bin/bash
exit() { :; }
die() { exit 1; }
trap 'echo bye' TERM # want
die
while poll-once; do sleep 5; done
`,
		"exit_overridden_direct.sh": `#!/bin/bash
exit() { echo "exit $*"; }
trap 'echo bye' TERM # want
case "$1" in
  watch) trap - TERM ;;
  *) exit 1 ;;
esac
while poll-once; do sleep 5; done
`,
		"trap_overridden.sh": `#!/bin/bash
trap 'echo bye' TERM # want
trap() { echo "trap $*"; }
trap - TERM
while poll-once; do sleep 5; done
`,
		"command_overridden.sh": `#!/bin/bash
command() { return 1; }
trap 'echo bye' TERM # want
command true && trap - TERM
while poll-once; do sleep 5; done
`,
		"command_fn_status.sh": `#!/bin/bash
f() { true; }
trap 'echo bye' TERM # want
command f && trap - TERM
while poll-once; do sleep 5; done
`,
		"shadowed_builtin_not_followed_is_work.sh": `#!/bin/bash
true() { sleep 1; }
true() { sync-all; }
trap 'rm -f "$tmp"' TERM # want
true
`,
		"command_true_skips_fn.sh": `#!/bin/bash
true() { return 1; }
trap 'echo bye' TERM
command true && trap - TERM
while poll-once; do sleep 5; done
`,
		"builtin_exit_skips_fn.sh": `#!/bin/bash
exit() { :; }
die() { builtin exit 1; }
trap 'echo bye' TERM
case "$1" in
  watch) trap 'exit 143' TERM ;; # want
  *) die ;;
esac
while poll-once; do sleep 5; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// A redirection that may not open, as one to a file, keeps the command
// from running: its status is then 1, and a function called with it, or
// defined with it, replaces no trap. /dev/null and a duplicated descriptor
// always open.
func TestShellTrapSignalWithoutExitRedirectMayFail(t *testing.T) {
	for name, source := range map[string]string{
		"d07_true_redir_fail.sh": `#!/bin/bash
trap 'echo bye' TERM # want
true > "$dir/x" 2>/dev/null && trap - TERM
while poll-once; do sleep 5; done
`,
		"e15_brace_redir_fail.sh": `#!/bin/bash
trap 'echo bye' TERM # want
{ true; } > "$dir/x" 2>/dev/null && trap - TERM
while poll-once; do sleep 5; done
`,
		"d08_fn_redir_fail.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { trap - TERM; }
f > "$dir/x"
while poll-once; do sleep 5; done
`,
		"e14_fn_def_redir_fail.sh": `#!/bin/bash
trap 'echo bye' TERM # want
f() { trap - TERM; } 2>"$dir/x"
f
while poll-once; do sleep 5; done
`,
		"dup_literal_file.sh": `#!/bin/bash
trap 'echo bye' TERM # want
true >&logfile && trap - TERM
while poll-once; do sleep 5; done
`,
		"dup_to_file_word.sh": `#!/bin/bash
trap 'echo bye' TERM # want
true >&"$log" && trap - TERM
while poll-once; do sleep 5; done
`,
		"e12_fn_redir_dev_null.sh": `#!/bin/bash
trap 'echo bye' TERM
f() { trap - TERM; }
f 2>/dev/null </dev/null
while poll-once; do sleep 5; done
`,
		"e13_fn_def_redir_dev_null.sh": `#!/bin/bash
trap 'echo bye' TERM
f() { trap - TERM; } > /dev/null
f
while poll-once; do sleep 5; done
`,
		"true_dup_and_reset.sh": `#!/bin/bash
trap 'echo bye' TERM
true >&2 2>&- && trap - TERM
while poll-once; do sleep 5; done
`,
		"true_heredoc_and_reset.sh": `#!/bin/bash
trap 'echo bye' TERM
true <<EOT && trap - TERM
text
EOT
while poll-once; do sleep 5; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// The status of the left of a long && chain is found once per command, so
// the chain is walked in linear time.
func TestShellTrapSignalWithoutExitLongAndChain(t *testing.T) {
	const n = 8000
	var b strings.Builder
	b.WriteString("#!/bin/bash\ntrap 'echo bye' TERM\n")
	b.WriteString(strings.Repeat("true && ", n))
	b.WriteString("trap - TERM\nwhile poll-once; do sleep 5; done\n")
	done := make(chan []string, 1)
	go func() {
		done <- patterntest.ShellFindings(t, "shell-trap-signal-without-exit", map[string]string{"and.sh": b.String()})
	}()
	select {
	case got := <-done:
		assert.Empty(t, got)
	case <-time.After(5 * time.Second):
		t.Fatal("the status of the left of && is walked again on every level of the chain")
	}
}

// The place that has surely run before the body of a function is found
// once per function: a trap at the end of a chain of functions that each
// call the next twice is followed in linear time.
func TestShellTrapSignalWithoutExitTrapInCalledChain(t *testing.T) {
	const n = 40
	var b strings.Builder
	fmt.Fprintf(&b, "#!/bin/bash\nstep_%d() { trap 'echo bye' TERM; while poll-once; do sleep 5; done; } # want\n", n)
	for i := n - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "step_%d() { step_%d; step_%d; }\n", i, i+1, i+1)
	}
	b.WriteString("step_0\n")
	done := make(chan []string, 1)
	go func() {
		done <- patterntest.ShellFindings(t, "shell-trap-signal-without-exit", map[string]string{"called.sh": b.String()})
	}()
	select {
	case got := <-done:
		assert.Equal(t, []string{"called.sh:2"}, got)
	case <-time.After(5 * time.Second):
		t.Fatal("the callers of a function are walked again for every path to it")
	}
}

// A handler that exits through a command with a redirection exits: the
// status walk of && and || may doubt the redirection, the exit of a
// handler does not, as in main. /dev/stderr and its kin always open.
func TestShellTrapSignalWithoutExitHandlerExitRedirected(t *testing.T) {
	for name, source := range map[string]string{
		"t11_handler_die_redirect.sh": `#!/bin/bash
die() { exit 1; }
trap 'die >>/dev/stderr' TERM
while poll-once; do sleep 5; done
`,
		"t12_handler_fn_def_redirect.sh": `#!/bin/bash
cleanup() { echo bye; exit 1; } >>/dev/stderr
trap cleanup TERM
while poll-once; do sleep 5; done
`,
		"t13_handler_block_redirect.sh": `#!/bin/bash
trap '{ echo bye; exit 1; } >>/dev/stderr' TERM
while poll-once; do sleep 5; done
`,
		"t14_handler_exit_redirect.sh": `#!/bin/bash
trap 'exit 1 2>/dev/stderr' TERM
while poll-once; do sleep 5; done
`,
		"handler_exit_redirect_to_file.sh": `#!/bin/bash
trap 'exit 1 2>>"$log"' TERM
while poll-once; do sleep 5; done
`,
		"true_to_stderr_and_reset.sh": `#!/bin/bash
trap 'echo bye' TERM
true 2>/dev/stderr && trap - TERM
while poll-once; do sleep 5; done
`,
		"fn_to_fd_path.sh": `#!/bin/bash
trap 'echo bye' TERM
f() { trap - TERM; }
f >/dev/fd/2 </dev/stdin 2>/dev/stdout
while poll-once; do sleep 5; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
	for name, target := range map[string]string{"true_to_fd_like_file.sh": "/dev/fdx", "true_to_fd_named.sh": "/dev/fd/x", "true_to_digit_file.sh": "123"} {
		shellWanted(t, "shell-trap-signal-without-exit", name, `#!/bin/bash
trap 'echo bye' TERM # want
true >`+target+` && trap - TERM
while poll-once; do sleep 5; done
`)
	}
}

// A function named as a builtin hides it only where its definition is
// seen, by the table calls use; a function that only passes its arguments
// on to the builtin of its name is that builtin.
func TestShellTrapSignalWithoutExitShadowSeen(t *testing.T) {
	for name, source := range map[string]string{
		"s05_trap_wrapper.sh": `#!/bin/bash
trap 'echo bye' TERM
trap() { builtin trap "$@"; }
trap - TERM
while poll-once; do sleep 5; done
`,
		"trap_command_wrapper.sh": `#!/bin/bash
trap 'echo bye' TERM
trap() { command trap "$@"; }
trap - TERM
while poll-once; do sleep 5; done
`,
		"s10_fn_true_defined_later.sh": `#!/bin/bash
trap 'echo bye' TERM
true && trap - TERM
true() { return 1; }
while poll-once; do sleep 5; done
`,
		"s11_exit_fn_defined_later.sh": `#!/bin/bash
trap 'echo bye' TERM
exit 0
exit() { :; }
while poll-once; do sleep 5; done
`,
		"s15_trap_fn_after_reset.sh": `#!/bin/bash
trap 'echo bye' TERM
trap - TERM
trap() { :; }
while poll-once; do sleep 5; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
	for name, source := range map[string]string{
		"s07_exit_fn_noop.sh": `#!/bin/bash
trap 'echo bye' TERM # want
exit() { :; }
exit 0
while poll-once; do sleep 5; done
`,
		"s06_exit_wrapper_with_work.sh": `#!/bin/bash
trap 'echo bye' TERM # want
exit() { rm -f "$tmp"; builtin exit "$@"; }
exit 0
`,
		"wrapper_of_other_builtin.sh": `#!/bin/bash
trap 'echo bye' TERM # want
trap() { builtin echo "$@"; }
trap - TERM
while poll-once; do sleep 5; done
`,
		"nested_exit_after_setup.sh": `#!/bin/bash
trap 'echo bye' TERM # want
setup() { exit() { :; }; }
setup
exit 0
while poll-once; do sleep 5; done
`,
		"nested_true_status_after_setup.sh": `#!/bin/bash
trap 'echo bye' TERM # want
setup() { true() { return 1; }; }
setup
true && trap - TERM
while poll-once; do sleep 5; done
`,
		"true_fn_defined_below_caller_body.sh": `#!/bin/bash
trap 'echo bye' TERM # want
g() { true && trap - TERM; }
true() { return 1; }
g
while poll-once; do sleep 5; done
`,
		"true_fn_calls_builtin_then_false.sh": `#!/bin/bash
trap 'echo bye' TERM # want
true() { builtin true "$@"; false; }
true && trap - TERM
while poll-once; do sleep 5; done
`,
		"wrapper_in_background.sh": `#!/bin/bash
trap 'echo bye' TERM # want
trap() { builtin trap "$@" & }
trap - TERM
while poll-once; do sleep 5; done
`,
		"wrapper_redirect_may_fail.sh": `#!/bin/bash
trap 'echo bye' TERM # want
trap() { builtin trap "$@"; } 2>>"$log"
trap - TERM
while poll-once; do sleep 5; done
`,
		"wrapper_fixed_args.sh": `#!/bin/bash
trap 'echo bye' TERM # want
trap() { builtin trap "$1"; }
trap - TERM
while poll-once; do sleep 5; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// eval, a sourced file and a command named by a variable or a
// substitution may run or define a function anywhere: no call is followed
// into a function then, as in main.
func TestShellTrapSignalWithoutExitOpaqueCalls(t *testing.T) {
	for name, source := range map[string]string{
		"r01_eval_runs_before_def.sh": `#!/bin/bash
g() { trap 'echo bye' TERM; f 2>/dev/null; while poll-once; do sleep 5; done; } # want
eval g
f() { trap - TERM; }
g
`,
		"r02_var_runs_before_def.sh": `#!/bin/bash
g() { trap 'echo bye' TERM; f 2>/dev/null; while poll-once; do sleep 5; done; } # want
cmd=g
$cmd
f() { trap - TERM; }
g
`,
		"r03_source_overrides.sh": `#!/bin/bash
f() { trap - TERM; }
trap 'echo bye' TERM # want
. "$(dirname "$0")/override.inc"
f
while poll-once; do sleep 5; done
`,
		"r04_eval_redefines.sh": `#!/bin/bash
f() { trap - TERM; }
trap 'echo bye' TERM # want
eval 'f() { :; }'
f
while poll-once; do sleep 5; done
`,
		"command_eval_redefines.sh": `#!/bin/bash
f() { trap - TERM; }
trap 'echo bye' TERM # want
command eval 'f() { :; }'
f
while poll-once; do sleep 5; done
`,
		"eval_redefines_status_fn.sh": `#!/bin/bash
f() { true; }
trap 'echo bye' TERM # want
eval 'f() { false; }'
f && trap - TERM
while poll-once; do sleep 5; done
`,
		"subst_names_command.sh": `#!/bin/bash
f() { trap - TERM; }
trap 'echo bye' TERM # want
"$(pick-tool)" --check
f
while poll-once; do sleep 5; done
`,
		"quoted_static_name.sh": `#!/bin/bash
f() { trap - TERM; }
trap 'echo bye' TERM
"f"
while poll-once; do sleep 5; done
`,
		"b29_source_dev_null.sh": `#!/bin/bash
trap 'echo bye' TERM
f() { trap - TERM; }
. /dev/null
f
while poll-once; do sleep 5; done
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}

// Calls interleaved with definitions: the effect of a function is kept
// for every set of definitions it depends on, not for each place it is
// called from, so the script is walked in time near its size.
func TestShellTrapSignalWithoutExitInterleavedDefinitions(t *testing.T) {
	const n = 600
	var b strings.Builder
	b.WriteString("#!/bin/bash\ntrap 'echo bye' TERM # want\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "f%d() { ", i)
		for j := 1; j < i; j++ {
			fmt.Fprintf(&b, "f%d; ", j)
		}
		fmt.Fprintf(&b, "sleep 0; }\nf%d\n", i)
	}
	b.WriteString("while poll-once; do sleep 5; done\n")
	done := make(chan []string, 1)
	go func() {
		done <- patterntest.ShellFindings(t, "shell-trap-signal-without-exit", map[string]string{"epoch.sh": b.String()})
	}()
	select {
	case got := <-done:
		assert.Equal(t, []string{"epoch.sh:2"}, got)
	case <-time.After(5 * time.Second):
		t.Fatal("the functions are walked again at every definition run before a call")
	}
}

// The effect kept for a call holds only for the definitions its body saw:
// a call made before and after a function it calls is defined, or from a
// place whose call at the top level is not known, is followed again.
func TestShellTrapSignalWithoutExitCallKeptPerDefinitions(t *testing.T) {
	for name, source := range map[string]string{
		"callee_defined_between_calls.sh": `#!/bin/bash
trap 'echo bye' TERM
g() { f; }
g
f() { trap - TERM; }
g
while poll-once; do sleep 5; done
`,
		"seen_first_then_unseen.sh": `#!/bin/bash
g() { f; }
k() { trap 'echo a' TERM; g; while poll-once; do sleep 5; done; }
h() { trap 'echo b' TERM; g; while poll-once; do sleep 5; done; } # want
h
f() { trap - TERM; }
k
`,
		"seen_through_nested_call.sh": `#!/bin/bash
m() { f; }
g() { m; }
k() { trap 'echo a' TERM; g; while poll-once; do sleep 5; done; }
h() { trap 'echo b' TERM; g; while poll-once; do sleep 5; done; } # want
h
f() { trap - TERM; }
k
`,
		"exit_hidden_for_later_caller.sh": `#!/bin/bash
g() { exit 0; }
h() { trap 'echo b' TERM; g; while poll-once; do sleep 5; done; } # want
trap 'echo a' TERM
if [ "$1" = stop ]; then g; fi
if [ "$1" = early ]; then h; fi
exit() { :; }
h
`,
	} {
		shellWanted(t, "shell-trap-signal-without-exit", name, source)
	}
}
