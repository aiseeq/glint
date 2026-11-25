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
	for i := range n {
		fmt.Fprintf(&b, "step_%d() { step_%d; step_%d; }\n", i, i+1, i+1)
	}
	fmt.Fprintf(&b, "step_%d() { echo step; }\nstep_0\nwhile poll-once; do sleep 5; done\n", n)
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
