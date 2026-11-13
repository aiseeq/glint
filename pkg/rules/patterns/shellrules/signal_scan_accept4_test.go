package shellrules

import "testing"

// A command list goes on after &&, || or | at the end of a line: the kill on
// the next line runs, also inside an if body and after a comment.
func TestSignalImplicitTargetKillAfterOperatorAtLineEnd(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "operator.sh", `#!/bin/bash
true &&
kill 0 # want
false ||
kill 0 # want
echo a |
kill 0 # want
if true; then echo a &&
  kill 0 # want
fi
true && # note
kill 0 # want
`)
}

// Both kills of a chain are reported, each on its own line.
func TestSignalImplicitTargetTwoKillsChainedOverLines(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "chain.sh", `#!/bin/bash
kill 0 && # want
kill $PPID # want
`)
}

// A here-document before the list does not hide the kill after the operator.
func TestSignalImplicitTargetKillAfterOperatorBelowDataHeredoc(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "below.sh", `#!/bin/bash
cat >/dev/null <<EOF
x
EOF
true &&
kill 0 # want
`)
}

// && inside a quoted string spanning lines is text; the kill after it runs.
func TestSignalImplicitTargetKillAfterMultilineStringEndingInOperator(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "string.sh", `#!/bin/bash
x="a &&
"; kill 0 # want
`)
}

// The body of an executed here-document is a script: an operator at the end
// of its line continues the list there too.
func TestSignalImplicitTargetKillAfterOperatorInExecutedHeredoc(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "body.sh", `#!/bin/bash
bash <<'EOF'
true &&
kill 0 # want
EOF
bash <<'A'; cat >/dev/null <<'B'
true &&
kill 0 # want
A
data
B
`)
}
