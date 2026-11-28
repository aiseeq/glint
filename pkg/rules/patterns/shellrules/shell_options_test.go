package shellrules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func scriptSource(t *testing.T, script string) *patternkit.ShellSource {
	t.Helper()
	ctx := core.NewFileContext("/p/a.sh", "/p", []byte(script), core.DefaultConfig())
	src, ok := patternkit.ReadShell(ctx)
	require.True(t, ok)
	return src
}

// The options of the last line of a script: errexit and pipefail as set,
// shopt, the shebang and the make shell leave them.
func TestShellOptionsSpellings(t *testing.T) {
	for _, c := range []struct {
		script            string
		errexit, pipefail bool
	}{
		{"#!/bin/bash\nset -oe pipefail\ntrue", true, true},
		{"#!/bin/bash\nset -euxo pipefail\ntrue", true, true},
		{"#!/bin/bash\nset -e +\ntrue", true, false},
		{"#!/bin/bash\nset - -e\ntrue", false, false},
		{"#!/bin/bash\nset \"$flags\" -e\ntrue", false, false},
		{"#!/bin/bash\nshopt -s -o errexit pipefail\ntrue", true, true},
		{"#!/bin/bash\nset -eo pipefail\nshopt -uo pipefail\ntrue", true, false},
		{"#!/bin/bash\nshopt -o errexit\ntrue", false, false},
		{"#!/bin/bash\nshopt -s errexit\ntrue", false, false},
		{"#!/bin/bash\nset -e\ncommand builtin set +e\ntrue", false, false},
		{"#!/bin/bash -o pipefail\ntrue", false, true},
		{"#!/usr/bin/env -S bash -euo pipefail\ntrue", true, true},
		{"#!/bin/bash\nset -e | cat\ntrue", false, false},
		{"#!/bin/bash\nset -e &\ntrue", false, false},
		{"#!/bin/bash\nset -e; { set +e; } > /dev/null\ntrue", false, false},
		{"#!/bin/bash\nf() { set -o pipefail; }\nf | cat\ntrue", false, false},
		{"#!/bin/bash\nf() { set -o pipefail; }\nif f; then :; fi\ntrue", false, true},
		{"#!/bin/bash\nf() { g; }\ng() { set -e; }\nf\ntrue", true, false},
		{"#!/bin/bash\nf() { f; set -e; }\nf\ntrue", true, false},
		{"#!/bin/bash\nset -e\nfi\ntrue", true, false},
	} {
		t.Run(c.script, func(t *testing.T) {
			src := scriptSource(t, c.script)
			options := scriptOptionsOf(src)
			require.NotNil(t, options)
			states := options.line(src, len(src.Lines)-1)
			assert.Equal(t, c.errexit, states.may(stateErrexit, true), "errexit")
			assert.False(t, c.errexit && states.may(stateErrexit, false), "errexit off in some run")
			assert.Equal(t, c.pipefail, states.may(statePipefail, true), "pipefail")
		})
	}
}

// A function called with errexit off and on is reached with both.
func TestShellOptionsFunctionCalledTwice(t *testing.T) {
	src := scriptSource(t, "#!/bin/bash\nf() {\n  true\n}\nf\nset -e\nf\n")
	states := scriptOptionsOf(src).line(src, 1)
	assert.True(t, states.may(stateErrexit, true))
	assert.True(t, states.may(stateErrexit, false))
}

// Every rule of a file reads one parse of it: the sources each rule reads
// share it through the file.
func TestShellOptionsParsedOncePerFile(t *testing.T) {
	ctx := core.NewFileContext("/p/a.sh", "/p", []byte("#!/bin/bash\nset -e\ntrue\n"), core.DefaultConfig())
	first, ok := patternkit.ReadShell(ctx)
	require.True(t, ok)
	second, ok := patternkit.ReadShell(ctx)
	require.True(t, ok)
	assert.Same(t, scriptOptionsOf(first), scriptOptionsOf(second))
}

// The make shell takes pipefail from SHELL and .SHELLFLAGS, also beside a
// make reference.
func TestShellOptionsMakeFlags(t *testing.T) {
	for _, c := range []struct {
		flags string
		want  bool
	}{
		{".SHELLFLAGS := -eo pipefail -c", true},
		{".SHELLFLAGS := $(EXTRA) -o pipefail -c", true},
		{"SHELL := /bin/bash -euo pipefail", true},
		{".SHELLFLAGS := -ec", false},
		{".SHELLFLAGS := -o pipefail +o pipefail -c", false},
	} {
		ctx := core.NewFileContext("/p/Makefile", "/p", []byte("SHELL := /bin/bash\n"+c.flags+"\nall:\n\ttrue\n"), core.DefaultConfig())
		src, ok := patternkit.ReadShell(ctx)
		require.True(t, ok)
		assert.Equal(t, c.want, makeSetsPipefail(src), c.flags)
	}
}

// The forms that read pipefail ask where their pipeline runs: pipefail set
// in a subshell or a function nothing calls before it does not hold there.
func TestShellOptionsPipefailScopeAcrossForms(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "status.sh", `#!/bin/bash
( set -o pipefail; true )
make build | tee build.log
echo "status $?" # want
`)
	shellWanted(t, "shell-status-of-pipe-tail", "status-on.sh", `#!/bin/bash
set -o pipefail
make build | tee build.log
echo "status $?"
`)
	shellWanted(t, "shell-pipeline-or-true-hides-producer", "excuse.sh", `#!/bin/bash
( set -o pipefail; true )
docker ps | grep api || true
`)
	shellWanted(t, "shell-pipeline-or-true-hides-producer", "excuse-on.sh", `#!/bin/bash
set -o pipefail
docker ps | grep api || true # want
`)
}

// Under set -e a failure anywhere between the trap and the copy exits, also
// when set -e comes after the trap.
func TestShellTrapRemovesResultsErrexitAfterTrap(t *testing.T) {
	shellWanted(t, "shell-trap-removes-results", "late.sh", `#!/bin/bash
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT # want
set -e
engine run > "$work/log" 2>&1
cp "$work/log" "$logs/run.log"
`)
	shellWanted(t, "shell-trap-removes-results", "off.sh", `#!/bin/bash
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
engine run > "$work/log" 2>&1
cp "$work/log" "$logs/run.log"
`)
}

// A checked capture reads pipefail where its pipeline runs: set inside the
// substitution before it holds, set in an earlier subshell does not.
func TestShellOptionsPipefailInCheckedCapture(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "inside.sh", `#!/bin/bash
out=$(set -o pipefail; curl -fsS "$URL" | jq -r .v) || exit 1
`)
	shellWanted(t, "shell-status-of-pipe-tail", "subshell.sh", `#!/bin/bash
( set -o pipefail )
out=$(curl -fsS "$URL" | jq -r .v) || exit 1 # want
`)
}
