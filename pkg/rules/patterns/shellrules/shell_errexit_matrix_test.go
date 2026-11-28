package shellrules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
)

// errexitMatrixSpelling is one way a script turns errexit on or off before
// a body. on tells whether errexit is in force at the body when the script
// runs as a program. wrap "main" puts the head and the body in main() and
// calls it; "main-top" puts set -e at the top and the body in main().
type errexitMatrixSpelling struct {
	on                     bool
	shebang, head, trailer string
	wrap                   string
}

var errexitMatrixSpellings = []errexitMatrixSpelling{
	{true, "#!/bin/bash", "set -e", "", ""},
	{true, "#!/bin/bash", "set -e;", "", ""},
	{true, "#!/bin/bash", "set -eu; cd /tmp", "", ""},
	{true, "#!/bin/bash", "set -o errexit", "", ""},
	{true, "#!/bin/bash", "set -x -e", "", ""},
	{true, "#!/bin/bash", "set -o pipefail -e", "", ""},
	{true, "#!/bin/bash", "builtin set -e", "", ""},
	{false, "#!/bin/bash", "set -- -e", "", ""},
	{false, "#!/bin/bash", `set -- "$@" -e`, "", ""},
	{false, "#!/bin/bash", "set -e\nset +e", "", ""},
	{false, "#!/bin/bash", "f() { set -e; }", "", ""},
	{false, "#!/bin/bash", "( set -e; true )", "", ""},
	{true, "#!/bin/bash", "if set -e; then :; fi", "", ""},
	{true, "#!/bin/bash -e", "", "", ""},
	{false, "#!/bin/bash", "", "", ""},
	{true, "#!/bin/bash", "set -euo pipefail", "", ""},
	{false, "#!/bin/bash", "set -x # -e later", "", ""},
	{false, "#!/bin/bash", "set -u; echo -e foo", "", ""},
	{true, "#!/usr/bin/env -S bash -e", "", "", ""},
	{false, "#!/bin/bash", "set -e +e", "", ""},
	{true, "#!/bin/bash", `"set" -e`, "", ""},
	{true, "#!/bin/bash", "set -e; trap cleanup EXIT; if true; then :; fi", "", ""},
	{true, "#!/bin/bash", "set -e\ncleanup() { set +e; rm -f \"$tmp\"; }", "", ""},
	{true, "#!/bin/bash", "set -e\nset +e; rc=0; set -e", "", ""},
	{true, "#!/bin/bash", "set -e\ncleanup() {\n  set +e\n  rm -f \"$tmp\"\n}", "", ""},
	{true, "#!/bin/bash", "set -e\n(\n  set +e\n  true\n)", "", ""},
	{true, "#!/bin/bash", "set -e\nx=$(\n  set +e\n  echo\n)", "", ""},
	{false, "#!/bin/bash", "set -e\n{ set +e; }", "", ""},
	{true, "#!/bin/bash", "{ set -e; }", "", ""},
	{true, "#!/bin/bash", "set -e\ntrap 'set +e' EXIT", "", ""},
	{true, "#!/bin/bash", "set -e\ncat <(set +e; true)", "", ""},
	{false, "#!/bin/bash", "set -e\ndisable() { set +e; }\ndisable", "", ""},
	{true, "#!/bin/bash", "enable() { set -e; }\nenable", "", ""},
	{true, "#!/bin/bash", "set -euo pipefail", "", "main"},
	{true, "#!/bin/bash", "", "", "main-top"},
	{true, "#!/bin/sh -e", "", "", ""},
	{true, "#!/bin/bash -eu", "", "", ""},
	{true, "#!/usr/bin/env bash", "set -e", "", ""},
	{true, "#!/usr/bin/env -S bash -euo pipefail", "", "", ""},
	{false, "#!/bin/bash --noprofile", "", "", ""},
	{false, "#!/bin/bash -e", "set +e", "", ""},
	{true, "#!/bin/bash", "set -e", "set +e", ""},
	{false, "#!/bin/bash", "set -e\ncommand set +e", "", ""},
	{true, "#!/bin/bash", "set -e\ncat <<EOF\nset +e\nEOF", "", ""},
	{false, "#!/bin/bash", "cat <<EOF\nset -e\nEOF", "", ""},
	{true, "#!/bin/bash", "set -eE", "", ""},
	{true, "#!/bin/bash", "set -o nounset -o errexit", "", ""},
	{true, "#!/bin/bash", "set -e", "fi", ""},
	{true, "#!/bin/bash", "if true; then\n  set -e\nfi", "", ""},
	{false, "#!/bin/bash", "set -e\nif true; then\n  set +e\nfi", "", ""},
	{true, "#!/bin/bash", "shopt -so errexit", "", ""},
	{true, "#!/bin/bash", "set -euxo pipefail", "", ""},
	{true, "#!/bin/bash", "set -e\nf() ( set +e; )", "", ""},
	{true, "#!/bin/bash", "set -e\nx=`set +e`", "", ""},
	{false, "#!/bin/bash", "set -euo pipefail\nset +o errexit", "", ""},
	{true, "#!/bin/bash", "set -e\nssh \"$h\" \"set +e; uptime\"", "", ""},
}

// errexitMatrixFixture is a body whose finding depends on errexit: the rule
// reports it when errexit is on (whenOn) or when it is off.
type errexitMatrixFixture struct {
	name, rule, body string
	whenOn           bool
}

var errexitMatrixFixtures = []errexitMatrixFixture{
	{"grep", "shell-grep-filter-exits-on-empty", "docker run --rm img 2>&1 | grep -v INFO", true},
	{"loop", "shell-loop-ignores-step-failure", "for pair in \"$@\"; do\n  \"$repo/tools/ab.sh\" \"$pair\" > \"$log\" 2>&1\n  grep -E total: \"$log\" || echo none\ndone\necho \"queue done\"", false},
	{"andlist", "shell-and-list-failure-passes", "cd \"$dir\"\nsudo proxy -t && sudo proxy -s reload\necho \"Proxy switched to $port\"", true},
	{"checkout", "shell-check-output-discarded", "go test ./... >/dev/null", true},
	{"trap", "shell-trap-removes-results", "work=$(mktemp -d)\ntrap 'rm -rf \"$work\"' EXIT\nengine run > \"$work/log\" 2>&1\ncp \"$work/log\" \"$logs/run.log\"", true},
	{"quiet", "shell-pipe-producer-stderr-discarded", "ssh \"$host\" uptime 2>/dev/null > \"$f\"\nnext_step \"$f\"", false},
	{"handler", "shell-set-e-exits-before-failure-handler", "STATUS=$(systemctl is-active app)\nif [ \"$STATUS\" != \"active\" ]; then rollback down; fi", true},
	{"pipetail", "shell-status-of-pipe-tail", "set -o pipefail\nv=$(git ls-files | sort); test -z \"$v\" && echo clean", false},
}

func (s errexitMatrixSpelling) script(body string) string {
	switch s.wrap {
	case "main":
		return s.shebang + "\nmain() {\n" + s.head + "\n" + body + "\n}\nmain \"$@\"\n"
	case "main-top":
		return s.shebang + "\nset -e\nmain() {\n" + body + "\n}\nmain \"$@\"\n"
	}
	return s.shebang + "\n" + s.head + "\n" + body + "\n" + s.trailer + "\n"
}

// Every rule whose finding depends on errexit answers the same for each
// spelling: errexit comes from the flags of set itself and of the shebang,
// in the scope where set runs (top level, a called function, not a
// subshell, a substitution, an uncalled function or a heredoc).
func TestShellErrexitMatrixAcrossRules(t *testing.T) {
	for k, s := range errexitMatrixSpellings {
		for _, f := range errexitMatrixFixtures {
			name := fmt.Sprintf("%02d-%s/%s", k+1, f.name, strings.ReplaceAll(strings.ReplaceAll(s.shebang+" "+s.head+" "+s.trailer+" "+s.wrap, "\n", "⏎"), "/", "∕"))
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				file := fmt.Sprintf("%s-%d.sh", f.name, k+1)
				require.NoError(t, os.WriteFile(filepath.Join(root, file), []byte(s.script(f.body)), 0o600))
				got := patterntest.ShellFindingsIn(t, f.rule, root, file)
				if s.on == f.whenOn {
					assert.NotEmpty(t, got, "want a finding of %s", f.rule)
				} else {
					assert.Empty(t, got, "want no finding of %s", f.rule)
				}
			})
		}
	}
}
