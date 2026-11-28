package shellrules

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
)

// errexitScopeProbes are scripts whose capture line (# CAP) hides a failed
// producer only when errexit or pipefail is off where the line runs. want
// is what bash does when the script runs as a program with a git that fails
// with empty output: true when "clean" is printed. errexit and pipefail
// follow the call: a function gets the state of its call site, not of its
// declaration; a subshell starts with the state of its parent at the point
// it runs; a $(…) drops -e; the shebang counts.
var errexitScopeProbes = []struct {
	name   string
	want   bool
	script string
}{
	{"N-brace-group.sh", false, `#!/bin/bash
{ set -euo pipefail; }
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"N-builtin-set.sh", false, `#!/bin/bash
builtin set -e -o pipefail
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"N-conditional-set.sh", false, `#!/bin/bash
if true; then set -euo pipefail; fi
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"N-env-bash.sh", false, `#!/usr/bin/env bash
set -Eeuo pipefail
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"N-fn-after-set.sh", false, `#!/bin/bash
set -euo pipefail
f() {
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
}
f`},
	{"N-fn-in-fn.sh", false, `#!/bin/bash
outer() {
  inner() {
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
}
  inner
}
set -euo pipefail
outer`},
	{"N-helper-declared-before-set.sh", false, `#!/bin/bash
helper() {
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
}
set -euo pipefail
main() { helper; }
main`},
	{"N-helper-from-main.sh", false, `#!/bin/bash
helper() {
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
}
main() { set -euo pipefail; helper; }
main "$@"`},
	{"N-long.sh", false, `#!/bin/bash
set -o errexit
set -o pipefail
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"N-main-body.sh", false, `#!/bin/bash
main() {
  set -euo pipefail
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
}
main "$@"`},
	{"N-pipefail-in-fn-errexit-top.sh", false, `#!/bin/bash
set -e
f() {
  set -o pipefail
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
}
f`},
	{"N-semicolon.sh", false, `#!/bin/bash
set -e; set -o pipefail; out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"N-set-o-pipefail-e.sh", false, `#!/bin/bash
set -o pipefail -e
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"N-setup-fn.sh", false, `#!/bin/bash
strict() { set -euo pipefail; }
strict
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"N-shebang.sh", false, `#!/bin/bash -e
set -o pipefail
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"N-subshell-in-fn.sh", false, `#!/bin/bash
f() { (
  cd /tmp
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
) }
set -euo pipefail
f`},
	{"N-top.sh", false, `#!/bin/bash
set -euo pipefail
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"W-errexit-in-subshell-pipefail-top.sh", true, `#!/bin/bash
set -o pipefail
( set -e )
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"W-in-cmdsubst.sh", true, `#!/bin/bash
set -eo pipefail
r=$(
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
)
echo "$r"`},
	{"W-local.sh", true, `#!/bin/bash
set -euo pipefail
f() { local out=$(git ls-files | sort); test -z "$out" && echo clean; } # CAP
f`},
	{"W-main-before-set.sh", true, `#!/bin/bash
main() {
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
  set -euo pipefail
}
main "$@"`},
	{"W-noerr-fn.sh", true, `#!/bin/bash
set -eo pipefail
noerr() { set +e; }
noerr
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"W-none.sh", true, `#!/bin/bash
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"W-pipefail-in-subshell-errexit-top.sh", true, `#!/bin/bash
set -e
( set -o pipefail )
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"W-pipefail-later-in-other-fn.sh", true, `#!/bin/bash
set -e
g() { set -o pipefail; }
f() {
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
}
f
g`},
	{"W-plus-e-after-call.sh", true, `#!/bin/bash
set -euo pipefail
f() {
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
}
set +e
f`},
	{"W-set-dashdash.sh", true, `#!/bin/bash
set -- -e
set -o pipefail
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"W-set-E-only.sh", true, `#!/bin/bash
set -Eo pipefail
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"W-set-x-only.sh", true, `#!/bin/bash
set -xo pipefail
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"W-subshell-plus-e.sh", true, `#!/bin/bash
set -euo pipefail
(
  set +e
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
)`},
	{"W-subshell-then-top.sh", true, `#!/bin/bash
( set -eo pipefail; true )
out=$(git ls-files | sort); test -z "$out" && echo clean # CAP`},
	{"W-twocalls.sh", true, `#!/bin/bash
f() {
  out=$(git ls-files | sort); test -z "$out" && echo clean # CAP
}
f
set -eo pipefail
f`},
}

func TestShellErrexitScopeProbes(t *testing.T) {
	for _, p := range errexitScopeProbes {
		t.Run(p.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(root, p.name), []byte(p.script+"\n"), 0o600))
			line := 0
			for i, l := range strings.Split(p.script, "\n") {
				if strings.Contains(l, "# CAP") {
					line = i + 1
				}
			}
			require.NotZero(t, line)
			got := patterntest.ShellFindingsIn(t, "shell-status-of-pipe-tail", root, p.name)
			if p.want {
				assert.Contains(t, got, p.name+":"+strconv.Itoa(line))
			} else {
				assert.Empty(t, got)
			}
		})
	}
}
