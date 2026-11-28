package shellrules

import (
	"fmt"
	"testing"
)

// errexitScopes pairs the head of a script with whether errexit is on for
// the top-level lines after it. A set inside a function body, a subshell or
// a substitution changes nothing at the top level; the -e of the shebang
// counts for every rule.
var errexitScopes = []struct {
	name string
	head string
	on   bool
}{
	{"set +e in a function", "#!/bin/bash\nset -e\ncleanup() { set +e; rm -f \"$tmp\"; }\n", true},
	{"set +e in a subshell", "#!/bin/bash\nset -e\n( set +e; true )\n", true},
	{"set -e in a subshell", "#!/bin/bash\n( set -e; true )\n", false},
	{"set -e in a substitution", "#!/bin/bash\nx=$(set -e; true)\n", false},
	{"set -e then +e", "#!/bin/bash\nset -e +e\n", false},
	{"shebang -e", "#!/bin/bash -e\n", true},
	{"env -S shebang -e", "#!/usr/bin/env -S bash -e\n", true},
	{"plain shebang", "#!/bin/bash\n", false},
}

func TestShellErrexitScopeAcrossRules(t *testing.T) {
	for i, s := range errexitScopes {
		t.Run(s.name, func(t *testing.T) {
			grepWant, loopWant := "", " # want"
			if s.on {
				grepWant, loopWant = " # want", ""
			}
			shellWanted(t, "shell-grep-filter-exits-on-empty", fmt.Sprintf("grep%d.sh", i), s.head+
				"docker run --rm img 2>&1 | grep -v INFO"+grepWant+"\n")
			shellWanted(t, "shell-loop-ignores-step-failure", fmt.Sprintf("loop%d.sh", i), s.head+`for pair in "$@"; do
  "$repo/tools/ab.sh" "$pair" > "$log" 2>&1`+loopWant+`
  grep -E total: "$log" || echo none
done
echo "queue done"
`)
		})
	}
}
