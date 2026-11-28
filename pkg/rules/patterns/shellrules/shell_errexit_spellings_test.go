package shellrules

import (
	"fmt"
	"testing"
)

// errexitSpellings pairs a set line with whether it turns errexit on for the
// lines after it.
var errexitSpellings = []struct {
	line string
	on   bool
}{
	{"set -e", true},
	{"set -e;", true},
	{"set -eu; cd /tmp", true},
	{"set -o errexit;", true},
	{"set -x -e", true},
	{"set -o pipefail -e", true},
	{"set -e&&cd /tmp", true},
	{"set -- -e", false},
	{`set -- "$@" -e`, false},
	{"set -u; echo -e foo", false},
	{"set -o pipefail; grep -e x f", false},
	{"set -x # -e later", false},
	{"set -u", false},
}

// Every rule that asks whether errexit is on reads the same spellings: a
// flag of set itself, not a -e after --, in a comment or in the next
// command of the line.
func TestShellErrexitSpellingsAcrossRules(t *testing.T) {
	for i, s := range errexitSpellings {
		t.Run(s.line, func(t *testing.T) {
			grepWant, loopWant := "", " # want"
			if s.on {
				grepWant, loopWant = " # want", ""
			}
			shellWanted(t, "shell-grep-filter-exits-on-empty", fmt.Sprintf("grep%d.sh", i), "#!/bin/bash\n"+s.line+`
docker run --rm img 2>&1 | grep -v INFO`+grepWant+"\n")
			shellWanted(t, "shell-loop-ignores-step-failure", fmt.Sprintf("loop%d.sh", i), "#!/bin/bash\n"+s.line+`
for pair in "$@"; do
  "$repo/tools/ab.sh" "$pair" > "$log" 2>&1`+loopWant+`
  grep -E total: "$log" || echo none
done
echo "queue done"
`)
		})
	}
}
