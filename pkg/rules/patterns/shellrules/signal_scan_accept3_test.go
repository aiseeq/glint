package shellrules

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// An escaped quote inside ${…} is a plain character, not an opening quote.
func TestSignalImplicitTargetEscapedQuoteInParameterExpansion(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "escaped.sh", `#!/bin/bash
x="a'b"; echo ${x//\'/q}; kill 0 # want
x='a"b'; echo ${x//\"/q}; kill 0 # want
y=$(echo ${x//\'/q}); kill $PPID # want
`)
}

// << inside $((…)) is a shift, not a here-document.
func TestSignalImplicitTargetArithmeticShiftIsNotHeredoc(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "shift.sh", `#!/bin/bash
x=$(echo $((1<<2))
)
kill 0 # want
echo it
kill $PPID # want
msg="value $((1<<2))
rest"
kill $PPID # want
z=`+"`"+`echo $((1<<2))
`+"`"+`
kill $PPID # want
`)
}

// A here-document opened in a substitution inside an executed here-document
// has its body right below; the outer body goes on after it.
func TestSignalImplicitTargetHeredocInSubstitutionInsideExecutedHeredoc(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "nested.sh", `#!/bin/bash
bash <<'OUT'
x=$(cat <<EOF
it's
EOF
)
kill 0 # want
OUT
kill $PPID # want
`)
}

// Many here-documents inside one substitution are read in linear time.
func TestSignalImplicitTargetManyHeredocsInSubstitutionLinear(t *testing.T) {
	var b strings.Builder
	b.WriteString("x=$(\n")
	for range 6600 {
		b.WriteString("cat <<EOF\nline\nEOF\n")
	}
	b.WriteString(")\nkill 0\n")
	lines := strings.Split(b.String(), "\n")
	inputs := textInputs(lines, func(i int) int { return i + 1 })
	start := time.Now()
	got := scanSignalLines(inputs, false)
	assert.Less(t, time.Since(start), 3*time.Second)
	assert.Equal(t, []int{len(lines) - 1}, got)
}
