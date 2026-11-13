package shellrules

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A command substitution inside double quotes opens its own quoting context:
// a quote inside "$(…)" or "`…`" does not end the outer string, so lines after
// it are still scanned.
func TestSignalImplicitTargetSubstitutionInsideDoubleQuotes(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "subst.sh", `#!/bin/bash
msg="$(printf "can't stop")"
echo "$msg"
kill -9 $PPID # want
echo "$(echo 'a"b')"; kill $PPID # want
out="`+"`"+`echo "x'y"`+"`"+`"
kill 0 # want
nested="$(echo "$(echo "it's")")"
kill -TERM -1 # want
echo "$(echo ')')"; kill $PPID # want
`)
}

// A # right after an operator starts a comment, so the rest of the line is
// not a command.
func TestSignalImplicitTargetCommentAfterOperator(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "comment.sh", `#!/bin/bash
true;# note; kill $PPID
true|# note | kill 0
true&# note & kill 0
(# note; kill 0
:)
true &&# note; kill 0
:
echo a#b; kill 0 # want
x=1#; kill $PPID # want
`)
}

// <<- strips leading tabs only: a delimiter indented with spaces does not end
// the body.
func TestSignalImplicitTargetStrippedHeredocSpacesDoNotClose(t *testing.T) {
	inputs := textInputs([]string{"cat <<-EOF", "kill 0", "  EOF", "kill 0", "\tEOF", "kill 0"}, func(i int) int { return i + 1 })
	assert.Equal(t, []int{6}, scanSignalLines(inputs, false))
}

// The first delimiter of an outer level ends the levels opened inside its
// body; the outer level goes on with its next delimiter. bash reads its script
// from fd 0, the body of A: the body of B on fd 3 is data, and only the line
// after B runs.
func TestSignalImplicitTargetOuterDelimiterOfSeveralEndsNested(t *testing.T) {
	inputs := textInputs([]string{"bash <<'A' 3<<'B'", "cat > note <<'IN'", "A", "kill 0", "B", "kill 0"}, func(i int) int { return i + 1 })
	assert.Equal(t, []int{6}, scanSignalLines(inputs, false))
}

// A line ending on a single & is a whole command: the next line is another one.
func TestSignalImplicitTargetBackgroundLineDoesNotContinue(t *testing.T) {
	inputs := textInputs([]string{"kill 0 &", "kill $PPID"}, func(i int) int { return i + 1 })
	assert.Equal(t, []int{1, 2}, scanSignalLines(inputs, false))
}

// A quote left open in an executed here-document body ends with the body.
func TestSignalImplicitTargetOpenQuoteEndsWithHeredoc(t *testing.T) {
	inputs := textInputs([]string{"bash <<'EOF'", "echo \"open", "EOF", "kill 0", "kill $PPID"}, func(i int) int { return i + 1 })
	assert.Equal(t, []int{4, 5}, scanSignalLines(inputs, false))
}

// Skipf on testing.TB is test prose, like on *testing.T.
func TestSignalImplicitTargetSkipfOnTestingTB(t *testing.T) {
	source := `package sample
import "testing"
func skip(tb testing.TB) {
  tb.Skipf("a; kill 0")
}
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "tb.go", source, parser.AllErrors)
	require.NoError(t, err)
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	_, err = (&types.Config{Importer: signalTestImporter{base: importer.Default()}}).Check("example.com/sample", fset, []*ast.File{parsed}, info)
	require.NoError(t, err)
	file := core.NewFileContext("tb.go", ".", []byte(source), nil)
	file.GoAST, file.GoFileSet, file.GoTypesInfo = parsed, fset, info
	assert.Empty(t, rulestest.ViolationLines(newSignalImplicitTargetRule().goFile(file, info)))
}
