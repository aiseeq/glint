package fix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func ioutilViolation(line, column int, function, replacement string) *core.Violation {
	context := map[string]any{"ioutil_function": function}
	if replacement != "" {
		context["replacement"] = replacement
	}
	return &core.Violation{Rule: "deprecated-ioutil", File: "rule.go", Line: line, Column: column, Context: context}
}

// Repro found by the map-iteration-order rule inside glint itself: a line
// using two ioutil calls got a different rewrite on every run. Each call now
// has its own finding and its own column.
func TestDeprecatedIoutilFixerRewritesEachCallOfALine(t *testing.T) {
	ctx := fixerContext(t, `package sample

import (
	"io"
	"io/ioutil"
)

func read(r io.Reader) {
	data, _ := ioutil.ReadAll(ioutil.NopCloser(r))
	_ = data
}
`)
	fixer := NewDeprecatedIoutilFixer()

	readAll := fixer.GenerateFix(ctx, ioutilViolation(9, 13, "ReadAll", "io.ReadAll"))
	require.Len(t, readAll, 1)
	assert.Equal(t, "ioutil.ReadAll", readAll[0].OldText)
	assert.Equal(t, "io.ReadAll", readAll[0].NewText)
	assert.Equal(t, 13, readAll[0].StartCol)

	nopCloser := fixer.GenerateFix(ctx, ioutilViolation(9, 28, "NopCloser", "io.NopCloser"))
	require.Len(t, nopCloser, 1)
	assert.Equal(t, "ioutil.NopCloser", nopCloser[0].OldText)
	assert.Equal(t, 28, nopCloser[0].StartCol)
}

func TestDeprecatedIoutilFixerAddsAndDropsImports(t *testing.T) {
	ctx := fixerContext(t, `package sample

import "io/ioutil"

func read(path string) {
	data, _ := ioutil.ReadFile(path)
	_ = data
}
`)
	fixes := NewDeprecatedIoutilFixer().GenerateFix(ctx, ioutilViolation(6, 13, "ReadFile", "os.ReadFile"))

	require.Len(t, fixes, 1)
	assert.Equal(t, "ioutil.ReadFile", fixes[0].OldText)
	assert.Equal(t, "os.ReadFile", fixes[0].NewText)
	assert.Equal(t, []string{"os"}, fixes[0].Imports)
	assert.Equal(t, []string{"io/ioutil"}, fixes[0].DropImports)
}

// ioutil.ReadDir returns []fs.FileInfo, os.ReadDir []fs.DirEntry: the rule names
// no replacement, and the fixer has nothing to substitute.
func TestDeprecatedIoutilFixerSkipsReadDir(t *testing.T) {
	assert.False(t, NewDeprecatedIoutilFixer().CanFix(ioutilViolation(1, 1, "ReadDir", "")))
}

// A local variable named os would capture the replacement.
func TestDeprecatedIoutilFixerSkipsTakenPackageName(t *testing.T) {
	ctx := fixerContext(t, `package sample

import "io/ioutil"

func read(os string) {
	data, _ := ioutil.ReadFile(os)
	_ = data
}
`)
	assert.Empty(t, NewDeprecatedIoutilFixer().GenerateFix(ctx, ioutilViolation(6, 13, "ReadFile", "os.ReadFile")))
}
