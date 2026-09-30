package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

// Two violations of one loop generate the same edit; it must be applied once.
func TestGenerateFixesDeduplicatesIdenticalEdits(t *testing.T) {
	ctx := fixerContext(t, `package rules

func names(m map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
`)

	engine := NewEngine(DefaultRegistry, true)
	fixes := engine.GenerateFixes(
		[]*core.Violation{mapOrderViolation(5, 2), mapOrderViolation(5, 2)},
		map[string]*core.FileContext{"rule.go": ctx},
	)
	assert.Len(t, fixes, 1)
}

// A fix whose OldText no longer matches the file must be reported, and then
// nothing is applied: the file changed since it was analyzed, so the other
// positions are suspect too.
func TestApplyFixesReportsFixThatDoesNotMatch(t *testing.T) {
	path := writeFixture(t, "f.go", "package x\n\nvar a = 1\n\nvar c = 3\n")

	engine := NewEngine(NewRegistry(), false)
	results := engine.ApplyFixes([]*Fix{
		{File: path, StartLine: 3, EndLine: 3, OldText: "var b = 1", NewText: "var b = 2", RuleName: "test-rule"},
		{File: path, StartLine: 5, EndLine: 5, OldText: "var c = 3", NewText: "var c = 4", RuleName: "other-rule"},
	})

	require.Len(t, results, 1)
	assert.Equal(t, 0, results[0].FixesApplied)
	require.Error(t, results[0].Error, "an unapplied fix must surface as an error")
	assert.Contains(t, results[0].Error.Error(), "test-rule")
	assert.Contains(t, readFixture(t, path), "var c = 3", "nothing is written when a fix is stale")
}

// Matching only the first line of a multi-line OldText allowed replacing a
// range whose remaining lines had already been changed by an earlier fix.
func TestApplyFixesMultiLineRequiresExactMatch(t *testing.T) {
	path := writeFixture(t, "notes.txt", "package x\nline one\nline two DIVERGED\n")

	engine := NewEngine(NewRegistry(), false)
	results := engine.ApplyFixes([]*Fix{{
		File: path, StartLine: 2, EndLine: 3,
		OldText: "line one\nline two", NewText: "replacement",
		RuleName: "test-rule",
	}})

	require.Len(t, results, 1)
	assert.Equal(t, 0, results[0].FixesApplied, "a partially matching range must not be replaced")
	require.Error(t, results[0].Error)
	assert.Contains(t, readFixture(t, path), "line two DIVERGED", "the diverged line must survive")
}

// Several fixes on one line apply by column, all in the same run.
func TestApplyFixesAppliesEveryFixOfALine(t *testing.T) {
	path := writeFixture(t, "f.go", "package x\n\nvar a, b = f(true == x), g(y == false)\n")

	engine := NewEngine(NewRegistry(), false)
	results := engine.ApplyFixes([]*Fix{
		{File: path, StartLine: 3, EndLine: 3, StartCol: 14, EndCol: 23, OldText: "true == x", NewText: "x"},
		{File: path, StartLine: 3, EndLine: 3, StartCol: 28, EndCol: 38, OldText: "y == false", NewText: "!y"},
	})

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.Equal(t, 2, results[0].FixesApplied)
	assert.Equal(t, "package x\n\nvar a, b = f(x), g(!y)\n", readFixture(t, path))
}

// Overlapping fixes are not applied halfway: the first in file order is
// applied, the one overlapping it is deferred to the next run, and the count
// says what really happened.
func TestApplyFixesDefersOverlappingFix(t *testing.T) {
	path := writeFixture(t, "f.go", "package x\n\nvar a = (x == true) == false\n")

	outer := &Fix{File: path, StartLine: 3, EndLine: 3, StartCol: 9, EndCol: 29, OldText: "(x == true) == false", NewText: "!(x == true)"}
	inner := &Fix{File: path, StartLine: 3, EndLine: 3, StartCol: 10, EndCol: 19, OldText: "x == true", NewText: "x"}
	results := NewEngine(NewRegistry(), false).ApplyFixes([]*Fix{inner, outer})

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.Equal(t, 1, results[0].FixesApplied)
	assert.Equal(t, []*Fix{inner}, results[0].Deferred)
	assert.Equal(t, "package x\n\nvar a = !(x == true)\n", readFixture(t, path))
}

// A fix that would leave a Go file that does not parse is not written.
func TestApplyFixesKeepsFileThatWouldNotParse(t *testing.T) {
	original := "package x\n\nvar a = 1\n"
	path := writeFixture(t, "f.go", original)

	results := NewEngine(NewRegistry(), false).ApplyFixes([]*Fix{
		{File: path, StartLine: 3, EndLine: 3, StartCol: 9, EndCol: 10, OldText: "1", NewText: "(1"},
	})

	require.Len(t, results, 1)
	require.Error(t, results[0].Error)
	assert.Zero(t, results[0].FixesApplied)
	assert.Equal(t, original, readFixture(t, path))
}

// The imports of all fixes of a file are added once, whichever fix asked.
func TestApplyFixesAddsEachImportOnce(t *testing.T) {
	path := writeFixture(t, "f.go", "package x\n\nvar a = A\n\nvar b = B\n")

	results := NewEngine(NewRegistry(), false).ApplyFixes([]*Fix{
		{File: path, StartLine: 3, EndLine: 3, StartCol: 9, EndCol: 10, OldText: "A", NewText: "slices.Max([]int{1})", Imports: []string{"slices"}},
		{File: path, StartLine: 5, EndLine: 5, StartCol: 9, EndCol: 10, OldText: "B", NewText: "slices.Min([]int{1})", Imports: []string{"slices"}},
	})

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	fixed := readFixture(t, path)
	assert.Equal(t, 1, strings.Count(fixed, `"slices"`), fixed)
}

// An import the fixes made unused is dropped; one still in use stays.
func TestApplyFixesDropsImportOnlyWhenUnused(t *testing.T) {
	source := "package x\n\nimport \"io/ioutil\"\n\nvar a, _ = ioutil.ReadFile(\"a\")\n\nvar b, _ = ioutil.ReadDir(\"b\")\n"
	path := writeFixture(t, "f.go", source)

	results := NewEngine(NewRegistry(), false).ApplyFixes([]*Fix{
		{File: path, StartLine: 5, EndLine: 5, StartCol: 12, EndCol: 27, OldText: "ioutil.ReadFile", NewText: "os.ReadFile",
			Imports: []string{"os"}, DropImports: []string{"io/ioutil"}},
	})

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	fixed := readFixture(t, path)
	assert.Contains(t, fixed, `"io/ioutil"`, "ReadDir still uses it")
	assert.Contains(t, fixed, `"os"`)
}

// Dry run reports what would be applied and leaves the file alone.
func TestApplyFixesDryRunWritesNothing(t *testing.T) {
	original := "package x\n\nvar a = x == true\n"
	path := writeFixture(t, "f.go", original)

	results := NewEngine(NewRegistry(), true).ApplyFixes([]*Fix{
		{File: path, StartLine: 3, EndLine: 3, StartCol: 9, EndCol: 18, OldText: "x == true", NewText: "x"},
	})

	require.Len(t, results, 1)
	assert.Equal(t, 1, results[0].FixesApplied)
	assert.Equal(t, original, readFixture(t, path))
}
