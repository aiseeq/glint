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

// Two violations in one file used to insert the same import block twice, which
// left the file uncompilable: `maps redeclared in this block`.
func TestGenerateFixesDeduplicatesImportEdits(t *testing.T) {
	ctx := fixerContext(t, `package rules

import (
	"fmt"
)

func a(m map[string]int) {
	for k, v := range m {
		fmt.Println(k, v)
	}
}

func b(m map[string]int) {
	for k, v := range m {
		fmt.Println(k, v)
	}
}
`)

	engine := NewEngine(DefaultRegistry, true)
	fixes := engine.GenerateFixes(
		[]*core.Violation{mapOrderViolation(8), mapOrderViolation(14)},
		map[string]*core.FileContext{"rule.go": ctx},
	)

	importEdits := 0
	for _, fix := range fixes {
		if strings.Contains(fix.NewText, `"maps"`) {
			importEdits++
		}
	}
	assert.Equal(t, 1, importEdits, "the import block must be added exactly once per file")
	assert.Len(t, fixes, 3, "two body rewrites and one import edit")
}

// A fix whose OldText no longer matches the file must be reported, not
// silently dropped: the user sees "Applied N fixes" and has to trust it.
func TestApplyFixesReportsFixThatDoesNotMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.go")
	require.NoError(t, os.WriteFile(path, []byte("package x\nvar a = 1\n"), 0o644))

	engine := NewEngine(NewRegistry(), false)
	results := engine.ApplyFixes([]*Fix{{
		File: path, StartLine: 2, EndLine: 2,
		OldText: "var b = 1", NewText: "var b = 2",
		RuleName: "test-rule",
	}})

	require.Len(t, results, 1)
	assert.Equal(t, 0, results[0].FixesApplied)
	require.Error(t, results[0].Error, "an unapplied fix must surface as an error")
	assert.Contains(t, results[0].Error.Error(), "test-rule")
}

// Matching only the first line of a multi-line OldText allowed replacing a
// range whose remaining lines had already been changed by an earlier fix.
func TestApplyFixesMultiLineRequiresExactMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.go")
	require.NoError(t, os.WriteFile(path, []byte("package x\nline one\nline two DIVERGED\n"), 0o644))

	engine := NewEngine(NewRegistry(), false)
	results := engine.ApplyFixes([]*Fix{{
		File: path, StartLine: 2, EndLine: 3,
		OldText: "line one\nline two", NewText: "replacement",
		RuleName: "test-rule",
	}})

	require.Len(t, results, 1)
	assert.Equal(t, 0, results[0].FixesApplied, "a partially matching range must not be replaced")
	require.Error(t, results[0].Error)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "line two DIVERGED", "the diverged line must survive")
}

// When the body rewrite needs an import that cannot be inserted (single
// unparenthesized import, no block), the fixer must produce nothing at all:
// rewriting the body alone leaves the file uncompilable (`undefined: slices`).
func TestMapIterationOrderFixerSkipsFixWhenImportImpossible(t *testing.T) {
	ctx := fixerContext(t, `package rules

import "fmt"

func names(sites map[string]int) {
	for name := range sites {
		fmt.Println(name)
	}
}
`)

	assert.Empty(t, NewMapIterationOrderFixer().GenerateFix(ctx, mapOrderViolation(6)),
		"a fix that cannot get its import must not be generated")
}

func TestReimplementedStdlibFixerSkipsFixWhenImportImpossible(t *testing.T) {
	ctx := fixerContext(t, `package rules

import "fmt"

func hasName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

var _ = fmt.Sprint
`)

	violation := &core.Violation{
		Rule: "reimplemented-stdlib", File: "rule.go", Line: 5,
		Context: map[string]any{"replacement": "slices.Contains"},
	}
	assert.Empty(t, NewReimplementedStdlibFixer().GenerateFix(ctx, violation),
		"a fix that cannot get its import must not be generated")
}
