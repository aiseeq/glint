package fix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// fixerContext builds the context of a parsed Go file, the way the fix command
// hands it to fixers.
func fixerContext(t *testing.T, source string) *core.FileContext {
	t.Helper()
	return rulestest.GoFile(t, "rule.go", source)
}

// mapOrderViolation points at the range statement at line:column that the rule
// marked as sortable.
func mapOrderViolation(line, column int) *core.Violation {
	return &core.Violation{
		Rule: "map-iteration-order", File: "rule.go", Line: line, Column: column,
		Context: map[string]any{"sortable_keys": true},
	}
}

// Repro from glint itself: eight rules collected their findings by walking a map,
// and the fix was the same everywhere.
func TestMapIterationOrderFixerRewritesKeyValueRange(t *testing.T) {
	ctx := fixerContext(t, `package rules

import (
	"fmt"
)

func report(sites map[string][]int) {
	for typeName, lines := range sites {
		fmt.Println(typeName, lines)
	}
}
`)

	fixes := NewMapIterationOrderFixer().GenerateFix(ctx, mapOrderViolation(8, 2))
	require.Len(t, fixes, 1)
	assert.Equal(t, "typeName, lines := range sites {", fixes[0].OldText)
	assert.Equal(t, "_, typeName := range slices.Sorted(maps.Keys(sites)) {\nlines := sites[typeName]", fixes[0].NewText)
	assert.Equal(t, []string{"maps", "slices"}, fixes[0].Imports)
}

// A key-only range needs no lookup line.
func TestMapIterationOrderFixerRewritesKeyOnlyRange(t *testing.T) {
	ctx := fixerContext(t, `package rules

func names(sites map[string]int) []string {
	var out []string
	for name := range sites {
		out = append(out, name)
	}
	return out
}
`)

	fixes := NewMapIterationOrderFixer().GenerateFix(ctx, mapOrderViolation(5, 2))
	require.Len(t, fixes, 1)
	assert.Equal(t, "_, name := range slices.Sorted(maps.Keys(sites)) {", fixes[0].NewText)
}

// Without the key there is nothing to sort by, so the fixer stays out of it.
func TestMapIterationOrderFixerSkipsBlankKey(t *testing.T) {
	ctx := fixerContext(t, `package rules

func total(counts map[string]int) int {
	sum := 0
	for _, count := range counts {
		sum += count
	}
	return sum
}
`)

	assert.Empty(t, NewMapIterationOrderFixer().GenerateFix(ctx, mapOrderViolation(5, 2)))
}

// A parameter named maps would capture the call the fixer writes.
func TestMapIterationOrderFixerSkipsTakenPackageName(t *testing.T) {
	ctx := fixerContext(t, `package rules

func names(maps map[string]int) []string {
	var out []string
	for name := range maps {
		out = append(out, name)
	}
	return out
}
`)

	assert.Empty(t, NewMapIterationOrderFixer().GenerateFix(ctx, mapOrderViolation(5, 2)))
}

// Only a loop the rule marked as sortable is rewritten: a struct key is not
// cmp.Ordered, and the fixer cannot tell that from the syntax.
func TestMapIterationOrderFixerMetadata(t *testing.T) {
	fixer := NewMapIterationOrderFixer()
	assert.Equal(t, "map-iteration-order", fixer.RuleName())
	assert.True(t, fixer.CanFix(mapOrderViolation(1, 1)))
	assert.False(t, fixer.CanFix(&core.Violation{Rule: "map-iteration-order", Line: 1, Column: 1}))
	assert.False(t, fixer.CanFix(&core.Violation{Rule: "other"}))
	assert.False(t, fixer.CanFix(nil))
}
