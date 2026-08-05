package fix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func fixerContext(t *testing.T, source string) *core.FileContext {
	t.Helper()
	ctx, err := core.NewFileContextChecked("/project/rule.go", "/project", []byte(source), core.DefaultConfig())
	require.NoError(t, err)
	return ctx
}

func mapOrderViolation(line int) *core.Violation {
	return &core.Violation{Rule: "map-iteration-order", File: "rule.go", Line: line}
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

	fixes := NewMapIterationOrderFixer().GenerateFix(ctx, mapOrderViolation(8))
	require.Len(t, fixes, 2)
	assert.Equal(t, "\tfor _, typeName := range slices.Sorted(maps.Keys(sites)) {\n\t\tlines := sites[typeName]", fixes[0].NewText)
	assert.Contains(t, fixes[1].NewText, `"maps"`)
	assert.Contains(t, fixes[1].NewText, `"slices"`)
}

// A key-only range needs no lookup line.
func TestMapIterationOrderFixerRewritesKeyOnlyRange(t *testing.T) {
	ctx := fixerContext(t, `package rules

import (
	"maps"
	"slices"
)

func names(sites map[string]int) []string {
	var out []string
	for name := range sites {
		out = append(out, name)
	}
	return out
}
`)

	fixes := NewMapIterationOrderFixer().GenerateFix(ctx, mapOrderViolation(10))
	require.Len(t, fixes, 1, "imports are already there")
	assert.Equal(t, "\tfor _, name := range slices.Sorted(maps.Keys(sites)) {", fixes[0].NewText)
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

	assert.Empty(t, NewMapIterationOrderFixer().GenerateFix(ctx, mapOrderViolation(5)))
}

func TestMapIterationOrderFixerMetadata(t *testing.T) {
	fixer := NewMapIterationOrderFixer()
	assert.Equal(t, "map-iteration-order", fixer.RuleName())
	assert.True(t, fixer.CanFix(mapOrderViolation(1)))
	assert.False(t, fixer.CanFix(&core.Violation{Rule: "other"}))
	assert.False(t, fixer.CanFix(nil))
}
