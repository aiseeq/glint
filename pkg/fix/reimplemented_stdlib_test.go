package fix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// stdlibViolation is a finding at the start of the declaration on line, as
// the rule marks an exact slices.Contains.
func stdlibViolation(line int, replacement string) *core.Violation {
	return &core.Violation{
		Rule:    "reimplemented-stdlib",
		File:    "rule.go",
		Line:    line,
		Column:  1,
		Context: map[string]any{"replacement": replacement, "fix_collection": "names", "fix_target": "name"},
	}
}

// Repro from glint itself: four helpers of this exact shape lived in the tree.
func TestReimplementedStdlibFixerRewritesSearchHelper(t *testing.T) {
	ctx := fixerContext(t, `package rules

import (
	"fmt"
)

func contains(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}

func use() { fmt.Println(contains(nil, "")) }
`)

	fixes := NewReimplementedStdlibFixer().GenerateFix(ctx, stdlibViolation(7, "slices.Contains"))
	require.Len(t, fixes, 1)
	assert.Equal(t, "return slices.Contains(names, name)", fixes[0].NewText)
	assert.Equal(t, 8, fixes[0].StartLine)
	assert.Equal(t, 13, fixes[0].EndLine)
	assert.Equal(t, []string{"slices"}, fixes[0].Imports)
}

// Shapes other than the exact linear search have no mechanical rewrite: the
// rule leaves the operands out, and the fixer does not guess them.
func TestReimplementedStdlibFixerSkipsOtherReplacements(t *testing.T) {
	fixer := NewReimplementedStdlibFixer()
	assert.False(t, fixer.CanFix(stdlibViolation(1, "strconv.Itoa")))
	assert.False(t, fixer.CanFix(&core.Violation{Rule: "reimplemented-stdlib", Line: 1, Column: 1,
		Context: map[string]any{"replacement": "slices.Contains"}}))
	assert.True(t, fixer.CanFix(stdlibViolation(1, "slices.Contains")))
}

// A comment in the body would be lost with the body.
func TestReimplementedStdlibFixerKeepsCommentedBody(t *testing.T) {
	ctx := fixerContext(t, `package rules

func contains(names []string, name string) bool {
	for _, candidate := range names {
		// exact match only
		if candidate == name {
			return true
		}
	}
	return false
}
`)

	assert.Empty(t, NewReimplementedStdlibFixer().GenerateFix(ctx, stdlibViolation(3, "slices.Contains")))
}

func TestReimplementedStdlibFixerMetadata(t *testing.T) {
	assert.Equal(t, "reimplemented-stdlib", NewReimplementedStdlibFixer().RuleName())
}
