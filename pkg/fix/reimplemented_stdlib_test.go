package fix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func stdlibViolation(line int, replacement string) *core.Violation {
	return &core.Violation{
		Rule:    "reimplemented-stdlib",
		File:    "rule.go",
		Line:    line,
		Context: map[string]any{"replacement": replacement},
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
	require.Len(t, fixes, 2)
	assert.Equal(t, `func contains(names []string, name string) bool {
	return slices.Contains(names, name)
}`, fixes[0].NewText)
	assert.Equal(t, 7, fixes[0].StartLine)
	assert.Equal(t, 14, fixes[0].EndLine)
	assert.Contains(t, fixes[1].NewText, `"slices"`)
}

// A helper searching its own list keeps its name; only the message applies.
func TestReimplementedStdlibFixerSkipsWrapperOverOwnList(t *testing.T) {
	ctx := fixerContext(t, `package rules

var supported = []string{"USDC", "USDT"}

func isSupported(currency string) bool {
	for _, candidate := range supported {
		if candidate == currency {
			return true
		}
	}
	return false
}
`)

	assert.Empty(t, NewReimplementedStdlibFixer().GenerateFix(ctx, stdlibViolation(5, "slices.Contains")))
}

// Shapes other than the linear search have no mechanical rewrite here.
func TestReimplementedStdlibFixerSkipsOtherReplacements(t *testing.T) {
	fixer := NewReimplementedStdlibFixer()
	assert.False(t, fixer.CanFix(stdlibViolation(1, "strconv.Itoa")))
	assert.False(t, fixer.CanFix(&core.Violation{Rule: "reimplemented-stdlib", Line: 1}))
	assert.True(t, fixer.CanFix(stdlibViolation(1, "slices.Contains")))
}

// A body that does anything else must be left to a human.
func TestReimplementedStdlibFixerSkipsDifferentBody(t *testing.T) {
	ctx := fixerContext(t, `package rules

import "strings"

func contains(names []string, name string) bool {
	for _, candidate := range names {
		if strings.EqualFold(candidate, name) {
			return true
		}
	}
	return false
}
`)

	assert.Empty(t, NewReimplementedStdlibFixer().GenerateFix(ctx, stdlibViolation(5, "slices.Contains")))
}

func TestReimplementedStdlibFixerMetadata(t *testing.T) {
	assert.Equal(t, "reimplemented-stdlib", NewReimplementedStdlibFixer().RuleName())
}
