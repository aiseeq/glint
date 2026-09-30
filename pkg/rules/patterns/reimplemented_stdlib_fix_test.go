package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// containsFixMarks runs the rule on a typed module and returns, per finding,
// the collection and target the fixer may pass to slices.Contains.
func containsFixMarks(t *testing.T, gomod, source string) [][2]any {
	t.Helper()
	files := map[string]string{"helpers/helpers.go": source}
	if gomod != "" {
		files["go.mod"] = gomod
	}
	violations := runRuleOnFiles(t, NewReimplementedStdlibRule(), files)
	marks := make([][2]any, 0, len(violations))
	for _, v := range violations {
		marks = append(marks, [2]any{v.Context["fix_collection"], v.Context["fix_target"]})
	}
	return marks
}

func linearSearch(signature, condition string) string {
	return `package helpers

import "strings"

var _ = strings.ToLower

type status string

func ` + signature + ` bool {
	for _, x := range xs {
		if ` + condition + ` {
			return true
		}
	}
	return false
}
`
}

// Only a search whose comparison slices.Contains performs exactly is marked
// for the fixer: the element against a parameter of the element's own type.
func TestReimplementedStdlibMarksExactContainsForFix(t *testing.T) {
	marks := containsFixMarks(t, "", linearSearch("has(xs []string, s string)", "x == s"))
	assert.Equal(t, [][2]any{{"xs", "s"}}, marks)

	marks = containsFixMarks(t, "", linearSearch("has(xs []string, s string)", "s == x"))
	assert.Equal(t, [][2]any{{"xs", "s"}}, marks)

	marks = containsFixMarks(t, "", linearSearch("has(xs []status, s status)", "x == s"))
	assert.Equal(t, [][2]any{{"xs", "s"}}, marks)
}

func TestReimplementedStdlibDoesNotMarkInexactSearch(t *testing.T) {
	tests := map[string][2]string{
		"converted target":          {"has(xs []string, s string)", "x == strings.ToLower(s)"},
		"element and target differ": {"has(xs []any, s string)", "x == s"},
		"array parameter":           {"has(xs [3]string, s string)", "x == s"},
		"target is not a parameter": {"has(xs []string, s string)", `x == "fixed"`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			marks := containsFixMarks(t, "", linearSearch(tt[0], tt[1]))
			require.Len(t, marks, 1, "the rule still reports the hand-written search")
			assert.Equal(t, [2]any{nil, nil}, marks[0])
		})
	}
}

// slices arrived in Go 1.21.
func TestReimplementedStdlibDoesNotMarkBeforeGo121(t *testing.T) {
	marks := containsFixMarks(t, "module example.com/rulestest\n\ngo 1.20\n",
		linearSearch("has(xs []string, s string)", "x == s"))
	assert.Equal(t, [][2]any{{nil, nil}}, marks)
}

// The column pins the helper for the fixer.
func TestReimplementedStdlibReportsColumn(t *testing.T) {
	violations := runRuleOnFiles(t, NewReimplementedStdlibRule(),
		map[string]string{"helpers/helpers.go": linearSearch("has(xs []string, s string)", "x == s")})
	require.Len(t, violations, 1)
	assert.Equal(t, 1, violations[0].Column)
}
