package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeStdlibCopies(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return NewReimplementedStdlibRule().AnalyzeFile(rulestest.GoFile(t, "helpers.go", source))
}

// Repro from glint itself: four copies of this helper lived in the tree, and
// each returned an empty string for a negative number.
func TestReimplementedStdlibReportsHandWrittenItoa(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 3, violations[0].Line)
	assert.Contains(t, violations[0].Message, "strconv.Itoa")
}

func TestReimplementedStdlibReportsHandWrittenAtoi(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "strconv.Atoi")
}

func TestReimplementedStdlibReportsLinearSearch(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "slices.Contains")
}

func TestReimplementedStdlibReportsAbs(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "abs")
}

func TestReimplementedStdlibReportsMin(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

func smallest(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "min/max")
}

func TestReimplementedStdlibReportsReverse(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

func reverse(items []string) {
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "slices.Reverse")
}

// A search that returns the position rather than a yes/no answer is a different
// function, and slices.Contains does not replace it.
func TestReimplementedStdlibIgnoresIndexSearch(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

func indexOf(items []string, target string) int {
	for i, item := range items {
		if item == target {
			return i
		}
	}
	return -1
}
`)

	assert.Empty(t, violations)
}

// A search with a condition of its own is not a plain membership test.
func TestReimplementedStdlibIgnoresPredicateSearch(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

import "strings"

func hasPrefixed(items []string, prefix string) bool {
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}
`)

	assert.Empty(t, violations)
}

// Formatting that already goes through strconv is doing something else.
func TestReimplementedStdlibIgnoresStrconvUser(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

import "strconv"

func padded(i int) string {
	s := strconv.Itoa(i % 10)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}
`)

	assert.Empty(t, violations)
}

// Comparison by a field is domain logic, not min/max.
func TestReimplementedStdlibIgnoresFieldComparison(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

type Item struct{ Weight int }

func heavier(a Item, b Item) Item {
	if a.Weight < b.Weight {
		return b
	}
	return a
}
`)

	assert.Empty(t, violations)
}

// Repro from glint itself: a loop that unpacks the element before comparing a
// field of it asks something slices.Contains cannot answer.
func TestReimplementedStdlibIgnoresFieldMatchSearch(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

type Violation struct{ Severity string }

func hasCritical(items []Violation) bool {
	for _, v := range items {
		if v.Severity == "critical" {
			return true
		}
	}
	return false
}
`)

	assert.Empty(t, violations)
}

// A loop doing more than the comparison is not a membership test either.
func TestReimplementedStdlibIgnoresLoopWithExtraWork(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

import "go/ast"

func returnsErr(results []ast.Expr) bool {
	for _, result := range results {
		if ident, ok := result.(*ast.Ident); ok {
			if ident.Name == "err" {
				return true
			}
		}
	}
	return false
}
`)

	assert.Empty(t, violations)
}

func TestReimplementedStdlibMetadata(t *testing.T) {
	rule := NewReimplementedStdlibRule()
	assert.Equal(t, "reimplemented-stdlib", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

// Числа словами делят на 10 и 100 ровно как ручной Itoa, но цифра идёт индексом
// в таблицу слов, а не превращается в символ. Репро из propay (mutator/numwords.go).
func TestReimplementedStdlibKeepsQuietOnNumberToWords(t *testing.T) {
	violations := analyzeStdlibCopies(t, `package helpers

var smallNumbers = []string{"Zero", "One", "Two"}
var tensNames = []string{"", "Ten", "Twenty"}

func threeDigitWords(n uint64) string {
	var parts []string
	if n >= 100 {
		parts = append(parts, smallNumbers[n/100], "Hundred")
		n %= 100
	}
	switch {
	case n >= 20:
		t := tensNames[n/10]
		if n%10 != 0 {
			t += " " + smallNumbers[n%10]
		}
		parts = append(parts, t)
	case n > 0:
		parts = append(parts, smallNumbers[n])
	}
	return join(parts)
}

func join(parts []string) string {
	out := ""
	for _, p := range parts {
		out += p
	}
	return out
}
`)

	assert.Empty(t, violations, "цифра здесь индекс в таблицу слов, а не символ: %v", violations)
}
