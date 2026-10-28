package duplication

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func nearDuplicateFuncFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewNearDuplicateFuncRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var found []string
	for _, v := range violations {
		found = append(found, v.File+":"+strconv.Itoa(v.Line)+" "+v.Message)
	}
	return found
}

func TestNearDuplicateFunc(t *testing.T) {
	t.Run("one call argument", func(t *testing.T) {
		files := map[string]string{"sample/sample.go": `package sample
func first(x int) int {
	if x < 0 { return 0 }
	y := x + 1
	z := relay(y, "alpha")
	return finish(z)
}
func second(x int) int {
	if x < 0 { return 0 }
	y := x + 1
	z := relay(y, "admin")
	return finish(z)
}
func relay(int, string) int { return 0 }
func finish(int) int { return 0 }
`}
		found := nearDuplicateFuncFindings(t, files)
		require.Len(t, found, 1)
		require.Contains(t, found[0], "sample/sample.go:2")
		require.Contains(t, found[0], "first")
		require.Contains(t, found[0], "alpha")
		require.Contains(t, found[0], "admin")
	})

	t.Run("computed call argument with different source signatures", func(t *testing.T) {
		files := map[string]string{"sample/sample.go": `package sample
import "fmt"
func first(x int) string {
	if x < 0 { return "" }
	a := x + 1
	b := a * 2
	c := b + 3
	return send("alpha", summary(c))
}
func second(x int, message string) string {
	if x < 0 { return "" }
	a := x + 1
	b := a * 2
	c := b + 3
	return send("alpha", fmt.Sprintf("%d: %s", c, message))
}
func send(string, string) string { return "" }
func summary(int) string { return "" }
`}
		require.Len(t, nearDuplicateFuncFindings(t, files), 1)
	})

	t.Run("method string literal", func(t *testing.T) {
		files := map[string]string{"sample/sample.go": `package sample
type Counter struct { value int }
func (c Counter) first(x int) int {
	if x < 0 { return 0 }
	y := x + c.value
	z := y * 2
	return use(z, "left")
}
func (c Counter) second(x int) int {
	if x < 0 { return 0 }
	y := x + c.value
	z := y * 2
	return use(z, "right")
}
func use(int, string) int { return 0 }
`}
		require.Len(t, nearDuplicateFuncFindings(t, files), 1)
	})

	t.Run("methods on different receiver types", func(t *testing.T) {
		files := map[string]string{"sample/sample.go": `package sample
type Left struct { value int }
type Right struct { value int }
func (x Left) first() int { if x.value < 0 { return 0 }; a := x.value + 1; b := a * 2; if b > 10 { return b }; return 0 }
func (x Right) second() int { if x.value < 0 { return 0 }; a := x.value + 1; b := a * 2; if b > 10 { return b }; return 1 }
`}
		require.Empty(t, nearDuplicateFuncFindings(t, files))
	})

	t.Run("three-way group reports each copy against first", func(t *testing.T) {
		files := map[string]string{"sample/sample.go": `package sample
func first(x int) string {
	if x < 0 { return "invalid" }
	y := x + 1
	z := y * 2
	if z > 10 { return "large" }
	return "first"
}
func second(x int) string {
	if x < 0 { return "invalid" }
	y := x + 1
	z := y * 2
	if z > 10 { return "large" }
	return "second"
}
func third(x int) string {
	if x < 0 { return "invalid" }
	y := x + 1
	z := y * 2
	if z > 10 { return "large" }
	return "third"
}
`}
		found := nearDuplicateFuncFindings(t, files)
		require.Len(t, found, 2)
		require.Contains(t, found[0], "second is a near-duplicate of sample/sample.go:2 (first)")
		require.Contains(t, found[1], "third is a near-duplicate of sample/sample.go:2 (first)")
	})

	t.Run("return string literal", func(t *testing.T) {
		files := map[string]string{"sample/sample.go": `package sample
func first(x int) string {
	if x < 0 { return "invalid" }
	y := x + 1
	z := y * 2
	if z > 10 { return "large" }
	return "left"
}
func second(x int) string {
	if x < 0 { return "invalid" }
	y := x + 1
	z := y * 2
	if z > 10 { return "large" }
	return "right"
}
`}
		require.Len(t, nearDuplicateFuncFindings(t, files), 1)
	})

	for _, tc := range []struct {
		name, source string
	}{
		{"three differences", `package sample
func first(x int) int { if x < 0 { return 0 }; y := x + 1; z := use(y, "a"); return done(z) }
func second(x int) int { if x < 1 { return 0 }; y := x + 2; z := use(y, "b"); return done(z) }
func use(int, string) int { return 0 }; func done(int) int { return 0 }
`},
		{"small bodies", `package sample
func first(x int) int { y := x + 1; return y }
func second(x int) int { y := x + 2; return y }
`},
		{"different structure", `package sample
func first(x int) int { if x < 0 { return 0 }; y := x + 1; z := x + 2; return y + z }
func second(x int) int { for x > 0 { x-- }; y := x + 1; z := x + 2; return y + z }
`},
		{"extra statement", `package sample
func first(x int) int { if x < 0 { return 0 }; y := x + 1; z := y + 2; return z }
func second(x int) int { if x < 0 { return 0 }; _ = x; y := x + 1; z := y + 2; return z }
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Empty(t, nearDuplicateFuncFindings(t, map[string]string{"sample.go": tc.source}))
		})
	}

	t.Run("different signatures", func(t *testing.T) {
		source := `package sample
type Number struct { value int }
type Label struct { value int }
func first(x Number) int { if x.value < 0 { return 0 }; a := x.value + 1; b := a * 2; if b > 10 { return useInt(a) }; return 0 }
func second(x Label) int { if x.value < 0 { return 0 }; a := x.value + 1; b := a * 2; if b > 10 { return useLabel(a) }; return 0 }
func useInt(int) int { return 0 }; func useLabel(int) int { return 0 }
`
		require.Empty(t, nearDuplicateFuncFindings(t, map[string]string{"sample/sample.go": source}))
	})

	t.Run("different call target", func(t *testing.T) {
		source := `package sample
func first(x int) int { if x < 0 { return 0 }; y := x + 1; z := x + 2; if z > 8 { return left(y) }; return 0 }
func second(x int) int { if x < 0 { return 0 }; y := x + 1; z := x + 2; if z > 8 { return right(y) }; return 0 }
func left(int) int { return 0 }; func right(int) int { return 0 }
`
		require.Empty(t, nearDuplicateFuncFindings(t, map[string]string{"sample/sample.go": source}))
	})

	t.Run("different called function signatures", func(t *testing.T) {
		source := `package sample
	func first(x any) string { if x == nil { return "" }; a := x.(int); b := a + 1; c := b * 2; return sink(formatInt(c)) }
	func second(x any) string { if x == nil { return "" }; a := x.(int); b := a + 1; c := b * 2; return sink(formatOther(c)) }
	func formatInt(int) string { return "" }; func formatOther(any) string { return "" }; func sink(string) string { return "" }
	`
		require.Empty(t, nearDuplicateFuncFindings(t, map[string]string{"sample/sample.go": source}))
	})

	t.Run("different packages", func(t *testing.T) {
		files := map[string]string{
			"one/one.go": `package one
func first(x int) int { if x < 0 { return 0 }; y := x + 1; z := y + 2; return z }
`,
			"two/two.go": `package two
func second(x int) int { if x < 0 { return 0 }; y := x + 2; z := y + 2; return z }
`,
		}
		require.Empty(t, nearDuplicateFuncFindings(t, files))
	})

	for _, path := range []string{"sample_test.go", "sample_generated.go"} {
		t.Run(path, func(t *testing.T) {
			first := `package sample
func first(x int) int { if x < 0 { return 0 }; y := x + 1; z := y + 2; return z }
func second(x int) int { if x < 0 { return 0 }; y := x + 2; z := y + 2; return z }
`
			if strings.HasSuffix(path, "generated.go") {
				first = "// Code generated by tool; DO NOT EDIT.\n" + first
			}
			require.Empty(t, nearDuplicateFuncFindings(t, map[string]string{"sample/" + path: first}))
		})
	}
}

// A package constant that differs between the two functions is a difference
// of its own, whether it is named directly or through its package.
func TestNearDuplicateFuncCountsPackageNames(t *testing.T) {
	files := map[string]string{
		"clause/clause.go": `package clause
const OnlyInternal = " AND u.internal"
const NoInternal = " AND NOT u.internal"
`,
		"sample/sample.go": sampleWithoutStaff + `func staff() (int, error) {
	query := other + clause.NoInternal
	count, err := run(query)
	if err != nil { return 0, errors.New("failed to get external count") }
	return count, nil
}
`}
	strictRule := NewNearDuplicateFuncRule()
	require.NoError(t, strictRule.Configure(map[string]any{"max_differences": 1}))
	strict, err := strictRule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var found []string
	for _, v := range strict {
		found = append(found, v.Message)
	}
	require.Len(t, found, 1, "only staff differs from external in one expression")
	require.Contains(t, found[0], "staff is a near-duplicate")
	require.Contains(t, found[0], `"base" vs "other"`)

	files["sample/sample.go"] = sampleWithoutStaff
	violations, err := NewNearDuplicateFuncRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	require.Len(t, violations, 1)
	require.Contains(t, violations[0].Message, `"clause.NoInternal" vs "clause.OnlyInternal"`)
	require.Contains(t, violations[0].Message, `"\"failed to get external count\"" vs "\"failed to get internal count\""`)
}

const sampleWithoutStaff = `package sample
import (
	"errors"
	"example.com/rulestest/clause"
)
const base = "SELECT COUNT(*) FROM users u"
const other = "SELECT COUNT(*) FROM staff u"
func run(string) (int, error) { return 0, nil }
func external() (int, error) {
	query := base + clause.NoInternal
	count, err := run(query)
	if err != nil { return 0, errors.New("failed to get external count") }
	return count, nil
}
func internal() (int, error) {
	query := base + clause.OnlyInternal
	count, err := run(query)
	if err != nil { return 0, errors.New("failed to get internal count") }
	return count, nil
}
`
