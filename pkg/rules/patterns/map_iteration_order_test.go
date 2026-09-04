package patterns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func mapOrderProject(t *testing.T, source string) *core.GoProjectContext {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/order\n\ngo 1.24\n"), 0o644))
	path := filepath.Join(root, "order.go")
	require.NoError(t, os.WriteFile(path, []byte(source), 0o644))

	ctx, err := core.NewFileContextChecked(path, root, []byte(source), core.DefaultConfig())
	require.NoError(t, err)

	project, err := core.LoadGoProject(root, []*core.FileContext{ctx}, core.GoProjectOptions{})
	require.NoError(t, err)
	return project
}

func analyzeMapOrder(t *testing.T, source string) []*core.Violation {
	t.Helper()
	violations, err := NewMapIterationOrderRule().AnalyzeGoProject(mapOrderProject(t, source))
	require.NoError(t, err)
	return violations
}

// Repro from glint itself: the responsibility areas of a struct were collected
// by ranging over a map and then printed in the finding's message, so the same
// code produced different text on every run.
func TestMapIterationOrderReportsUnsortedCollect(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Areas(detected map[string]bool) []string {
	var areas []string
	for area := range detected {
		areas = append(areas, area)
	}
	return areas
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Contains(t, violations[0].Message, "areas")
}

// Sorting before the value leaves the function makes the order deterministic.
func TestMapIterationOrderAcceptsSortedCollect(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "sort"

func Areas(detected map[string]bool) []string {
	areas := make([]string, 0, len(detected))
	for area := range detected {
		areas = append(areas, area)
	}
	sort.Strings(areas)
	return areas
}
`)

	assert.Empty(t, violations)
}

func TestMapIterationOrderAcceptsSlicesSort(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

func Areas(detected map[string]int) []string {
	var areas []string
	for area := range detected {
		areas = append(areas, area)
	}
	slices.Sort(areas)
	return areas
}
`)

	assert.Empty(t, violations)
}

// A slice that never leaves the function cannot leak the order to a caller.
func TestMapIterationOrderIgnoresLocalOnlySlice(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Count(detected map[string]bool) int {
	var areas []string
	for area := range detected {
		areas = append(areas, area)
	}
	return len(areas)
}
`)

	assert.Empty(t, violations)
}

// Ranging over a slice keeps its order; only maps are unordered.
func TestMapIterationOrderIgnoresSliceRange(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Copy(items []string) []string {
	var out []string
	for _, item := range items {
		out = append(out, item)
	}
	return out
}
`)

	assert.Empty(t, violations)
}

// Building a message by concatenating map entries has the same problem.
func TestMapIterationOrderReportsStringAccumulation(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Describe(detected map[string]bool) string {
	message := ""
	for area := range detected {
		message += area + ", "
	}
	return message
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "message")
}

// Aggregation does not depend on the order the map is walked in.
func TestMapIterationOrderIgnoresOrderIndependentAggregation(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Total(counts map[string]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}
`)

	assert.Empty(t, violations)
}

// Collecting into a map keeps no order to leak.
func TestMapIterationOrderIgnoresMapToMap(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Invert(source map[string]string) map[string]string {
	result := make(map[string]string)
	for key, value := range source {
		result[value] = key
	}
	return result
}
`)

	assert.Empty(t, violations)
}

func TestMapIterationOrderMetadata(t *testing.T) {
	rule := NewMapIterationOrderRule()
	assert.Equal(t, "map-iteration-order", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.False(t, rule.RequiresSSA())
}

// Сортировка через собственный хелпер — та же гарантия порядка, что и sort.Strings.
// Репро из projectC: scheduler/xe_refresher.go собирает пары и зовёт sortXEPairs.
func TestMapIterationOrderAcceptsSortHelper(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "sort"

func sortPairs(pairs [][2]string) {
	sort.Slice(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
}

func Pairs(unique map[[2]string]bool) [][2]string {
	pairs := make([][2]string, 0, len(unique))
	for pair := range unique {
		pairs = append(pairs, pair)
	}
	sortPairs(pairs)
	return pairs
}
`)
	assert.Empty(t, violations, "срез отсортирован перед возвратом: %v", violations)
}

// Repro from a real project: the configuration was chosen by walking a map and
// returning the first entry whose key matched loosely, so the same binary got a
// different configuration from run to run.
func TestMapIterationOrderReportsFirstMatchReturn(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "strings"

func Config(profiles map[string]int, binary string) int {
	for name, profile := range profiles {
		if strings.Contains(binary, name) {
			return profile
		}
	}
	return 0
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[0].Message, "picks")
}

// The same choice made through an outer variable and a break.
func TestMapIterationOrderReportsFirstMatchBreak(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Pick(profiles map[string]int, limit int) int {
	chosen := 0
	for _, profile := range profiles {
		if profile < limit {
			chosen = profile
			break
		}
	}
	return chosen
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
}

// A lookup by key equality picks the one entry that can match: map keys are
// unique, so the walk order changes nothing.
func TestMapIterationOrderAcceptsKeyEqualityLookup(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Lookup(profiles map[string]int, want string) int {
	for name, profile := range profiles {
		if name == want {
			return profile
		}
	}
	return 0
}
`)

	assert.Empty(t, violations)
}

// An existence check returns the same answer whatever the order.
func TestMapIterationOrderAcceptsExistenceCheck(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func AnyOver(profiles map[string]int, limit int) bool {
	for _, profile := range profiles {
		if profile > limit {
			return true
		}
	}
	return false
}
`)

	assert.Empty(t, violations)
}

// Picking the maximum is order-independent: the comparison, not the walk,
// decides the winner.
func TestMapIterationOrderAcceptsMaximumSearch(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Best(profiles map[string]int) int {
	best := 0
	for _, profile := range profiles {
		if profile > best {
			best = profile
		}
	}
	return best
}
`)

	assert.Empty(t, violations)
}

// False positive from a real project: a duplicate is found by comparing an
// identity field of the value. Such a field is treated as unique, the way a map
// key is, so the walk order does not decide the answer.
func TestMapIterationOrderAcceptsValueIdentityLookup(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Article struct {
	URL string
}

func Find(seen map[string]*Article, want *Article) *Article {
	for _, existing := range seen {
		if existing.URL == want.URL {
			return existing
		}
	}
	return nil
}
`)

	assert.Empty(t, violations)
}

// False positive from a real project: the function has already refused every
// case but one, so the loop takes the single entry left — there is nothing to
// choose between.
func TestMapIterationOrderAcceptsSingleEntryTake(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "errors"

func Only(matches map[string]int) (int, error) {
	if len(matches) > 1 {
		return 0, errors.New("ambiguous")
	}
	for _, match := range matches {
		return match, nil
	}
	return 0, errors.New("empty")
}
`)

	assert.Empty(t, violations)
}
