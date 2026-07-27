package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeQuadraticLoop(t *testing.T, source string) []*core.Violation {
	t.Helper()
	ctx := rulestest.GoFile(t, "scan.go", source)
	return NewQuadraticLoopRule().AnalyzeFile(ctx)
}

// Repro from glint itself: findDuplicateWindows compared every window with every
// other one, which made a 900-file project take minutes instead of seconds.
func TestQuadraticLoopReportsNestedScanOverSameSlice(t *testing.T) {
	violations := analyzeQuadraticLoop(t, `package scan

func FindPairs(windows []string) []string {
	var pairs []string
	for i := 0; i < len(windows); i++ {
		for j := i + 1; j < len(windows); j++ {
			if windows[i] == windows[j] {
				pairs = append(pairs, windows[i])
			}
		}
	}
	return pairs
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[0].Message, "windows")
}

// The same shape written with range.
func TestQuadraticLoopReportsNestedRangeOverSameCollection(t *testing.T) {
	violations := analyzeQuadraticLoop(t, `package scan

type Item struct {
	ID   string
	Name string
}

func Duplicates(items []Item) []Item {
	var found []Item
	for _, a := range items {
		for _, b := range items {
			if a.ID == b.ID && a.Name != b.Name {
				found = append(found, a)
			}
		}
	}
	return found
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 11, violations[0].Line)
	assert.Contains(t, violations[0].Message, "items")
}

// Two different collections give O(n*m), which is what the code is asking for.
func TestQuadraticLoopIgnoresDifferentCollections(t *testing.T) {
	violations := analyzeQuadraticLoop(t, `package scan

func Match(users []string, roles []string) int {
	count := 0
	for _, u := range users {
		for _, r := range roles {
			if u == r {
				count++
			}
		}
	}
	return count
}
`)

	assert.Empty(t, violations)
}

// The inner loop walks the element of the outer one, so it is linear overall.
func TestQuadraticLoopIgnoresNestedDataStructure(t *testing.T) {
	violations := analyzeQuadraticLoop(t, `package scan

type Group struct {
	Members []string
}

func Count(groups []Group) int {
	total := 0
	for _, g := range groups {
		for range g.Members {
			total++
		}
	}
	return total
}
`)

	assert.Empty(t, violations)
}

// Repro from glint itself: normalizeLine collapsed spaces by rescanning the
// whole string on every replacement.
func TestQuadraticLoopReportsRescanningReplace(t *testing.T) {
	violations := analyzeQuadraticLoop(t, `package scan

import "strings"

func Normalize(line string) string {
	for strings.Contains(line, "  ") {
		line = strings.ReplaceAll(line, "  ", " ")
	}
	return line
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[0].Message, "line")
}

// A loop that shrinks the string by other means is not the rescan pattern.
func TestQuadraticLoopIgnoresPlainReplace(t *testing.T) {
	violations := analyzeQuadraticLoop(t, `package scan

import "strings"

func Normalize(line string) string {
	line = strings.ReplaceAll(line, "  ", " ")
	return line
}
`)

	assert.Empty(t, violations)
}

// A nested loop whose body does nothing expensive is cheap enough to leave be.
func TestQuadraticLoopIgnoresTrivialBody(t *testing.T) {
	violations := analyzeQuadraticLoop(t, `package scan

func Count(items []int) int {
	total := 0
	for range items {
		for range items {
			total++
		}
	}
	return total
}
`)

	assert.Empty(t, violations)
}

func TestQuadraticLoopIgnoresTestFiles(t *testing.T) {
	ctx := rulestest.GoFile(t, "scan_test.go", `package scan

func check(items []string) {
	for _, a := range items {
		for _, b := range items {
			if a == b {
				panic("dup")
			}
		}
	}
}
`)

	assert.Empty(t, NewQuadraticLoopRule().AnalyzeFile(ctx))
}

// The same shape in TypeScript: for…of over the same array inside itself.
func TestQuadraticLoopReportsNestedFrontendLoop(t *testing.T) {
	ctx := rulestest.TextFile(t, "scan.ts", `export function pairs(items: Item[]) {
  const found: string[] = []
  for (const a of items) {
    for (const b of items) {
      if (a.id !== b.id && a.name === b.name) {
        found.push(a.id)
      }
    }
  }
  return found
}
`)

	violations := NewQuadraticLoopRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, 3, violations[0].Line)
	assert.Contains(t, violations[0].Message, "items")
}

// Array methods walk the collection just as a loop does.
func TestQuadraticLoopReportsNestedArrayMethods(t *testing.T) {
	ctx := rulestest.TextFile(t, "scan.ts", `export function duplicates(items: Item[]) {
  return items.filter((a) => {
    return items.some((b) => b.id !== a.id && b.name === a.name)
  })
}
`)

	violations := NewQuadraticLoopRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "items")
}

// Two different collections give O(n*m), which is what the code asks for.
func TestQuadraticLoopIgnoresFrontendCrossJoin(t *testing.T) {
	ctx := rulestest.TextFile(t, "scan.ts", `export function crossJoin(users: string[], roles: string[]) {
  return users.map((user) => roles.filter((role) => role === user))
}
`)

	assert.Empty(t, NewQuadraticLoopRule().AnalyzeFile(ctx))
}

// Rescanning a string after each replacement is quadratic in JavaScript too.
func TestQuadraticLoopReportsFrontendRescan(t *testing.T) {
	ctx := rulestest.TextFile(t, "scan.ts", `export function collapse(text: string) {
  let value = text
  while (value.includes("  ")) {
    value = value.replace("  ", " ")
  }
  return value
}
`)

	violations := NewQuadraticLoopRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, 3, violations[0].Line)
	assert.Contains(t, violations[0].Message, "value")
}

// A single replaceAll is the fixed form and must stay silent.
func TestQuadraticLoopIgnoresSingleFrontendReplace(t *testing.T) {
	ctx := rulestest.TextFile(t, "scan.ts", `export function collapse(text: string) {
  return text.replace(/\s+/g, " ")
}
`)

	assert.Empty(t, NewQuadraticLoopRule().AnalyzeFile(ctx))
}

// Repro from projectA: a chain of array methods walks the result of the previous
// step, so each pass is linear and the whole chain is not quadratic.
func TestQuadraticLoopIgnoresMethodChain(t *testing.T) {
	ctx := rulestest.TextFile(t, "chart.tsx", `export function series(chartData: Point[]) {
  const values = chartData.map((d) => d.apy).filter((v) => v > 0)
  return values
}
`)

	assert.Empty(t, NewQuadraticLoopRule().AnalyzeFile(ctx))
}

// Repro from projectA: narrowing a list step by step is a sequence of passes, not a
// scan inside a scan.
func TestQuadraticLoopIgnoresSequentialFilters(t *testing.T) {
	ctx := rulestest.TextFile(t, "registry.tsx", `export function narrow(operations: Op[], kind: string) {
  let filtered = operations
  filtered = filtered.filter((op) => op.type === 'yield')
  filtered = filtered.filter((op) => op.kind === kind)
  return filtered
}
`)

	assert.Empty(t, NewQuadraticLoopRule().AnalyzeFile(ctx))
}

func TestQuadraticLoopMetadata(t *testing.T) {
	rule := NewQuadraticLoopRule()
	assert.Equal(t, "quadratic-loop", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}
