package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestGoModernRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "sort.Slice - suggest slices.SortFunc",
			code: `package main

import "sort"

func main() {
	items := []int{3, 1, 2}
	sort.Slice(items, func(i, j int) bool {
		return items[i] < items[j]
	})
}`,
			wantViolations: 1,
		},
		{
			name: "sort.SliceStable - suggest slices.SortStableFunc",
			code: `package main

import "sort"

func main() {
	items := []int{3, 1, 2}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i] < items[j]
	})
}`,
			wantViolations: 1,
		},
		{
			name: "sort.Search - suggest slices.BinarySearch",
			code: `package main

import "sort"

func main() {
	items := []int{1, 2, 3}
	idx := sort.Search(len(items), func(i int) bool {
		return items[i] >= 2
	})
	_ = idx
}`,
			wantViolations: 1,
		},
		{
			name: "math.Max - suggest built-in max",
			code: `package main

import "math"

func main() {
	a, b := 1.0, 2.0
	m := math.Max(a, b)
	_ = m
}`,
			wantViolations: 1,
		},
		{
			name: "math.Min - suggest built-in min",
			code: `package main

import "math"

func main() {
	a, b := 1.0, 2.0
	m := math.Min(a, b)
	_ = m
}`,
			wantViolations: 1,
		},
		{
			name: "slices.Sort - already modern, no violation",
			code: `package main

import "slices"

func main() {
	items := []int{3, 1, 2}
	slices.Sort(items)
}`,
			wantViolations: 0,
		},
		{
			name: "built-in max - no violation",
			code: `package main

func main() {
	a, b := 1, 2
	m := max(a, b)
	_ = m
}`,
			wantViolations: 0,
		},
		{
			name: "multiple old patterns",
			code: `package main

import (
	"math"
	"sort"
)

func main() {
	items := []int{3, 1, 2}
	sort.Slice(items, func(i, j int) bool {
		return items[i] < items[j]
	})

	a, b := 1.0, 2.0
	m := math.Max(a, b)
	_ = m
}`,
			wantViolations: 2,
		},
		{
			name: "callback iteration - Walk with func literal",
			code: `package main

type Tree struct{}

func (t *Tree) Walk(fn func(int) bool) {}

func main() {
	t := &Tree{}
	t.Walk(func(v int) bool {
		return true
	})
}`,
			wantViolations: 1,
		},
		{
			name: "callback iteration - ForEach with func literal",
			code: `package main

type List struct{}

func (l *List) ForEach(fn func(string)) {}

func main() {
	l := &List{}
	l.ForEach(func(s string) {
		println(s)
	})
}`,
			wantViolations: 1,
		},
		{
			name: "callback iteration - no func literal",
			code: `package main

type Tree struct{}

func (t *Tree) Walk(fn func(int) bool) {}
func myCallback(v int) bool { return true }

func main() {
	t := &Tree{}
	t.Walk(myCallback)
}`,
			wantViolations: 0, // Not using func literal, might be intentional
		},
		{
			name: "regular method call - not iteration",
			code: `package main

type Service struct{}

func (s *Service) Process(data string) {}

func main() {
	s := &Service{}
	s.Process("data")
}`,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewGoModernRule()

			parser := core.NewParser()
			ctx := core.NewFileContext("/src/main.go", "/src", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := parser.ParseGoFile("/src/main.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)
		})
	}
}

func TestGoModernRuleMetadata(t *testing.T) {
	rule := NewGoModernRule()

	assert.Equal(t, "go-modern", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityLow, rule.DefaultSeverity())
}
