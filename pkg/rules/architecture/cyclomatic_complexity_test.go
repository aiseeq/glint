package architecture

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestCyclomaticComplexityRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		maxComplexity  int
		wantViolations int
	}{
		{
			name: "simple function - complexity 1",
			code: `package main

func simple() int {
	return 42
}`,
			maxComplexity:  1,
			wantViolations: 0,
		},
		{
			name: "function with if - complexity 2",
			code: `package main

func withIf(x int) int {
	if x > 0 {
		return x
	}
	return 0
}`,
			maxComplexity:  2,
			wantViolations: 0,
		},
		{
			name: "function with nested ifs - complexity 3",
			code: `package main

func nested(x, y int) int {
	if x > 0 {
		if y > 0 {
			return x + y
		}
	}
	return 0
}`,
			maxComplexity:  2,
			wantViolations: 1,
		},
		{
			name: "function with for loop - complexity 2",
			code: `package main

func withFor(n int) int {
	sum := 0
	for i := 0; i < n; i++ {
		sum += i
	}
	return sum
}`,
			maxComplexity:  2,
			wantViolations: 0,
		},
		{
			name: "function with range - complexity 2",
			code: `package main

func withRange(items []int) int {
	sum := 0
	for _, item := range items {
		sum += item
	}
	return sum
}`,
			maxComplexity:  2,
			wantViolations: 0,
		},
		{
			name: "function with switch cases - complexity 4",
			code: `package main

func withSwitch(x int) string {
	switch x {
	case 1:
		return "one"
	case 2:
		return "two"
	case 3:
		return "three"
	default:
		return "other"
	}
}`,
			maxComplexity:  3,
			wantViolations: 1,
		},
		{
			name: "function with && and || - complexity 3",
			code: `package main

func withLogical(a, b bool) bool {
	return a && b || !a
}`,
			maxComplexity:  2,
			wantViolations: 1,
		},
		{
			name: "complex function - many decision points",
			code: `package main

func complex(x, y int, items []int) int {
	if x > 0 {
		if y > 0 {
			return x + y
		}
	}

	sum := 0
	for _, item := range items {
		if item > 0 {
			sum += item
		}
	}

	switch x {
	case 1:
		return 1
	case 2:
		return 2
	}

	if x > 0 && y > 0 {
		return x * y
	}

	return sum
}`,
			maxComplexity:  5,
			wantViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewCyclomaticComplexityRule()
			rule.maxComplexity = tt.maxComplexity

			// Create fresh parser for each test to avoid caching
			parser := core.NewParser()
			ctx := core.NewFileContext("/src/test.go", "/src", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := parser.ParseGoFile("/src/test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantViolations, "Code: %s", tt.code)
		})
	}
}

func TestCyclomaticComplexityConfigure(t *testing.T) {
	rule := NewCyclomaticComplexityRule()

	// Default should be 10
	assert.Equal(t, 10, rule.maxComplexity)

	// Configure with new value
	err := rule.Configure(map[string]any{"max_complexity": 15})
	assert.NoError(t, err)
	assert.Equal(t, 15, rule.maxComplexity)
}

func TestCyclomaticComplexityNoAST(t *testing.T) {
	rule := NewCyclomaticComplexityRule()

	ctx := core.NewFileContext("/src/file.ts", "/src", []byte("function foo() { if (true) {} }"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}
