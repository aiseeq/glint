package architecture

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestDeepNestingRule(t *testing.T) {
	rule := NewDeepNestingRule()
	require.NoError(t, rule.Configure(map[string]any{
		"max_depth": 3, // Low threshold for testing
	}))

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "Shallow nesting - OK",
			code: `package main
func foo() {
	if true {
		if true {
			x := 1
			_ = x
		}
	}
}`,
			expectedCount: 0,
		},
		{
			name: "Deep nesting - should flag",
			code: `package main
func foo() {
	if true {
		if true {
			if true {
				if true {
					x := 1
					_ = x
				}
			}
		}
	}
}`,
			expectedCount: 1, // 4th level exceeds max of 3
		},
		{
			name: "Nested for loops - should flag",
			code: `package main
func foo() {
	for i := 0; i < 10; i++ {
		for j := 0; j < 10; j++ {
			for k := 0; k < 10; k++ {
				for l := 0; l < 10; l++ {
					_ = i + j + k + l
				}
			}
		}
	}
}`,
			expectedCount: 1,
		},
		{
			name: "Mixed nesting - should flag",
			code: `package main
func foo() {
	if true {
		for i := 0; i < 10; i++ {
			switch i {
			case 1:
				if true {
					x := 1
					_ = x
				}
			}
		}
	}
}`,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/file.go", "/src", []byte(tt.code), core.DefaultConfig())

			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/src/file.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}

			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

func TestDeepNestingRule_FuncLit(t *testing.T) {
	rule := NewDeepNestingRule()
	require.NoError(t, rule.Configure(map[string]any{
		"max_depth": 3,
	}))

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "Deep nesting inside assigned closure - should flag",
			code: `package main
func foo() {
	g := func() {
		if true {
			if true {
				if true {
					if true {
						x := 1
						_ = x
					}
				}
			}
		}
	}
	g()
}`,
			expectedCount: 1,
		},
		{
			name: "Deep nesting inside go closure - should flag",
			code: `package main
func foo() {
	go func() {
		for {
			if true {
				if true {
					if true {
						x := 1
						_ = x
					}
				}
			}
		}
	}()
}`,
			expectedCount: 1,
		},
		{
			name: "Deep nesting inside deferred closure - should flag",
			code: `package main
func foo() {
	defer func() {
		if true {
			if true {
				if true {
					if true {
						x := 1
						_ = x
					}
				}
			}
		}
	}()
}`,
			expectedCount: 1,
		},
		{
			name: "Shallow closure in deep context - depth resets at closure body, OK",
			code: `package main
func foo() {
	if true {
		if true {
			if true {
				g := func() {
					if true {
						x := 1
						_ = x
					}
				}
				g()
			}
		}
	}
}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/file.go", "/src", []byte(tt.code), core.DefaultConfig())

			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/src/file.go", []byte(tt.code))
			require.NoError(t, err)
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

func TestDeepNestingRuleNoAST(t *testing.T) {
	rule := NewDeepNestingRule()

	ctx := core.NewFileContext("/src/file.ts", "/src", []byte("if (true) { if (true) { } }"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}

func TestDeepNestingConfigure(t *testing.T) {
	rule := NewDeepNestingRule()

	err := rule.Configure(map[string]any{
		"max_depth": 5,
	})
	assert.NoError(t, err)
	assert.Equal(t, 5, rule.maxDepth)
}

func TestDeepNestingConfigureFloat64(t *testing.T) {
	rule := NewDeepNestingRule()

	// YAML parsers may deliver numbers as float64
	err := rule.Configure(map[string]any{
		"max_depth": float64(2),
	})
	assert.NoError(t, err)
	assert.Equal(t, 2, rule.maxDepth)
}

func TestDeepNestingConfigureReset(t *testing.T) {
	rule := NewDeepNestingRule()

	require.NoError(t, rule.Configure(map[string]any{
		"max_depth": 2,
	}))
	assert.Equal(t, 2, rule.maxDepth)

	// Re-configuring without the key must reset to the default,
	// not keep the value from a previously analyzed config
	require.NoError(t, rule.Configure(map[string]any{}))
	assert.Equal(t, defaultMaxNestingDepth, rule.maxDepth)
}

// nestingFindings runs the rule with the default maximum of 4 levels.
func nestingFindings(t *testing.T, code string) []*core.Violation {
	t.Helper()
	rule := NewDeepNestingRule()
	require.NoError(t, rule.Configure(map[string]any{}))
	return rule.AnalyzeFile(createTestContext(t, "pkg/nest/nest.go", code))
}

// A label in front of a loop does not take the loop out of the count.
func TestDeepNestingCountsLabeledLoop(t *testing.T) {
	violations := nestingFindings(t, `package nest

func Labeled(m [][][][][]int) int {
	n := 0
outer:
	for _, a := range m {
		for _, b := range a {
			for _, c := range b {
				for _, d := range c {
					for _, e := range d {
						if e < 0 {
							break outer
						}
						n += e
					}
				}
			}
		}
	}
	return n
}
`)
	require.NotEmpty(t, violations)
	assert.Contains(t, violations[0].Message, "Nesting depth 5")
}

// The body of else sits one level below its if, exactly like the body of the
// if itself.
func TestDeepNestingCountsElseBodyLikeIfBody(t *testing.T) {
	elseBranch := nestingFindings(t, `package nest

func ElseBranch(a, b, c, d, e bool) int {
	if a {
		return 0
	} else {
		if b {
			if c {
				if d {
					if e {
						return 1
					}
				}
			}
		}
	}
	return 2
}
`)
	ifBranch := nestingFindings(t, `package nest

func IfBranch(a, b, c, d, e bool) int {
	if a {
		if b {
			if c {
				if d {
					if e {
						return 1
					}
				}
			}
		}
	}
	return 2
}
`)
	require.Len(t, ifBranch, 1)
	require.Len(t, elseBranch, 1)
	assert.Contains(t, ifBranch[0].Message, "Nesting depth 5")
	assert.Contains(t, elseBranch[0].Message, "Nesting depth 5")
}

// An else-if chain stays at the level of its first if.
func TestDeepNestingKeepsElseIfChainLevel(t *testing.T) {
	violations := nestingFindings(t, `package nest

func Chain(a, b, c, d, e, f bool) int {
	if a {
		return 1
	} else if b {
		return 2
	} else if c {
		return 3
	} else if d {
		return 4
	} else if e {
		return 5
	} else if f {
		return 6
	}
	return 0
}
`)
	assert.Empty(t, violations)
}

// A closure in the header of a statement (if init, for condition, switch tag)
// is a function body of its own and is checked like any other.
func TestDeepNestingChecksClosuresInStatementHeaders(t *testing.T) {
	violations := nestingFindings(t, `package nest

func Header(m [][][][][]int) bool {
	if n := func() int {
		total := 0
		for _, a := range m {
			for _, b := range a {
				for _, c := range b {
					for _, d := range c {
						for _, e := range d {
							total += e
						}
					}
				}
			}
		}
		return total
	}(); n > 0 {
		return true
	}
	return false
}
`)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Nesting depth 5")
}
