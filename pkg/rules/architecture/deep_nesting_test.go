package architecture

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestDeepNestingRule(t *testing.T) {
	rule := NewDeepNestingRule()
	rule.Configure(map[string]any{
		"max_depth": 3, // Low threshold for testing
	})

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
