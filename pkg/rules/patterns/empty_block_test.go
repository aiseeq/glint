package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestEmptyBlockRule(t *testing.T) {
	rule := NewEmptyBlockRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "Empty if block",
			code: `package main
func foo() {
	if true {
	}
}`,
			expectedCount: 1,
		},
		{
			name: "Non-empty if block - OK",
			code: `package main
func foo() {
	if true {
		x := 1
		_ = x
	}
}`,
			expectedCount: 0,
		},
		{
			name: "Empty for block",
			code: `package main
func foo() {
	for i := 0; i < 10; i++ {
	}
}`,
			expectedCount: 1,
		},
		{
			name: "Empty else block",
			code: `package main
func foo() {
	if true {
		x := 1
		_ = x
	} else {
	}
}`,
			expectedCount: 1,
		},
		{
			name: "Empty range block",
			code: `package main
func foo() {
	for range []int{1,2,3} {
	}
}`,
			expectedCount: 1,
		},
		{
			name: "Empty switch block",
			code: `package main
func foo() {
	switch x := 1; x {
	}
}`,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/test/file.go", "/test", []byte(tt.code), core.DefaultConfig())

			// Parse Go AST
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/test/file.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}

			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

func TestEmptyBlockRuleNoAST(t *testing.T) {
	rule := NewEmptyBlockRule()

	ctx := core.NewFileContext("/test/file.ts", "/test", []byte("if (true) {}"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}
