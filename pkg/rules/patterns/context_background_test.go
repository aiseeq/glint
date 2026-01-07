package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestContextBackgroundRule(t *testing.T) {
	rule := NewContextBackgroundRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "context.Background in func with ctx param",
			code: `package main
import "context"
func foo(ctx context.Context) {
	newCtx := context.Background()
	_ = newCtx
}`,
			expectedCount: 1,
		},
		{
			name: "context.TODO in func with ctx param",
			code: `package main
import "context"
func foo(ctx context.Context) {
	newCtx := context.TODO()
	_ = newCtx
}`,
			expectedCount: 1,
		},
		{
			name: "context.Background in func without ctx - OK",
			code: `package main
import "context"
func foo() {
	ctx := context.Background()
	_ = ctx
}`,
			expectedCount: 0,
		},
		{
			name: "Using ctx param - OK",
			code: `package main
import "context"
func foo(ctx context.Context) {
	doSomething(ctx)
}
func doSomething(ctx context.Context) {}`,
			expectedCount: 0,
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

func TestContextBackgroundRuleNoAST(t *testing.T) {
	rule := NewContextBackgroundRule()

	ctx := core.NewFileContext("/src/file.go", "/src", []byte("context.Background()"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}
