package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
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
		{
			// select {} blocks forever on purpose: the idiom for "run until killed".
			name: "empty select is a deliberate block",
			code: `package main
func wait() {
	select {}
}`,
			expectedCount: 0,
		},
		{
			// A drain loop over a value that may be a channel: without types the
			// rule cannot tell, so it stays silent.
			name: "drain loop over a possible channel is not reported",
			code: `package main
func drain(ch chan int) {
	for range ch {
	}
	for _ = range ch {
	}
}`,
			expectedCount: 0,
		},
		{
			name: "empty range with a variable over a literal is reported",
			code: `package main
func foo() {
	for range 10 {
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

// With types the rule knows what is ranged over: draining a channel (or a
// range-over-func iterator) is a real action, an empty loop over a slice is not.
func TestEmptyBlockRuleTypedRange(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"app/app.go": `package app

type holder struct {
	events chan int
	items  []int
}

func Drain(h holder) {
	for range h.events {
	}
	for range h.items {
	}
}
`,
	})
	violations, err := NewEmptyBlockRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, 11, violations[0].Line)
}

func TestEmptyBlockRuleNoAST(t *testing.T) {
	rule := NewEmptyBlockRule()

	ctx := core.NewFileContext("/test/file.ts", "/test", []byte("if (true) {}"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}
