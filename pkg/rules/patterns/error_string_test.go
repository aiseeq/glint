package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestErrorStringRule(t *testing.T) {
	rule := NewErrorStringRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "Capitalized error - should flag",
			code: `package main
import "errors"
var err = errors.New("Something went wrong")`,
			expectedCount: 1,
		},
		{
			name: "Lowercase error - OK",
			code: `package main
import "errors"
var err = errors.New("something went wrong")`,
			expectedCount: 0,
		},
		{
			name: "Error ending with period - should flag",
			code: `package main
import "errors"
var err = errors.New("something went wrong.")`,
			expectedCount: 1,
		},
		{
			name: "Error ending with exclamation - should flag",
			code: `package main
import "errors"
var err = errors.New("something went wrong!")`,
			expectedCount: 1,
		},
		{
			name: "Acronym at start - OK",
			code: `package main
import "errors"
var err = errors.New("HTTP request failed")`,
			expectedCount: 0,
		},
		{
			name: "API acronym - OK",
			code: `package main
import "errors"
var err = errors.New("API not available")`,
			expectedCount: 0,
		},
		{
			name: "fmt.Errorf capitalized - should flag",
			code: `package main
import "fmt"
var err = fmt.Errorf("Failed to connect: %w", err)`,
			expectedCount: 1,
		},
		{
			name: "fmt.Errorf lowercase - OK",
			code: `package main
import "fmt"
var err = fmt.Errorf("failed to connect: %w", err)`,
			expectedCount: 0,
		},
		{
			name: "Error with colon - OK",
			code: `package main
import "errors"
var err = errors.New("connection failed: timeout")`,
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

func TestErrorStringRuleNoAST(t *testing.T) {
	rule := NewErrorStringRule()

	ctx := core.NewFileContext("/src/file.go", "/src", []byte(`errors.New("Error")`), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}
