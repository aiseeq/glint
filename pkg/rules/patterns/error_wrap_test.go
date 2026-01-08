package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestErrorWrapRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "properly wrapped error",
			code: `package main

import "fmt"

func doSomething() error {
	err := operation()
	if err != nil {
		return fmt.Errorf("doSomething failed: %w", err)
	}
	return nil
}

func operation() error { return nil }`,
			wantViolations: 0,
		},
		{
			name: "bare error return",
			code: `package main

func doSomething() error {
	err := operation()
	if err != nil {
		return err
	}
	return nil
}

func operation() error { return nil }`,
			wantViolations: 1,
		},
		{
			name: "multiple bare returns",
			code: `package main

func doSomething() error {
	err := step1()
	if err != nil {
		return err
	}

	err = step2()
	if err != nil {
		return err
	}

	return nil
}

func step1() error { return nil }
func step2() error { return nil }`,
			wantViolations: 2,
		},
		{
			name: "function with multiple returns including error",
			code: `package main

func getData() (string, error) {
	err := validate()
	if err != nil {
		return "", err
	}
	return "data", nil
}

func validate() error { return nil }`,
			wantViolations: 1,
		},
		{
			name: "function without error return - ok",
			code: `package main

func doSomething() string {
	return "hello"
}`,
			wantViolations: 0,
		},
		{
			name: "returning new error - ok",
			code: `package main

import "errors"

func doSomething() error {
	if condition {
		return errors.New("something failed")
	}
	return nil
}

var condition bool`,
			wantViolations: 0,
		},
		{
			name: "returning nil error - ok",
			code: `package main

func doSomething() error {
	return nil
}`,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewErrorWrapRule()

			parser := core.NewParser()
			ctx := core.NewFileContext("/src/test.go", "/src", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := parser.ParseGoFile("/src/test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)
		})
	}
}
