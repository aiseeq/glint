package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestErrorStringCompareRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "correct errors.Is usage",
			code: `package main

import "errors"

var ErrNotFound = errors.New("not found")

func check(err error) bool {
	return errors.Is(err, ErrNotFound)
}`,
			wantViolations: 0,
		},
		{
			name: "correct errors.As usage",
			code: `package main

import "errors"

type MyError struct{}
func (e *MyError) Error() string { return "my error" }

func check(err error) bool {
	var myErr *MyError
	return errors.As(err, &myErr)
}`,
			wantViolations: 0,
		},
		{
			name: "err.Error() == string comparison",
			code: `package main

func check(err error) bool {
	return err.Error() == "not found"
}`,
			wantViolations: 1,
		},
		{
			name: "err.Error() != string comparison",
			code: `package main

func check(err error) bool {
	return err.Error() != "success"
}`,
			wantViolations: 1,
		},
		{
			name: "strings.Contains with err.Error()",
			code: `package main

import "strings"

func check(err error) bool {
	return strings.Contains(err.Error(), "timeout")
}`,
			wantViolations: 1,
		},
		{
			name: "strings.HasPrefix with err.Error()",
			code: `package main

import "strings"

func check(err error) bool {
	return strings.HasPrefix(err.Error(), "error:")
}`,
			wantViolations: 1,
		},
		{
			name: "strings.HasSuffix with err.Error()",
			code: `package main

import "strings"

func check(err error) bool {
	return strings.HasSuffix(err.Error(), "failed")
}`,
			wantViolations: 1,
		},
		{
			name: "variable ending with Err",
			code: `package main

func check(connectionErr error) bool {
	return connectionErr.Error() == "connection refused"
}`,
			wantViolations: 1,
		},
		{
			name: "normal string comparison - ok",
			code: `package main

func check(s string) bool {
	return s == "hello"
}`,
			wantViolations: 0,
		},
		{
			name: "strings.Contains on normal string - ok",
			code: `package main

import "strings"

func check(s string) bool {
	return strings.Contains(s, "hello")
}`,
			wantViolations: 0,
		},
		{
			name: "err == nil is ok",
			code: `package main

func check(err error) bool {
	return err == nil
}`,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewErrorStringCompareRule()

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
