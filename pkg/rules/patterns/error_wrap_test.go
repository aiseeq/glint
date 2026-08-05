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

// Delegating to the same method on an embedded type is a pass-through: the
// caller adds the context, so wrapping here would only duplicate it. Every
// rule's Configure looked like a finding because of this.
func TestErrorWrapIgnoresEmbeddedDelegation(t *testing.T) {
	code := `package svc

type Base struct{}

func (b *Base) Configure(settings map[string]any) error { return nil }

type Rule struct {
	*Base
}

func (r *Rule) Configure(settings map[string]any) error {
	if err := r.Base.Configure(settings); err != nil {
		return err
	}
	return nil
}
`
	ctx := errorWrapContext(t, code)
	if violations := NewErrorWrapRule().AnalyzeFile(ctx); len(violations) != 0 {
		t.Fatalf("expected no findings, got %d", len(violations))
	}
}

// A closure-runner call (RunInTx-style: the error comes from a call taking a
// func literal) is a transparent pass-through: context is added inside the
// closure, and wrapping outside would also break sentinel-error comparison for
// callers that unwrap with errors.Is.
func TestErrorWrapIgnoresClosureRunner(t *testing.T) {
	code := `package svc

import "fmt"

func (s *Service) Apply(ctx Context, userID string) error {
	if err := s.repo.RunInTx(ctx, func(ctx Context) error {
		if err := s.repo.Save(ctx, userID); err != nil {
			return fmt.Errorf("save: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
`
	ctx := errorWrapContext(t, code)
	if violations := NewErrorWrapRule().AnalyzeFile(ctx); len(violations) != 0 {
		t.Fatalf("expected no findings, got %d", len(violations))
	}
}

// Invoking a caller-supplied callback parameter is the same pass-through: the
// callback owns its context (RunInTx itself returns fn's error verbatim so
// domain sentinels survive).
func TestErrorWrapIgnoresCallbackParameter(t *testing.T) {
	code := `package svc

func RunInTx(ctx Context, fn func(ctx Context) error) error {
	if err := fn(ctx); err != nil {
		return err
	}
	return nil
}
`
	ctx := errorWrapContext(t, code)
	if violations := NewErrorWrapRule().AnalyzeFile(ctx); len(violations) != 0 {
		t.Fatalf("expected no findings, got %d", len(violations))
	}
}

// A different callee still loses its context and must be reported.
func TestErrorWrapStillReportsForeignCall(t *testing.T) {
	code := `package svc

import "os"

func Load(path string) error {
	if _, err := os.ReadFile(path); err != nil {
		return err
	}
	return nil
}
`
	ctx := errorWrapContext(t, code)
	if violations := NewErrorWrapRule().AnalyzeFile(ctx); len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
}

func errorWrapContext(t *testing.T, code string) *core.FileContext {
	t.Helper()
	ctx := core.NewFileContext("/src/svc.go", "/src", []byte(code), core.DefaultConfig())
	fset, astFile, err := core.NewParser().ParseGoFile("/src/svc.go", []byte(code))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx.SetGoAST(fset, astFile)
	return ctx
}
