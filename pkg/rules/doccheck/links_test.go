package doccheck

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestDocLinksRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "valid URL - ok",
			code: `package main

// GetUser fetches a user.
// See https://docs.example.org/api/users for API docs.
func GetUser() {}`,
			wantViolations: 0, // example.org is fine, example.com is suspicious
		},
		{
			name: "placeholder URL with example.com",
			code: `package main

// GetUser fetches a user.
// See https://example.com/api/users for API docs.
func GetUser() {}`,
			wantViolations: 1,
		},
		{
			name: "localhost URL - ok for local dev docs",
			code: `package main

// Server runs on http://localhost:8080
func Server() {}`,
			wantViolations: 0, // localhost valid for local development docs
		},
		{
			name: "placeholder with TODO",
			code: `package main

// See https://TODO-add-docs.com for documentation.
func GetUser() {}`,
			wantViolations: 1,
		},
		{
			name: "template variable in URL",
			code: `package main

// Configure at https://your-domain.com/settings
func Configure() {}`,
			wantViolations: 1,
		},
		{
			name: "GitHub URL - ok",
			code: `package main

// See https://github.com/user/repo for source.
func GetCode() {}`,
			wantViolations: 0,
		},
		{
			name: "godoc URL - ok",
			code: `package main

// See https://pkg.go.dev/encoding/json for documentation.
func Parse() {}`,
			wantViolations: 0,
		},
		{
			name: "one issue - example.com only",
			code: `package main

// Connect to http://localhost:3000
// See https://example.com/docs for more.
func Connect() {}`,
			wantViolations: 1, // localhost ok, example.com flagged
		},
		{
			name: "no URLs - ok",
			code: `package main

// GetUser returns a user by ID.
// It validates the ID before lookup.
func GetUser(id string) {}`,
			wantViolations: 0,
		},
		{
			name: "IP address URL - ok for local dev docs",
			code: `package main

// Access at http://127.0.0.1:8080/api
func Access() {}`,
			wantViolations: 0, // 127.0.0.1 valid for local development docs
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDocLinksRule()

			parser := core.NewParser()
			ctx := core.NewFileContext("/src/main.go", "/src", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := parser.ParseGoFile("/src/main.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)
		})
	}
}

func TestDocLinksRuleMetadata(t *testing.T) {
	rule := NewDocLinksRule()

	assert.Equal(t, "doc-links", rule.Name())
	assert.Equal(t, "documentation", rule.Category())
	assert.Equal(t, core.SeverityLow, rule.DefaultSeverity())
}

func TestDocLinksSkipsTestFiles(t *testing.T) {
	rule := NewDocLinksRule()

	code := `package main

// See http://localhost:8080 for testing.
func Test() {}`

	parser := core.NewParser()
	ctx := core.NewFileContext("/src/main_test.go", "/src", []byte(code), core.DefaultConfig())
	fset, astFile, err := parser.ParseGoFile("/src/main_test.go", []byte(code))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	ctx.SetGoAST(fset, astFile)

	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Should skip test files")
}
