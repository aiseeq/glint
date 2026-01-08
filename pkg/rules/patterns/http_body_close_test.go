package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPBodyCloseRule_Metadata(t *testing.T) {
	rule := NewHTTPBodyCloseRule()

	assert.Equal(t, "http-body-close", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestHTTPBodyCloseRule_Detection(t *testing.T) {
	rule := NewHTTPBodyCloseRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "http.Get without close",
			code: `package main

import "net/http"

func example() {
	resp, err := http.Get("http://example.com")
	if err != nil {
		return
	}
	_ = resp
}
`,
			expectMatch: true,
		},
		{
			name: "http.Get with defer close",
			code: `package main

import "net/http"

func example() {
	resp, err := http.Get("http://example.com")
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
`,
			expectMatch: false,
		},
		{
			name: "http.Get with close",
			code: `package main

import "net/http"

func example() {
	resp, err := http.Get("http://example.com")
	if err != nil {
		return
	}
	resp.Body.Close()
}
`,
			expectMatch: false,
		},
		{
			name: "client.Do without close",
			code: `package main

import "net/http"

func example(client *http.Client, req *http.Request) {
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp
}
`,
			expectMatch: true,
		},
		{
			name: "response ignored",
			code: `package main

import "net/http"

func example() {
	_, err := http.Get("http://example.com")
	if err != nil {
		return
	}
}
`,
			expectMatch: false, // Ignored with _
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createHTTPContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "http_body_leak", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

// Helper function
func createHTTPContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitHTTPLines(code),
		Content: []byte(code),
	}

	if len(path) > 3 && path[len(path)-3:] == ".go" {
		parser := core.NewParser()
		fset, ast, err := parser.ParseGoFile(path, []byte(code))
		if err != nil {
			t.Fatalf("Failed to parse Go code: %v", err)
		}
		ctx.SetGoAST(fset, ast)
	}

	return ctx
}

func splitHTTPLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
