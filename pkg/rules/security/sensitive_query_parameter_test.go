package security

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func TestSensitiveQueryParameterRuleIsRegistered(t *testing.T) {
	_, ok := rules.Get("sensitive-query-param")
	assert.True(t, ok, "sensitive-query-param must run through the CLI registry")
}

func TestSensitiveQueryParameterRule(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		code           string
		wantViolations int
	}{
		{
			name:           "Go reads token from query",
			path:           "/src/auth.go",
			code:           `package auth; func token(r *http.Request) string { return r.URL.Query().Get("token") }`,
			wantViolations: 1,
		},
		{
			name:           "TypeScript reads token from search params",
			path:           "/src/callback.ts",
			code:           `const token = searchParams.get('access_token')`,
			wantViolations: 1,
		},
		{
			name:           "sensitive URL literal",
			path:           "/src/email.go",
			code:           `package email; const actionURL = "/verify?token=" + token`,
			wantViolations: 1,
		},
		{
			name:           "fragment token is not sent to server",
			path:           "/src/email.go",
			code:           `package email; const actionURL = "/verify#token=" + token`,
			wantViolations: 0,
		},
		{
			name:           "ordinary query parameter",
			path:           "/src/list.ts",
			code:           `const page = searchParams.get('page')`,
			wantViolations: 0,
		},
		{
			name:           "JSON body token",
			path:           "/src/client.ts",
			code:           `await fetch('/verify', { method: 'POST', body: JSON.stringify({ token }) })`,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSensitiveQueryParameterRule()
			ctx := core.NewFileContext(tt.path, "/src", []byte(tt.code), core.DefaultConfig())
			assert.Len(t, rule.AnalyzeFile(ctx), tt.wantViolations)
		})
	}
}

func TestSensitiveQueryParameterSuppression(t *testing.T) {
	rule := NewSensitiveQueryParameterRule()
	code := `package auth
func token(r *http.Request) string {
	//nolint:sensitive-query-param // protocol-mandated callback
	return r.URL.Query().Get("token")
}`
	ctx := core.NewFileContext("/src/auth.go", "/src", []byte(code), core.DefaultConfig())
	assert.Empty(t, rule.AnalyzeFile(ctx))
}
