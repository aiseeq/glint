package security

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestHardcodedSecretsRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
		wantPattern    string // expected pattern name in context
	}{
		{
			name: "no secrets",
			code: `package main

var name = "John"
var count = 42`,
			wantViolations: 0,
		},
		{
			name: "hardcoded password",
			code: `package main

var password = "supersecret123"`,
			wantViolations: 1,
			wantPattern:    "password",
		},
		{
			name: "hardcoded passwd",
			code: `package main

const passwd = "mypassword"`,
			wantViolations: 1,
			wantPattern:    "password",
		},
		{
			name: "hardcoded api key",
			code: `package main

var apiKey = "sk_live_abcdefghijklmnop"`,
			wantViolations: 1,
			wantPattern:    "api_key",
		},
		{
			name: "hardcoded api-key with hyphen",
			code: `package main

var api_key = "abcdefghijklmnopqrstuvwx"`,
			wantViolations: 1,
			wantPattern:    "api_key",
		},
		{
			name: "hardcoded secret",
			code: `package main

var secret = "very_secret_value_here"`,
			wantViolations: 1,
			wantPattern:    "secret",
		},
		{
			name: "hardcoded private key",
			code: `package main

var privateKey = "my_private_key_value"`,
			wantViolations: 1,
			wantPattern:    "secret",
		},
		{
			name: "hardcoded auth token",
			code: `package main

var authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9_token_here"`,
			wantViolations: 1,
			wantPattern:    "token",
		},
		{
			name: "AWS access key",
			code: `package main

var awsKey = "AKIAIOSFODNN7REALKEY"`,
			wantViolations: 1,
			wantPattern:    "aws_key",
		},
		{
			name: "PEM private key header",
			code: `package main

var key = "-----BEGIN RSA PRIVATE KEY-----"`,
			wantViolations: 1,
			wantPattern:    "private_key",
		},
		{
			name: "JWT token",
			code: `package main

var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"`,
			wantViolations: 1,
			wantPattern:    "jwt",
		},
		{
			name: "placeholder value - should skip",
			code: `package main

var password = "your_password_here"`,
			wantViolations: 0,
		},
		{
			name: "example value - should skip",
			code: `package main

var apiKey = "example_api_key_12345678"`,
			wantViolations: 0,
		},
		{
			name: "TODO comment - should skip",
			code: `package main

var password = "TODO: replace with real password"`,
			wantViolations: 0,
		},
		{
			name: "test_ prefix - should skip",
			code: `package main

var apiKey = "test_key_for_development"`,
			wantViolations: 0,
		},
		{
			name: "comment line - should skip",
			code: `package main

// password = "secret123"
var x = 1`,
			wantViolations: 0,
		},
		{
			name: "short password - should skip",
			code: `package main

var pwd = "abc"`,
			wantViolations: 0,
		},
		{
			name: "environment variable reference - ok",
			code: `package main

import "os"

var password = os.Getenv("PASSWORD")`,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewHardcodedSecretsRule()

			ctx := core.NewFileContext("/src/config.go", "/src", []byte(tt.code), core.DefaultConfig())

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)

			if tt.wantPattern != "" && len(violations) > 0 {
				ctx := violations[0].Context
				assert.Equal(t, tt.wantPattern, ctx["pattern"],
					"Expected pattern '%s' but got '%s'", tt.wantPattern, ctx["pattern"])
			}
		})
	}
}

func TestHardcodedSecretsScansSecuritySensitiveLocations(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		code        string
		wantPattern string
	}{
		{
			name:        "provider credential in test helper",
			path:        "/src/e2e/credential_helper_test.go",
			code:        `package e2e; const key = "` + strings.Join([]string{"re", "_1234567890abcdefghijklmnop"}, "") + `"`,
			wantPattern: "resend_key",
		},
		{
			name:        "password in config package",
			path:        "/src/config/loader.go",
			code:        `package config; const password = "real-password-value"`,
			wantPattern: "password",
		},
		{
			name:        "password embedded in shell command",
			path:        "/src/tools/database.go",
			code:        `package tools; const command = "` + strings.Join([]string{"PGPASSWORD", "=1234567890abcdefghijkl psql"}, "") + `"`,
			wantPattern: "pgpassword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewHardcodedSecretsRule()
			ctx := core.NewFileContext(tt.path, "/src", []byte(tt.code), core.DefaultConfig())
			violations := rule.AnalyzeFile(ctx)
			if assert.Len(t, violations, 1) {
				assert.Equal(t, tt.wantPattern, violations[0].Context["pattern"])
			}
		})
	}
}

func TestHardcodedSecretsAllowsExplicitPlaceholders(t *testing.T) {
	rule := NewHardcodedSecretsRule()
	code := `package config
var password = "${DB_PASSWORD}"
var key = process.env.RESEND_API_KEY`
	ctx := core.NewFileContext("/src/config/loader.go", "/src", []byte(code), core.DefaultConfig())
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestHardcodedSecretsAllowsDynamicPGPassword(t *testing.T) {
	rule := NewHardcodedSecretsRule()
	code := "const remote = `PGPASSWORD=${shellQuote(dbPassword)} psql -h 127.0.0.1`"
	ctx := core.NewFileContext("/src/e2e/deploy.ts", "/src", []byte(code), core.DefaultConfig())
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestHardcodedSecretsAllowsGenericCredentialsInTestConfig(t *testing.T) {
	rule := NewHardcodedSecretsRule()
	code := `const config = { jwtSecret: "test-jwt-secret-32-characters-minimum" }`
	ctx := core.NewFileContext("/src/shared/config/test-config.ts", "/src", []byte(code), core.DefaultConfig())
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestHardcodedSecretsMasksOutput(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		fullMatch string
		forbidden string
	}{
		{
			name:      "unquoted PGPASSWORD",
			code:      `PGPASSWORD=1234567890abcdefghijkl psql`,
			fullMatch: "PGPASSWORD=1234567890abcdefghijkl",
		},
		{
			name:      "unquoted PGPASSWORD with punctuation suffix",
			code:      `PGPASSWORD=1234567890abcdefghijkl@prod-secret:%more psql`,
			fullMatch: "PGPASSWORD=1234567890abcdefghijkl@prod-secret:%more",
			forbidden: "prod-secret",
		},
		{
			name:      "AWS access key",
			code:      `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REALKEY`,
			fullMatch: "AKIAIOSFODNN7REALKEY",
		},
		{
			name:      "JWT",
			code:      `token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
			fullMatch: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		},
		{
			name:      "PEM private key header",
			code:      `-----BEGIN RSA PRIVATE KEY-----`,
			fullMatch: "-----BEGIN RSA PRIVATE KEY-----",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewHardcodedSecretsRule()
			ctx := core.NewFileContext("/src/config.go", "/src", []byte(tt.code), core.DefaultConfig())

			violations := rule.AnalyzeFile(ctx)

			if assert.Len(t, violations, 1) {
				assert.Contains(t, violations[0].Code, "[REDACTED]")
				assert.NotContains(t, violations[0].Code, tt.fullMatch, "full regexp match must not appear")
				if tt.forbidden != "" && strings.Contains(violations[0].Code, tt.forbidden) {
					t.Fatal("secret suffix must not appear in violation code")
				}
			}
		})
	}
}

func TestHardcodedSecretsMasksEveryMatchOnReportedLine(t *testing.T) {
	const password = `password = "very-secret-password"`
	const awsKey = `AKIAIOSFODNN7REALKEY`
	const jwt = `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`
	code := `package config; var credentials = map[string]string{"db": "` + password + `", "aws": "` + awsKey + `", "jwt": "` + jwt + `"}`
	ctx := core.NewFileContext("/src/config.go", "/src", []byte(code), core.DefaultConfig())

	violations := NewHardcodedSecretsRule().AnalyzeFile(ctx)

	if assert.Len(t, violations, 1) {
		assert.NotContains(t, violations[0].Code, password)
		assert.NotContains(t, violations[0].Code, awsKey)
		assert.NotContains(t, violations[0].Code, jwt)
		assert.Equal(t, 3, strings.Count(violations[0].Code, "[REDACTED]"))
	}
}
