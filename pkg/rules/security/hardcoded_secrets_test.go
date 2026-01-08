package security

import (
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

func TestHardcodedSecretsSkipsTestFiles(t *testing.T) {
	rule := NewHardcodedSecretsRule()

	code := `package main

var password = "test_password_123456"`

	// Path is a test file - should be skipped
	ctx := core.NewFileContext("/src/config_test.go", "/src", []byte(code), core.DefaultConfig())

	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Should skip test files")
}

func TestHardcodedSecretsMasksOutput(t *testing.T) {
	rule := NewHardcodedSecretsRule()

	code := `package main

var password = "verylongsecretpassword"`

	ctx := core.NewFileContext("/src/config.go", "/src", []byte(code), core.DefaultConfig())

	violations := rule.AnalyzeFile(ctx)

	assert.Len(t, violations, 1)
	// The code should be masked - not contain the full secret
	assert.Contains(t, violations[0].Code, "***", "Secret should be masked in output")
	assert.NotContains(t, violations[0].Code, "verylongsecretpassword", "Full secret should not appear")
}
