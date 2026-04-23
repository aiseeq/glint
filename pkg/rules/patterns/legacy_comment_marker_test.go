package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestLegacyCommentMarkerRule(t *testing.T) {
	rule := NewLegacyCommentMarkerRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name: "inline line comment admitting runtime legacy branch",
			code: `package router

func Route(p string) string {
	// 2. Legacy mode: separate admin/user path handling
	if p == "/admin" {
		return "admin"
	}
	return "user"
}`,
			filename:  "backend/router/composite_router.go",
			wantCount: 1,
		},
		{
			name: "godoc-level legacy comment caught too",
			code: `package auth

// Legacy SSE auth: token-query fallback for old clients
func AuthSSE() {}`,
			filename:  "backend/auth/sse.go",
			wantCount: 1,
		},
		{
			name: "URL-adjacent legacy descriptor — 3rd-party service, NOT flagged",
			code: `package middleware

var ScriptSrc = []string{
	"https://www.googletagmanager.com", // Google Tag Manager (legacy browser support)
}`,
			filename:  "backend/middleware/csp.go",
			wantCount: 0,
		},
		{
			name: "policy quote self-reference — NOT flagged",
			code: `package lint

// CLAUDE.md forbids legacy code — see "No legacy, only current code"
var policy = "legacy"
`,
			filename:  "tools/policy.go",
			wantCount: 0,
		},
		{
			name: "nolint suppression honored",
			code: `package router

func Route() {
	// Legacy compat branch //nolint:legacy-comment-marker
	_ = 1
}`,
			filename:  "router/r.go",
			wantCount: 0,
		},
		{
			name: "test file skipped",
			code: `package router

// Legacy mode test
func TestLegacy() {}`,
			filename:  "router/r_test.go",
			wantCount: 0,
		},
		{
			name: "word legacy inside longer word — NOT flagged",
			code: `package math

// legacies is the plural form we keep in schema
var legacies int
`,
			filename:  "math/m.go",
			wantCount: 0,
		},
		{
			name: "block-comment legacy admitted",
			code: `package config

/*
 * Legacy loader retained for old deployments.
 */
func LoadOld() {}
`,
			filename:  "config/old.go",
			wantCount: 1,
		},
		{
			name: "self-exclusion file skipped (legacy_identifier.go)",
			code: `package rules

// Legacy is flagged by this rule.
var name = "legacy"
`,
			filename:  "rules/legacy_identifier.go",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), nil)
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d (%q)", v.Message, v.Line, v.Code)
				}
			}
		})
	}
}
