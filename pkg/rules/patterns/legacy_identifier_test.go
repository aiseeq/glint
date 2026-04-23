package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestLegacyIdentifierRule(t *testing.T) {
	rule := NewLegacyIdentifierRule()

	tests := []struct {
		name          string
		path          string
		code          string
		expectedCount int
	}{
		{
			name: "method with Legacy prefix",
			path: "/src/backend/router.go",
			code: `package router
type R struct{}
func (r *R) registerLegacyAdminRoutes() {}`,
			expectedCount: 1,
		},
		{
			name: "method with Legacy suffix",
			path: "/src/backend/router.go",
			code: `package router
type R struct{}
func (r *R) RegisterRoutesLegacy() {}`,
			expectedCount: 1,
		},
		{
			name: "standalone function with Legacy in middle",
			path: "/src/backend/helpers.go",
			code: `package helpers
func BuildLegacyPayload() {}`,
			expectedCount: 1,
		},
		{
			name: "type LegacyUser",
			path: "/src/backend/models.go",
			code: `package models
type LegacyUser struct{}`,
			expectedCount: 1,
		},
		{
			name: "const LegacyTimeout",
			path: "/src/backend/config.go",
			code: `package config
const LegacyTimeout = 30`,
			expectedCount: 1,
		},
		{
			name: "var legacy_flag (snake_case)",
			path: "/src/backend/flags.go",
			code: `package flags
var legacy_flag = true`,
			expectedCount: 1,
		},
		{
			name: "func legally NOT flagged (incidental substring)",
			path: "/src/backend/helpers.go",
			code: `package helpers
func IsLegallyCompliant() bool { return true }`,
			expectedCount: 0,
		},
		{
			name: "func Collegial NOT flagged",
			path: "/src/backend/helpers.go",
			code: `package helpers
func CollegialReview() {}`,
			expectedCount: 0,
		},
		{
			name: "test file skipped",
			path: "/src/backend/router_test.go",
			code: `package router
func registerLegacyAdminRoutes() {}`,
			expectedCount: 0,
		},
		{
			name: "generated file skipped",
			path: "/src/backend/types.gen.go",
			code: `package types
type LegacyUser struct{}`,
			expectedCount: 0,
		},
		{
			name: "nolint opt-out honored",
			path: "/src/backend/router.go",
			code: `package router
func registerLegacyRoutes() {} //nolint:legacy-identifier // external API stability`,
			expectedCount: 0,
		},
		{
			name: "two Legacy methods in same file",
			path: "/src/backend/router.go",
			code: `package router
type R struct{}
func (r *R) registerLegacyAdminRoutes() {}
func (r *R) registerLegacyUserRoutes() {}`,
			expectedCount: 2,
		},
		{
			name: "clean code NOT flagged",
			path: "/src/backend/router.go",
			code: `package router
type Router struct{}
func (r *Router) RegisterAdminRoutes() {}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.path, "/src", []byte(tt.code), core.DefaultConfig())
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile(tt.path, []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}
