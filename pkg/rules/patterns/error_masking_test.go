package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorMaskingRule_Metadata(t *testing.T) {
	rule := NewErrorMaskingRule()

	assert.Equal(t, "error-masking", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityCritical, rule.DefaultSeverity())
	assert.NotEmpty(t, rule.Description())
}

func TestErrorMaskingRule_GoPatterns(t *testing.T) {
	rule := NewErrorMaskingRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
		pattern     string
	}{
		{
			name:        "error return true",
			code:        `if err != nil { log.Error(err); return true }`,
			expectMatch: true,
			pattern:     "error_return_true",
		},
		{
			name:        "error return success string",
			code:        `if err != nil { return "success" }`,
			expectMatch: true,
			pattern:     "error_return_success",
		},
		// NOTE: switch default is now only detected via AST in specific function contexts
		// to avoid false positives on display/label functions
		{
			name:        "fake data return",
			code:        `return "fake-user-id-123"`,
			expectMatch: true,
			pattern:     "fake_data_return",
		},
		{
			name:        "proper error handling",
			code:        `if err != nil { return fmt.Errorf("failed: %w", err) }`,
			expectMatch: false,
		},
		{
			name:        "normal return",
			code:        `return result, nil`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.FileContext{
				Path:    "/project/backend/service.go",
				RelPath: "backend/service.go",
				Lines:   []string{tt.code},
			}

			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
				assert.Contains(t, violations[0].Context["pattern"], tt.pattern)
			} else {
				assert.Empty(t, violations, "Expected no violation for: %s", tt.code)
			}
		})
	}
}

func TestErrorMaskingRule_TSPatterns(t *testing.T) {
	rule := NewErrorMaskingRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
		pattern     string
	}{
		{
			name:        "env default",
			code:        `const port = process.env.PORT || "3000"`,
			expectMatch: true,
			pattern:     "env_default",
		},
		{
			name:        "config default",
			code:        `const url = config.apiUrl || "http://localhost"`,
			expectMatch: true,
			pattern:     "config_default",
		},
		{
			name:        "catch return null",
			code:        `catch (e) { console.error(e); return null }`,
			expectMatch: true,
			pattern:     "catch_hardcoded_return",
		},
		{
			name:        "proper error handling",
			code:        `catch (e) { throw new Error("Operation failed", { cause: e }) }`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.FileContext{
				Path:    "/project/frontend/src/api/client.ts",
				RelPath: "frontend/src/api/client.ts",
				Lines:   []string{tt.code},
			}

			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
			} else {
				assert.Empty(t, violations, "Expected no violation for: %s", tt.code)
			}
		})
	}
}

func TestErrorMaskingRule_Exceptions(t *testing.T) {
	rule := NewErrorMaskingRule()

	tests := []struct {
		name        string
		path        string
		code        string
		expectMatch bool
	}{
		{
			name:        "test file excluded",
			path:        "backend/service_test.go",
			code:        `return "fake-user-id"`,
			expectMatch: false,
		},
		{
			name:        "vendor excluded",
			path:        "vendor/lib/file.go",
			code:        `if err != nil { return true }`,
			expectMatch: false,
		},
		{
			name:        "generated file excluded",
			path:        "backend/generated/types.go",
			code:        `default: return nil`,
			expectMatch: false,
		},
		{
			name:        "next.config excluded",
			path:        "frontend/next.config.js",
			code:        `process.env.NODE_ENV || "development"`,
			expectMatch: false,
		},
		{
			name:        "e2e excluded",
			path:        "frontend/e2e/tests/login.ts",
			code:        `catch (e) { return null }`,
			expectMatch: false,
		},
		{
			name:        "production code detected",
			path:        "backend/services/user_service.go",
			code:        `if err != nil { log.Error(err); return true }`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.FileContext{
				Path:    tt.path,
				RelPath: tt.path,
				Lines:   []string{tt.code},
			}

			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s in %s", tt.code, tt.path)
			} else {
				assert.Empty(t, violations, "Expected no violation for: %s in %s", tt.code, tt.path)
			}
		})
	}
}

func TestErrorMaskingRule_CommentSkip(t *testing.T) {
	rule := NewErrorMaskingRule()

	ctx := &core.FileContext{
		Path:    "backend/service.go",
		RelPath: "backend/service.go",
		Lines: []string{
			"// if err != nil { return true }",
			"/* default: return nil */",
			"",
			"   // Comment with default: return false",
		},
	}

	violations := rule.AnalyzeFile(ctx)
	assert.Empty(t, violations, "Comments should be skipped")
}
