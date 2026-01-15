package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestRedundantCompatibilityRule_FalseCompatibilityComments(t *testing.T) {
	tests := []struct {
		name       string
		code       string
		wantCount  int
		wantReason string
	}{
		{
			name: "Russian backward compatibility comment",
			code: `package main

// GetAdminIDFromContext returns admin ID
// Fallback: проверяем constants.UserIDKey для обратной совместимости
func GetAdminIDFromContext() {}
`,
			wantCount:  1,
			wantReason: "False backward compatibility claim",
		},
		{
			name: "English backward compatibility comment",
			code: `package main

// For backward compatibility with old clients
func GetOldValue() {}
`,
			wantCount:  1,
			wantReason: "False backward compatibility claim",
		},
		{
			name: "Legacy support comment",
			code: `package main

// Legacy support for v1 API
func HandleLegacy() {}
`,
			wantCount:  1,
			wantReason: "False backward compatibility claim",
		},
		{
			name: "Normal comment - no violation",
			code: `package main

// GetValue returns value from context
func GetValue() {}
`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh rule for each test
			rule := NewRedundantCompatibilityRule()
			
			ctx := core.NewFileContext("test.go", ".", []byte(tt.code), nil)
			violations := rule.AnalyzeFile(ctx)
			
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s", v.Message)
				}
			}
			
			if tt.wantCount > 0 && len(violations) > 0 {
				if violations[0].Message == "" {
					t.Error("violation message should not be empty")
				}
			}
		})
	}
}

func TestRedundantCompatibilityRule_MultipleContextKeyFallbacks(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name: "Multiple ctx.Value calls with different keys",
			code: `package main

import "context"

func GetAdminIDFromContext(ctx context.Context) (string, bool) {
	if value := ctx.Value(AdminIDKeyAlt); value != nil {
		return value.(string), true
	}
	if value := ctx.Value(AdminIDKey); value != nil {
		return value.(string), true
	}
	if value := ctx.Value(UserIDKey); value != nil {
		return value.(string), true
	}
	return "", false
}
`,
			wantCount: 1, // One violation for the function
		},
		{
			name: "Single ctx.Value call - no violation",
			code: `package main

import "context"

func GetUserID(ctx context.Context) (string, bool) {
	if value := ctx.Value(UserIDKey); value != nil {
		return value.(string), true
	}
	return "", false
}
`,
			wantCount: 0,
		},
		{
			name: "Two ctx.Value calls - violation",
			code: `package main

import "context"

func GetID(ctx context.Context) string {
	if v := ctx.Value(Key1); v != nil {
		return v.(string)
	}
	if v := ctx.Value(Key2); v != nil {
		return v.(string)
	}
	return ""
}
`,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRedundantCompatibilityRule()
			parser := core.NewParser()
			
			ctx := core.NewFileContext("test.go", ".", []byte(tt.code), nil)
			// Parse Go AST for AST-based checks
			fset, astFile, err := parser.ParseGoFile("test.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}
			
			violations := rule.AnalyzeFile(ctx)
			
			// Filter for multiple-context-keys pattern
			contextKeyViolations := 0
			for _, v := range violations {
				if v.Context != nil {
					if pattern, ok := v.Context["pattern"].(string); ok && pattern == "multiple-context-keys" {
						contextKeyViolations++
					}
				}
			}
			
			if contextKeyViolations != tt.wantCount {
				t.Errorf("got %d context-key violations, want %d", contextKeyViolations, tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d", v.Message, v.Line)
				}
			}
		})
	}
}

func TestRedundantCompatibilityRule_DuplicateKeyDefinitions(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name: "AdminIDKey and AdminIDKeyAlt",
			code: `package main

const (
	AdminIDKey    = "adminID"
	AdminIDKeyAlt = "admin_id"
)
`,
			wantCount: 1,
		},
		{
			name: "Single key - no violation",
			code: `package main

const (
	AdminIDKey = "adminID"
	UserIDKey  = "userID"
)
`,
			wantCount: 0,
		},
		{
			name: "Key with Alt suffix",
			code: `package main

var (
	TokenKey    = contextKey("token")
	TokenKeyAlt = contextKey("token_alt")
)
`,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRedundantCompatibilityRule()
			parser := core.NewParser()
			
			ctx := core.NewFileContext("test.go", ".", []byte(tt.code), nil)
			// Parse Go AST for AST-based checks
			fset, astFile, err := parser.ParseGoFile("test.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}
			
			violations := rule.AnalyzeFile(ctx)
			
			// Filter for duplicate-key-definitions pattern
			dupKeyViolations := 0
			for _, v := range violations {
				if v.Context != nil {
					if pattern, ok := v.Context["pattern"].(string); ok && pattern == "duplicate-key-definitions" {
						dupKeyViolations++
					}
				}
			}
			
			if dupKeyViolations != tt.wantCount {
				t.Errorf("got %d duplicate-key violations, want %d", dupKeyViolations, tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s", v.Message)
				}
			}
		})
	}
}

func TestRedundantCompatibilityRule_SkipTestFiles(t *testing.T) {
	code := `package main

// For backward compatibility
func GetOldValue() {}
`
	rule := NewRedundantCompatibilityRule()
	
	// Test file should be skipped
	ctx := core.NewFileContext("test_file_test.go", ".", []byte(code), nil)
	violations := rule.AnalyzeFile(ctx)
	
	if len(violations) != 0 {
		t.Errorf("test files should be skipped, got %d violations", len(violations))
	}
}

func TestRedundantCompatibilityRule_LegitimateCompatibility(t *testing.T) {
	code := `package main

// For backward compatibility with external API clients
func HandleExternalAPI() {}
`
	rule := NewRedundantCompatibilityRule()
	
	// Should skip because it mentions "external API"
	ctx := core.NewFileContext("api_handler.go", ".", []byte(code), nil)
	violations := rule.AnalyzeFile(ctx)
	
	if len(violations) != 0 {
		t.Errorf("legitimate external API compatibility should be skipped, got %d violations", len(violations))
	}
}
