package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestFrontendEnvFallbackRule(t *testing.T) {
	rule := NewFrontendEnvFallbackRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name:      "placeholder Supabase URL is forbidden",
			code:      `const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://placeholder.supabase.co'`,
			filename:  "frontend/src/lib/supabase.ts",
			wantCount: 1,
		},
		{
			name:      "placeholder anon key is forbidden",
			code:      `const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'placeholder-key'`,
			filename:  "frontend/src/lib/supabase.ts",
			wantCount: 1,
		},
		{
			name:      "bracket NEXT_PUBLIC access is forbidden",
			code:      `const apiUrl = process.env['NEXT_PUBLIC_API_URL'] ?? ''`,
			filename:  "frontend/src/lib/auth-context.tsx",
			wantCount: 1,
		},
		{
			name:      "Supabase required env fallback is forbidden",
			code:      `const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL ?? 'https://example.supabase.co'`,
			filename:  "frontend/src/lib/supabase.ts",
			wantCount: 1,
		},
		{
			name: "explicit required config is valid",
			code: `const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error('Supabase public configuration is required')
}`,
			filename:  "frontend/src/lib/supabase.ts",
			wantCount: 0,
		},
		{
			name:      "test files can mention placeholder for regression assertions",
			code:      `expect(url.hostname).not.toBe('placeholder.supabase.co')`,
			filename:  "frontend/e2e/tests/auth-redirect.spec.ts",
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
