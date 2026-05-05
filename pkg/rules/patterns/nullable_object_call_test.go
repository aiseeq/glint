package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestNullableObjectCallRule(t *testing.T) {
	rule := NewNullableObjectCallRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name:      "Object entries on nested API field is forbidden",
			code:      `const rows = Object.entries(entry.details)`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 1,
		},
		{
			name:      "hasOwnProperty call on nested API field is forbidden",
			code:      `.filter(([key]) => Object.prototype.hasOwnProperty.call(entry.details, key))`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 1,
		},
		{
			name:      "Object hasOwn call on nested API field is forbidden",
			code:      `if (Object.hasOwn(response.data, key)) return response.data[key]`,
			filename:  "frontend/admin-app/src/lib/api.ts",
			wantCount: 1,
		},
		{
			name:      "local object constant is valid",
			code:      `const rows = Object.entries(detailLabels)`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 0,
		},
		{
			name:      "nullish object fallback is valid",
			code:      `const rows = Object.entries(entry.details ?? {})`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 0,
		},
		{
			name:      "same-line object guard is valid",
			code:      `return entry.details && Object.keys(entry.details).length > 0`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 0,
		},
		{
			name:      "test files are skipped",
			code:      `expect(Object.entries(entry.details)).toHaveLength(1)`,
			filename:  "frontend/admin-app/src/app/employees/page.test.tsx",
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
