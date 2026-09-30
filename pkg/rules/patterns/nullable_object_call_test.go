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
		{
			name: "JSDoc mentioning the call is not code",
			code: `/**
 * Object.keys(resp.data) throws when data is null.
 */
export const x = 1`,
			filename:  "frontend/src/lib/api.ts",
			wantCount: 0,
		},
		{
			name: "early-return guard on a previous line is valid",
			code: `export function keys(data: Resp) {
  if (!data.items) return []
  return Object.keys(data.items)
}`,
			filename:  "frontend/src/lib/objs.ts",
			wantCount: 0,
		},
		{
			name: "early-return guard block is valid",
			code: `export function keys(data: Resp) {
  if (data.items == null) {
    throw new Error('items are required')
  }
  return Object.keys(data.items)
}`,
			filename:  "frontend/src/lib/objs.ts",
			wantCount: 0,
		},
		{
			name: "enclosing truthy guard is valid",
			code: `export function keys(data: Resp) {
  if (data.items) {
    const names = Object.keys(data.items)
    return names
  }
  return []
}`,
			filename:  "frontend/src/lib/objs.ts",
			wantCount: 0,
		},
		{
			name: "guard inside a sibling block does not cover the call",
			code: `export function keys(data: Resp, strict: boolean) {
  if (strict) {
    if (!data.items) return []
  }
  return Object.keys(data.items)
}`,
			filename:  "frontend/src/lib/objs.ts",
			wantCount: 1,
		},
		{
			name: "guard in another function does not cover the call",
			code: `export function a(data: Resp) {
  if (!data.items) return []
  return 1
}
export function b(data: Resp) {
  return Object.keys(data.items)
}`,
			filename:  "frontend/src/lib/objs.ts",
			wantCount: 1,
		},
		{
			name: "call split over lines is checked",
			code: `export function k2(cfg: Cfg) {
  return Object.keys(
    cfg.routes
  )
}`,
			filename:  "frontend/src/lib/objs.ts",
			wantCount: 1,
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
