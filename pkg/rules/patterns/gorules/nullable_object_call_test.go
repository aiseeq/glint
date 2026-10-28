package gorules

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
			// The right side of || runs only when the left one is false.
			name:      "same-line null check before || is valid",
			code:      `return entry.stats == null || !Object.hasOwn(entry.stats, "skipped") ? 0 : entry.stats.skipped`,
			filename:  "src/lib/report.ts",
			wantCount: 0,
		},
		{
			name:      "same-line negation before || is valid",
			code:      `if (!entry.details || Object.keys(entry.details).length === 0) return`,
			filename:  "src/lib/report.ts",
			wantCount: 0,
		},
		{
			name:      "same-line not-null check before && is valid",
			code:      `return entry.details !== undefined && entry.details !== null && Object.keys(entry.details).length > 0`,
			filename:  "src/lib/report.ts",
			wantCount: 0,
		},
		{
			name:      "same-line null check before && does not guard",
			code:      `return entry.details == null && Object.keys(entry.details).length > 0`,
			filename:  "src/lib/report.ts",
			wantCount: 1,
		},
		{
			name:      "same-line check of another value does not guard",
			code:      `return entry.stats == null || Object.keys(entry.details).length > 0`,
			filename:  "src/lib/report.ts",
			wantCount: 1,
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

// A property the file itself fills with an object is no response field: the
// loader stores its module table on the require function and reads it back.
// A property filled from a call or an await may still be null.
func TestNullableObjectCallPropertyFilledByTheFile(t *testing.T) {
	code := `function load() {
  const modules = { ...chunk[0][1], ...ctx.appModules };
  const table = [];
  function req(id) { return modules[id] }
  req.m = modules;
  req.t = table;
  req.c = new Map();
  req.d = { a: 1 };
  req.r = await fetchRegistry();
  req.s = buildState();
  return req;
}
function findModule(req, marker) {
  const ids = Object.keys(req.m).filter((id) => req.m[id].toString().includes(marker));
  const n = Object.keys(req.t).length + Object.keys(req.d).length;
  const c = Object.entries(req.c);
  const r = Object.keys(req.r);
  const s = Object.keys(req.s);
  return ids[0];
}
`
	ctx := core.NewFileContext("scripts/bundle.mjs", ".", []byte(code), nil)
	var lines []int
	for _, v := range NewNullableObjectCallRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	if len(lines) != 2 || lines[0] != 17 || lines[1] != 18 {
		t.Fatalf("want findings on lines 17 (await) and 18 (call) only, got %v", lines)
	}
}

// A property the file also clears or fills from elsewhere may be missing.
func TestNullableObjectCallPropertyAlsoCleared(t *testing.T) {
	code := `const modules = {};
req.m = modules;
function reset() { req.m = null; }
const ids = Object.keys(req.m);
`
	if got := NewNullableObjectCallRule().AnalyzeFile(core.NewFileContext("scripts/bundle.mjs", ".", []byte(code), nil)); len(got) != 1 {
		t.Fatalf("a property also set to null is still reported, got %d findings", len(got))
	}
}

// A row of the file's own constant table is no response: every row is a
// literal of the file, and a field its type does not let be missing is there.
// A field declared optional or nullable may still be missing in a row.
func TestNullableObjectCallRowOfTheFileTable(t *testing.T) {
	code := `const sets: { id: string; re: Record<string, RegExp> }[] = [
  { id: "a", re: { x: /-x$/, y: /-y$/ } },
  { id: "b", re: { x: /-x2$/ } },
];
const conf = { limits: { a: 1 } };
for (const set of sets) {
  for (const [name, re] of Object.entries(set.re)) {
    console.log(name, re);
  }
}
const n = Object.keys(conf.limits).length;
const opts: { id: string; extra?: Record<string, string> }[] = [{ id: "a" }];
for (const o of opts) {
  console.log(Object.keys(o.extra));
}
for (const row of await loadRows()) {
  console.log(Object.keys(row.re));
}
`
	var lines []int
	for _, v := range NewNullableObjectCallRule().AnalyzeFile(core.NewFileContext("tools/report.ts", ".", []byte(code), nil)) {
		lines = append(lines, v.Line)
	}
	if len(lines) != 2 || lines[0] != 14 || lines[1] != 17 {
		t.Fatalf("want findings on lines 14 (optional field) and 17 (rows from a call) only, got %v", lines)
	}
}
