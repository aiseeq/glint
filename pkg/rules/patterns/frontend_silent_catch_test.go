package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestFrontendSilentCatchRule(t *testing.T) {
	rule := NewFrontendSilentCatchRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name: "logger only is forbidden",
			code: `try {
  await save()
} catch (err) {
  logger.error('Save failed', err)
}`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 1,
		},
		{
			name: "console only is forbidden",
			code: `try {
  await save()
} catch (err) {
  console.error(err)
}`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 1,
		},
		{
			name: "visible error state is valid",
			code: `try {
  await save()
} catch (err) {
  logger.error('Save failed', err)
  setSaveError('Изменения не сохранены')
}`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 0,
		},
		{
			name: "rethrow is valid",
			code: `try {
  await save()
} catch (err) {
  logger.error('Save failed', err)
  throw err
}`,
			filename:  "frontend/admin-app/src/lib/admin-api.ts",
			wantCount: 0,
		},
		{
			name: "test files are skipped",
			code: `try {
  await save()
} catch (err) {
  console.error(err)
}`,
			filename:  "frontend/admin-app/src/app/employees/page.test.tsx",
			wantCount: 0,
		},
		{
			name: "e2e helpers are skipped",
			code: `try {
  await cleanup()
} catch (err) {
  console.error(err)
}`,
			filename:  "frontend/e2e/utils/auth-helpers.ts",
			wantCount: 0,
		},
		{
			name: "e2e helpers are skipped from frontend root",
			code: `try {
  await cleanup()
} catch (err) {
  console.error(err)
}`,
			filename:  "e2e/utils/auth-helpers.ts",
			wantCount: 0,
		},
		{
			name: "jest setup is skipped",
			code: `try {
  mockFetch()
} catch (err) {
  console.error(err)
}`,
			filename:  "frontend/admin-app/jest.setup.js",
			wantCount: 0,
		},
	}

	tests = append(tests, []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name: "logger call inside a comment is not logging",
			code: `try {
  await save()
} catch (err) {
  // console.error(err) was too noisy
  setSaveError(String(err))
}`,
			filename:  "frontend/src/app/page.tsx",
			wantCount: 0,
		},
		{
			name: "feedback word inside a string is not feedback",
			code: `try {
  await save()
} catch (err) {
  console.error('will throw later', err)
}`,
			filename:  "frontend/src/app/page.tsx",
			wantCount: 1,
		},
	}...)

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

// The finding points at the catch itself, and a brace inside a string neither
// stretches that block nor hides the next catch.
func TestFrontendSilentCatchRuleLines(t *testing.T) {
	code := `export async function load() {
  try {
    await fetchData()
  } catch (e) {
    console.error('failed', e)
    report(e)
    cleanup()
  }
}

export async function save() {
  try {
    await put()
  } catch (e) {
    console.error('bad brace {', e)
  }
}

export function Page() {
  const [error, setError] = useState('')
  async function other() {
    try { await x() } catch (e) { setError(String(e)) }
  }
  return null
}`
	ctx := core.NewFileContext("frontend/src/catch.tsx", ".", []byte(code), nil)
	violations := NewFrontendSilentCatchRule().AnalyzeFile(ctx)
	var lines []int
	for _, v := range violations {
		lines = append(lines, v.Line)
		if !strings.Contains(v.Code, "catch") {
			t.Errorf("line %d: code %q is not the catch line", v.Line, v.Code)
		}
	}
	if len(lines) != 2 || lines[0] != 4 || lines[1] != 14 {
		t.Errorf("violations at lines %v, want [4 14]", lines)
	}
}
