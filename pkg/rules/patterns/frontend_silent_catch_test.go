package patterns

import (
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
