package doccheck

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestMdListAfterLabelRule(t *testing.T) {
	rule := NewMdListAfterLabelRule()

	tests := []struct {
		name             string
		path             string
		content          string
		expectViolations int
	}{
		{
			name: "label with list no blank line",
			path: "/test/doc.md",
			content: `# Test

**Оценка сроков:**
- MVP: 6-9 месяцев
- Production-ready: 12-18 месяцев

Some text.`,
			expectViolations: 1,
		},
		{
			name: "label with list and blank line",
			path: "/test/doc.md",
			content: `# Test

**Оценка сроков:**

- MVP: 6-9 месяцев
- Production-ready: 12-18 месяцев

Some text.`,
			expectViolations: 0,
		},
		{
			name: "label with value on same line",
			path: "/test/doc.md",
			content: `# Test

**Version:** 1.0.0

Some text.`,
			expectViolations: 0,
		},
		{
			name: "multiple labels with lists",
			path: "/test/doc.md",
			content: `# Test

**First:**
- item1
- item2

**Second:**
- item3
- item4`,
			expectViolations: 2,
		},
		{
			name: "numbered list after label",
			path: "/test/doc.md",
			content: `# Test

**Steps:**
1. First step
2. Second step`,
			expectViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.path, "/test", []byte(tt.content), nil)
			violations := rule.AnalyzeFile(ctx)

			if len(violations) != tt.expectViolations {
				t.Errorf("expected %d violations, got %d", tt.expectViolations, len(violations))
				for _, v := range violations {
					t.Logf("  violation at line %d: %s", v.Line, v.Message)
				}
			}
		})
	}
}
