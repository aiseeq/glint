package doccheck

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestMdLineBreakRule(t *testing.T) {
	rule := NewMdLineBreakRule()

	tests := []struct {
		name             string
		content          string
		expectViolations int
	}{
		{
			name: "consecutive bold-labels without hard breaks",
			content: `# Document

**Версия:** 1.0.0
**Дата создания:** Январь 2026
**Автор:** Saga Team
**Статус:** Published

Some text`,
			expectViolations: 1,
		},
		{
			name: "bold-labels with hard breaks (two spaces)",
			// Note: trailing spaces are added via string concatenation to prevent trimming
			content: "# Document\n\n" +
				"**Версия:** 1.0.0  \n" +
				"**Дата создания:** Январь 2026  \n" +
				"**Автор:** Saga Team  \n" +
				"**Статус:** Published\n\n" +
				"Some text",
			expectViolations: 0,
		},
		{
			name: "bold-labels separated by blank lines",
			content: `# Document

**Версия:** 1.0.0

**Дата создания:** Январь 2026

**Автор:** Saga Team

**Статус:** Published

Some text`,
			expectViolations: 0,
		},
		{
			name: "single bold-label line",
			content: `# Document

**Версия:** 1.0.0

Some text`,
			expectViolations: 0,
		},
		{
			name: "two consecutive bold-labels",
			content: `# Document

**Key1:** Value1
**Key2:** Value2

Some text`,
			expectViolations: 1,
		},
		{
			name: "mixed - some with breaks, some without",
			content: `# Document

**First:** A
**Second:** B
**Third:** C

Some text`,
			expectViolations: 1,
		},
		{
			name: "at end of file without blank line",
			content: `# Document

Some text

**Версия:** 1.0.0
**Статус:** Published`,
			expectViolations: 1,
		},
		{
			name: "non-markdown file",
			content: `**Bold:** text
**Another:** text`,
			expectViolations: 0, // Will be filtered because not .md file
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use .md extension for all tests except the last one
			path := "/test/doc.md"
			if tt.name == "non-markdown file" {
				path = "/test/doc.txt"
			}

			ctx := core.NewFileContext(path, "/test", []byte(tt.content), nil)
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

func TestMdLineBreakRule_Fix(t *testing.T) {
	rule := NewMdLineBreakRule()

	content := `# Document

**Версия:** 1.0.0
**Дата:** Январь 2026
**Автор:** Team

Some text`

	ctx := core.NewFileContext("/test/doc.md", "/test", []byte(content), nil)
	violations := rule.AnalyzeFile(ctx)

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}

	fix, err := rule.Fix(ctx, violations[0])
	if err != nil {
		t.Fatalf("fix error: %v", err)
	}

	if fix == nil {
		t.Fatal("expected fix, got nil")
	}

	// Check that fix adds trailing spaces to lines except last
	expected := "**Версия:** 1.0.0  \n**Дата:** Январь 2026  \n**Автор:** Team"
	if fix.NewText != expected {
		t.Errorf("unexpected fix:\ngot:      %q\nexpected: %q", fix.NewText, expected)
	}
}
