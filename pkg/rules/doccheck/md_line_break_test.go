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
		{
			name: "bold-labels inside fenced code block",
			content: "# Document\n\n" +
				"```markdown\n" +
				"**Key1:** Value1\n" +
				"**Key2:** Value2\n" +
				"```\n\n" +
				"Some text",
			expectViolations: 0, // code block content is a literal example
		},
		{
			name: "bold-labels inside tilde fenced code block",
			content: "# Document\n\n" +
				"~~~\n" +
				"**Key1:** Value1\n" +
				"**Key2:** Value2\n" +
				"~~~\n\n" +
				"Some text",
			expectViolations: 0,
		},
		{
			name: "bold-labels after a closed fence are still checked",
			content: "# Document\n\n" +
				"```\n" +
				"code\n" +
				"```\n\n" +
				"**Key1:** Value1\n" +
				"**Key2:** Value2\n\n" +
				"Some text",
			expectViolations: 1,
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
