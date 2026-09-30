package doccheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A link target is URL-encoded and may hold balanced parentheses; a link
// written inside a code span, an HTML comment or an indented code block is an
// example, not a reference; a ~~~ fence is closed only by ~~~, so a ``` line
// inside it is content.
func TestMdBrokenLinkMarkdownSyntax(t *testing.T) {
	violations := analyzeMarkdown(t, "README.md", map[string]string{
		"README.md": "# Doc\n\n" +
			"See [spaced](docs/my%20file.md) and [parens](docs/foo_(bar).md).\n" +
			"Use `[label](docs/missing-in-code-span.md)` syntax for links.\n" +
			"\n" +
			"<!-- [old](docs/removed.md) -->\n" +
			"<!--\n[older](docs/removed-too.md)\n-->\n" +
			"\n" +
			"    [indented code](docs/indented.md)\n" +
			"\n" +
			"~~~\n```\n~~~\n" +
			"[after tilde fence](docs/real.md) and [gone](docs/gone.md)\n",
		"docs/my file.md":   "# Spaced\n",
		"docs/foo_(bar).md": "# Parens\n",
		"docs/real.md":      "# Real\n",
	})

	require.Len(t, violations, 1)
	assert.Equal(t, 16, violations[0].Line)
	assert.Contains(t, violations[0].Message, "docs/gone.md")
}

// A closing fence must use the opening character and be at least as long; an
// unclosed fence runs to the end of the document.
func TestMdBrokenLinkFenceMatching(t *testing.T) {
	violations := analyzeMarkdown(t, "README.md", map[string]string{
		"README.md": "Start a block with:\n\n~~~\n```\n~~~\n\n[gone](missing.md)\n\n````md\n```\n[inside](inside.md)\n````\n[after](after.md)\n\n```\n[unclosed](unclosed.md)\n",
	})

	var targets []any
	for _, v := range violations {
		targets = append(targets, v.Context["target"])
	}
	assert.Equal(t, []any{"missing.md", "after.md"}, targets)
}

// An indented line inside a list item continues the item: its link is prose.
func TestMdBrokenLinkIndentedListContinuationIsProse(t *testing.T) {
	violations := analyzeMarkdown(t, "README.md", map[string]string{
		"README.md": "- item\n\n    continued with [a link](missing.md)\n",
	})

	require.Len(t, violations, 1)
	assert.Equal(t, 3, violations[0].Line)
}

// A list inside a ~~~ fence is literal text, not a label followed by a list.
func TestMdListAfterLabelIgnoresTildeFence(t *testing.T) {
	ctx := rulestest.TextFile(t, "content/post.md", "Intro text.\n\n~~~text\nSome text describing a list:\n- literal item in a tilde fence\n~~~\n")
	assert.Empty(t, NewMdListAfterLabelRule().AnalyzeFile(ctx))
}

// docs/ is rendered like any other Markdown: the rendering rules apply there.
func TestMdRenderingRulesCheckDocsDirectory(t *testing.T) {
	lineBreak := rulestest.TextFile(t, "docs/guide.md", "**Name:** glint\n**Owner:** team\n")
	assert.Len(t, NewMdLineBreakRule().AnalyzeFile(lineBreak), 1)

	list := rulestest.TextFile(t, "docs/guide.md", "Some text describing a list:\n- item\n")
	assert.Len(t, NewMdListAfterLabelRule().AnalyzeFile(list), 1)
}

// Frontmatter is YAML: an RFC 3339 timestamp and a quoted date are valid
// dates; YAML that does not parse is reported as such.
func TestMdFrontmatterParsesYAML(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "rfc3339 timestamp",
			content: "---\ntitle: \"Release notes\"\ndate: 2024-01-15T10:00:00+03:00\nversion: 1.2.3\n---\n",
		},
		{
			name:    "quoted date",
			content: "---\ndate: \"2024-01-15\"\n---\n",
		},
		{
			name:    "date that is not a date",
			content: "---\ndate: January 2026\n---\n",
			want:    []string{"Invalid date format"},
		},
		{
			name:    "empty date",
			content: "---\ndate:\n---\n",
			want:    []string{"Invalid date format"},
		},
		{
			name:    "broken yaml",
			content: "---\ntitle: [unclosed\n---\n",
			want:    []string{"not valid YAML"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := rulestest.TextFile(t, "content/post.md", tt.content)
			var got []string
			for _, v := range NewMdFrontmatterRule().AnalyzeFile(ctx) {
				got = append(got, v.Message)
			}
			require.Len(t, got, len(tt.want), "%v", got)
			for i, want := range tt.want {
				assert.Contains(t, got[i], want)
			}
		})
	}
}

// doc-links judges a URL by its parts, not by substrings: "..." inside a
// compare range, "todo" inside a word, and an archived URL embedded in the
// path are ordinary URLs. Sentence punctuation after a URL is not part of it.
func TestDocLinksURLParts(t *testing.T) {
	ctx := goDocFile(t, `// Package doc demonstrates links.
package doc

// A compares releases at https://github.com/golang/go/compare/go1.21.0...go1.22.0 for details.
// The reference app is https://github.com/tastejs/todomvc and its spec.
// Archived copy: https://web.archive.org/web/2020/https://golang.org/doc/
func A() {}

// B links https://example.com/api, https://host.test/TODO/page, https://host.test/a//b and https://host.test/a/../b.
func B() {}
`)
	var urls []any
	for _, v := range NewDocLinksRule().AnalyzeFile(ctx) {
		urls = append(urls, v.Context["url"])
	}
	assert.Equal(t, []any{
		"https://example.com/api",
		"https://host.test/TODO/page",
		"https://host.test/a//b",
		"https://host.test/a/../b",
	}, urls)
}

// internal/ at any depth is not a public API; a method of an unexported type
// is not either.
func TestDocMissingSkipsNonPublicAPI(t *testing.T) {
	nested := goDocFile(t, "pkg/svc/internal/impl/impl.go", `// Package impl is internal.
package impl

func Helper() {}
`)
	assert.Empty(t, NewDocCompletenessRule().AnalyzeFile(nested))

	method := goDocFile(t, "pkg/svc/svc.go", `// Package svc is a service.
package svc

type server struct{ port int }

func (s *server) Serve() error { s.port++; return nil }
`)
	assert.Empty(t, NewDocCompletenessRule().AnalyzeFile(method))
}

// Percent escapes decode; a % that starts no escape is a literal percent sign.
func TestFilePathOfDecodesPercentEscapes(t *testing.T) {
	assert.Equal(t, "docs/my file.md", filePathOf("docs/my%20file.md"))
	assert.Equal(t, "docs/100%.md", filePathOf("docs/100%.md"))
	assert.Equal(t, "docs/a b%zz.md", filePathOf("docs/a%20b%zz.md"))
}

func goDocFile(t *testing.T, pathOrSource string, source ...string) *core.FileContext {
	t.Helper()
	if len(source) == 0 {
		return rulestest.GoFile(t, "doc/a.go", pathOrSource)
	}
	return rulestest.GoFile(t, pathOrSource, source[0])
}
