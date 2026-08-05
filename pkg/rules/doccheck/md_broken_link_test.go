package doccheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// markdownProject writes the given files and analyzes the first one as Markdown.
func analyzeMarkdown(t *testing.T, target string, files map[string]string) []*core.Violation {
	t.Helper()

	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}

	path := filepath.Join(root, target)
	ctx, err := core.NewFileContextChecked(path, root, []byte(files[target]), core.DefaultConfig())
	require.NoError(t, err)
	return NewMdBrokenLinkRule().AnalyzeFile(ctx)
}

// Repro from glint itself: README linked to docs/configuration.md, which had
// never been written.
func TestMdBrokenLinkReportsMissingFile(t *testing.T) {
	violations := analyzeMarkdown(t, "README.md", map[string]string{
		"README.md": `# Glint

See [configuration reference](docs/configuration.md) for the full list.
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, 3, violations[0].Line)
	assert.Contains(t, violations[0].Message, "docs/configuration.md")
}

func TestMdBrokenLinkAcceptsExistingFile(t *testing.T) {
	violations := analyzeMarkdown(t, "README.md", map[string]string{
		"README.md":             "See [rules](docs/rules.md).\n",
		"docs/rules.md":         "# Rules\n",
		"docs/configuration.md": "# Configuration\n",
	})

	assert.Empty(t, violations)
}

// A link relative to the document's own directory resolves from there.
func TestMdBrokenLinkResolvesRelativeToDocument(t *testing.T) {
	violations := analyzeMarkdown(t, "docs/guide.md", map[string]string{
		"docs/guide.md": "Back to the [index](index.md), up to the [readme](../README.md).\n",
		"docs/index.md": "# Index\n",
		"README.md":     "# Glint\n",
	})

	assert.Empty(t, violations)
}

// A root-relative link resolves from the project root, as GitHub renders it,
// not from the directory of the document that contains it.
func TestMdBrokenLinkResolvesRootRelativeFromProjectRoot(t *testing.T) {
	violations := analyzeMarkdown(t, "docs/guide.md", map[string]string{
		"docs/guide.md": "Back to the [readme](/README.md).\n",
		"README.md":     "# Glint\n",
	})

	assert.Empty(t, violations)
}

func TestMdBrokenLinkReportsMissingRootRelativeTarget(t *testing.T) {
	violations := analyzeMarkdown(t, "docs/guide.md", map[string]string{
		"docs/guide.md": "See [reference](/docs/missing.md).\n",
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "/docs/missing.md")
}

// A directory is a valid link target.
func TestMdBrokenLinkAcceptsDirectory(t *testing.T) {
	violations := analyzeMarkdown(t, "README.md", map[string]string{
		"README.md":         "The [tasks](docs/tasks) live here.\n",
		"docs/tasks/one.md": "# One\n",
	})

	assert.Empty(t, violations)
}

// External links and anchors are not this rule's business: it checks what it
// can check without guessing.
func TestMdBrokenLinkIgnoresExternalAndAnchors(t *testing.T) {
	violations := analyzeMarkdown(t, "README.md", map[string]string{
		"README.md": `# Glint

- [site](https://example.com/page)
- [mail](mailto:team@example.com)
- [section](#configuration)
- [protocol relative](//cdn.example.com/x.js)
`,
	})

	assert.Empty(t, violations)
}

// The anchor part addresses a place inside the file, and the file is what exists.
func TestMdBrokenLinkChecksFileOfAnchoredLink(t *testing.T) {
	violations := analyzeMarkdown(t, "README.md", map[string]string{
		"README.md": "See [section](docs/missing.md#install).\n",
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "docs/missing.md")
}

// A link inside a fenced code block is an example, not a link.
func TestMdBrokenLinkIgnoresFencedCode(t *testing.T) {
	violations := analyzeMarkdown(t, "README.md", map[string]string{
		"README.md": "```markdown\n[example](docs/whatever.md)\n```\n",
	})

	assert.Empty(t, violations)
}

// An image is a link to a file that has to be there just the same.
func TestMdBrokenLinkReportsMissingImage(t *testing.T) {
	violations := analyzeMarkdown(t, "README.md", map[string]string{
		"README.md": "![diagram](docs/flow.png)\n",
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "docs/flow.png")
}

func TestMdBrokenLinkIgnoresNonMarkdown(t *testing.T) {
	violations := analyzeMarkdown(t, "main.go", map[string]string{
		"main.go": "package main // [link](missing.md)\n",
	})

	assert.Empty(t, violations)
}

// Repro from projectA: screenshots are linked with a cache-busting query string.
func TestMdBrokenLinkIgnoresQueryString(t *testing.T) {
	violations := analyzeMarkdown(t, "docs/guide.md", map[string]string{
		"docs/guide.md":    "![admin](../assets/admin.png?v=4.2.185)\n",
		"assets/admin.png": "binary",
	})

	assert.Empty(t, violations)
}

func TestMdBrokenLinkMetadata(t *testing.T) {
	rule := NewMdBrokenLinkRule()
	assert.Equal(t, "md-broken-link", rule.Name())
	assert.Equal(t, "documentation", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}
