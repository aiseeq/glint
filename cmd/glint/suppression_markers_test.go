package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/deadcode"
	"github.com/aiseeq/glint/pkg/rules/doccheck"
)

// Every file that comments in its own syntax has markers, and
// suppression-without-reason judges the same markers that suppress: a bare
// one in a block-comment continuation, in Markdown, HTML or Python is a
// finding, a reasoned one is not, and text that is no comment is neither.
func TestSuppressionWithoutReasonJudgesEveryCommentSyntax(t *testing.T) {
	root := t.TempDir()
	for _, tt := range []struct {
		name, file, source string
		want               []int
	}{
		{"go block continuation", "a.go", "package p\n\n/* grouped constants\n * nolint:empty-decl-group */\nconst ()\n", []int{4}},
		{"go block with reason", "b.go", "package p\n\n/* nolint:empty-decl-group kept for the generator */\nconst ()\n", nil},
		{"go raw string", "c.go", "package p\n\nvar s = `\n//nolint:empty-decl-group\n`; const ()\n", nil},
		{"ts template literal", "a.ts", "const t = `\n//nolint:hardcoded-secret\n`; const password = \"x\";\n", nil},
		{"markdown on the line", "doc.md", "# Doc\n\nSee [x](missing.md). <!-- //nolint:md-broken-link -->\n", []int{3}},
		{"markdown above", "above.md", "# Doc\n\n<!-- nolint:md-broken-link -->\nSee [x](missing.md).\n", []int{3}},
		{"markdown with reason", "reason.md", "<!-- nolint:md-broken-link the page is published later -->\nSee [x](missing.md).\n", nil},
		{"markdown quoted in a fence", "fence.md", "```\n<!-- nolint:md-broken-link -->\n```\n", nil},
		{"python", "s.py", "# nolint:python-file\nprint(\"x\")\n", []int{1}},
		{"python slashes after the hash", "t.py", "# //nolint:python-file\nprint(\"x\")\n", nil},
		{"html", "p.html", "<script src=\"http://cdn.example.com/x.js\"></script> <!-- //nolint:cdn-asset-without-integrity -->\n", []int{1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(filepath.Join(root, tt.file), root, []byte(tt.source), core.DefaultConfig())
			var lines []int
			for _, v := range deadcode.NewSuppressionWithoutReasonRule().AnalyzeFile(ctx) {
				lines = append(lines, v.Line)
			}
			assert.Equal(t, tt.want, lines)
		})
	}
}

// Punctuation after the rule name is no reason: the marker is a finding.
func TestSuppressionWithoutReasonRejectsPunctuationReasons(t *testing.T) {
	root := t.TempDir()
	source := "package p\n//nolint:empty-decl-group .\n//nolint:empty-decl-group //\n//nolint:empty-decl-group –\n// empty-decl-group: safe.\n// empty-decl-group: safe –\n//nolint:empty-decl-group — real reason\n/* nolint:empty-decl-group real reason */\n// empty-decl-group:\tsafe — real reason\n"
	ctx := parsedGoContext(t, filepath.Join(root, "a.go"), root, source)
	var lines []int
	for _, v := range deadcode.NewSuppressionWithoutReasonRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{2, 3, 4, 5, 6}, lines)
}

// excludedReader reads the instruction files an exclude pattern leaves out
// and honors markers; it borrows the name of a glint rule, since only markers
// of glint rules are judged.
type excludedReader struct{ *everyFileRule }

func (*excludedReader) ReadsExcludedInstructions() {}

// An instruction file an exclude pattern leaves out still reaches the rules
// that read such files, so a bare marker in it hides what a reader that
// honors markers reports: it is judged there like a marker in analyzed code.
// instruction-size honors no marker, so its markers hide nothing there.
func TestExcludedInstructionMarkerWithoutReasonIsReported(t *testing.T) {
	module := t.TempDir()
	writeModuleFile(t, module, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, module, "main.go", "package main\n\nfunc main() {}\n")
	writeModuleFile(t, module, "CLAUDE.md", "<!-- nolint:md-broken-link -->\n")
	writeModuleFile(t, module, "sub/CLAUDE.md", "<!-- nolint:md-broken-link the page is published later -->\n")
	writeModuleFile(t, module, "big/CLAUDE.md", "<!-- nolint:instruction-size -->\n"+strings.Repeat("a", 30000))
	cfg := core.DefaultConfig()
	cfg.Settings.Exclude = []string{"*.md"}
	reader := &excludedReader{&everyFileRule{rules.NewBaseRule("md-broken-link", "docs", "sees every file", core.SeverityLow)}}
	list := []rules.Rule{doccheck.NewInstructionSizeRule(), reader, deadcode.NewSuppressionWithoutReasonRule()}

	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), module, cfg, list, false)
	require.NoError(t, err)
	violations, panics, err := analyzePrepared(prepared, list, cfg)
	require.NoError(t, err)
	require.Empty(t, panics)
	var found []string
	for _, v := range violations {
		if strings.HasSuffix(v.File, ".md") && v.Suppression == "" {
			found = append(found, v.File+":"+strconv.Itoa(v.Line)+":"+v.Rule)
		}
	}
	assert.ElementsMatch(t, []string{"big/CLAUDE.md:1:instruction-size", "big/CLAUDE.md:1:md-broken-link", "CLAUDE.md:1:suppression-without-reason"}, found)
}

// settings.exclude with a pattern over every file of a language of the
// project ("*.go", "**/*.ts") takes that language out of the analysis.
func TestBroadExclusionReportsAWholeLanguage(t *testing.T) {
	for pattern, want := range map[string]bool{
		"*.go":        true,
		"**/*.ts":     true,
		"*.ts":        true,
		"*.pb.go":     false,
		"*_test.go":   false,
		"*.md":        false,
		"**/*.min.js": false,
	} {
		t.Run(pattern, func(t *testing.T) {
			root := t.TempDir()
			writeModuleFile(t, root, ".glint.yaml", "settings:\n  exclude:\n    - \""+pattern+"\"\n")
			writeModuleFile(t, root, "cmd/app/main.go", "package main\n\nfunc main() {}\n")
			writeModuleFile(t, root, "internal/store/a.go", "package store\n")
			writeModuleFile(t, root, "internal/store/a_test.go", "package store\n")
			writeModuleFile(t, root, "web/src/a.ts", "export const a = 1;\n")
			writeModuleFile(t, root, "web/src/b.ts", "export const b = 1;\n")
			cfg, err := core.LoadConfigWithDefaults(root)
			require.NoError(t, err)
			found := broadFindingsForTest(t, cfg)
			if want {
				require.Len(t, found, 1)
				assert.Equal(t, 3, found[0].Line)
			} else {
				assert.Empty(t, found)
			}
		})
	}
}

// An explicit settings.skip_dirs that names a directory of the project's
// sources takes it out as a whole; a foreign, generated or test-data one, or
// one without sources, does not.
func TestBroadExclusionReportsSkipDirsOverSources(t *testing.T) {
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "settings:\n  skip_dirs:\n    - internal\n    - vendor\n    - testdata\n    - generated\n    - assets\n    - web\n    - .git\n")
	writeModuleFile(t, root, "cmd/app/main.go", "package main\n\nfunc main() {}\n")
	writeModuleFile(t, root, "internal/store/a.go", "package store\n")
	writeModuleFile(t, root, "vendor/x/x.go", "package x\n")
	writeModuleFile(t, root, "pkg/testdata/t.go", "package t\n")
	writeModuleFile(t, root, "pkg/generated/g.go", "package g\n")
	writeModuleFile(t, root, "assets/logo.svg", "<svg/>\n")
	writeModuleFile(t, root, "web/src/a.ts", "export const a = 1;\n")
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	var lines []int
	for _, v := range broadFindingsForTest(t, cfg) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{3, 8}, lines)
}
