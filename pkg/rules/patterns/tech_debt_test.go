package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTechDebtRule_Metadata(t *testing.T) {
	rule := NewTechDebtRule()

	assert.Equal(t, "tech-debt", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

// Comments admitting legacy code belong to legacy-comment-marker; tech-debt keeps
// the other obsolete-code admissions, so one comment is never reported twice.
func TestTechDebtRule_ObsoleteCodeMarkers(t *testing.T) {
	rule := NewTechDebtRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name:        "legacy code marker is legacy-comment-marker's",
			code:        "// legacy code - needs migration",
			expectMatch: false,
		},
		{
			name:        "deprecated code",
			code:        "// deprecated code, will be removed",
			expectMatch: true,
		},
		{
			name:        "old code marker",
			code:        "// old code from v1",
			expectMatch: true,
		},
		{
			name:        "remove legacy is legacy-comment-marker's",
			code:        "// TODO: remove legacy implementation",
			expectMatch: false,
		},
		{
			name:        "normal comment",
			code:        "// This function handles user login",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createTechDebtContext(t, "backend/service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
				assert.Equal(t, "obsolete_code_marker", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}

func TestTechDebtRule_FakeRefactoring(t *testing.T) {
	rule := NewTechDebtRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name:        "wrapper instead of removal",
			code:        "// wrapper delegates instead of removal",
			expectMatch: true,
		},
		{
			name:        "russian fake refactoring",
			code:        "// делегирует вместо удаления",
			expectMatch: true,
		},
		{
			name:        "normal delegation comment",
			code:        "// delegates to the service layer",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createTechDebtContext(t, "backend/service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
				assert.Equal(t, "fake_refactoring", violations[0].Context["pattern"])
				assert.Equal(t, core.SeverityHigh, violations[0].Severity)
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}

func TestTechDebtRule_TemporarySolutions(t *testing.T) {
	rule := NewTechDebtRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name:        "temporary fix",
			code:        "// temporary fix for issue #123",
			expectMatch: true,
		},
		{
			name:        "temp fix",
			code:        "// temp fix until next release",
			expectMatch: true,
		},
		{
			name:        "quick fix",
			code:        "// quick fix for production",
			expectMatch: true,
		},
		{
			name:        "workaround",
			code:        "// workaround for library bug",
			expectMatch: true,
		},
		{
			name:        "hotfix",
			code:        "// hotfix for critical issue",
			expectMatch: true,
		},
		{
			name:        "russian temporary",
			code:        "// временное решение",
			expectMatch: true,
		},
		{
			name:        "temporary workaround",
			code:        "// temporary workaround for the vendor bug",
			expectMatch: true,
		},
		{
			name:        "temporary as a marker label",
			code:        "// Temporary: until the new endpoint ships",
			expectMatch: true,
		},
		{
			// Describes the domain (short-lived credentials), not the code.
			name:        "temporary as an ordinary adjective",
			code:        "// temporary credentials expire after one hour",
			expectMatch: false,
		},
		{
			name:        "russian temporary as an ordinary adjective",
			code:        "// временный файл удаляется после загрузки",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createTechDebtContext(t, "backend/service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
				assert.Equal(t, "temporary_solution", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}

func TestTechDebtRule_BrokenFeature(t *testing.T) {
	rule := NewTechDebtRule()

	code := "// broken - doesn't work with new API"
	ctx := createTechDebtContext(t, "backend/service.go", code)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations)
	assert.Equal(t, "broken_feature", violations[0].Context["pattern"])
	assert.Equal(t, core.SeverityHigh, violations[0].Severity)

	for _, marker := range []string{"// BROKEN: returns stale rows", "// broken feature, see the issue", "// broken"} {
		ctx := createTechDebtContext(t, "backend/service.go", marker)
		require.NotEmpty(t, rule.AnalyzeFile(ctx), "marker must be reported: %s", marker)
	}
}

// "broken" describing the world (a pipe, a link) is not an admission about the code.
func TestTechDebtRule_BrokenAsOrdinaryWord(t *testing.T) {
	rule := NewTechDebtRule()
	for _, code := range []string{
		"// broken pipe is expected when the client disconnects",
		"// broken links are reported to the author",
	} {
		ctx := createTechDebtContext(t, "backend/service.go", code)
		assert.Empty(t, rule.AnalyzeFile(ctx), "not a marker: %s", code)
	}
}

// Markdown prose and fenced examples are documentation, not code comments.
func TestTechDebtRule_OnlyCodeFiles(t *testing.T) {
	rule := NewTechDebtRule()
	code := "# Docs\n\n```go\n// temporary workaround for the vendor bug\nx := 1\n```\n"
	ctx := &core.FileContext{
		Path:    "/docs/README.md",
		RelPath: "docs/README.md",
		Lines:   splitLines(code),
		Content: []byte(code),
	}
	assert.Empty(t, rule.AnalyzeFile(ctx))

	for _, path := range []string{"web/src/api.ts", "web/src/api.js", "backend/api.go"} {
		ctx := createTechDebtContext(t, path, "// temporary workaround for the vendor bug")
		assert.NotEmpty(t, rule.AnalyzeFile(ctx), "code file must be checked: %s", path)
	}
}

func TestTechDebtRule_NeedsRefactoring(t *testing.T) {
	rule := NewTechDebtRule()

	tests := []struct {
		code        string
		expectMatch bool
	}{
		{"// needs refactoring", true},
		{"// should be refactored", true},
		{"// refactor this later", true},
		{"// the code is clean", false},
	}

	for _, tt := range tests {
		ctx := createTechDebtContext(t, "backend/service.go", tt.code)
		violations := rule.AnalyzeFile(ctx)

		if tt.expectMatch {
			require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
		} else {
			assert.Empty(t, violations)
		}
	}
}

func TestTechDebtRule_WIPRequiresWordBoundary(t *testing.T) {
	rule := NewTechDebtRule()

	tests := []struct {
		code        string
		expectMatch bool
	}{
		{"// WIP: implementation is not finished", true},
		{"// wiping live position rows is prevented", false},
	}

	for _, tt := range tests {
		ctx := createTechDebtContext(t, "backend/service.go", tt.code)
		violations := rule.AnalyzeFile(ctx)

		if tt.expectMatch {
			require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
		} else {
			assert.Empty(t, violations)
		}
	}
}

// A godoc comment opens with the name of the thing it documents. When that
// name happens to be, or start with, a marker word (temporaryFetchError,
// incomplete), the comment describes an identifier, not a state of the code.
func TestTechDebtRule_DocCommentNamingIdentifierIsNotMarker(t *testing.T) {
	rule := NewTechDebtRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "identifier starts with marker word",
			code: `package p

// temporaryFetchError tells a transient failure from a permanent one.
func temporaryFetchError(err error) bool { return false }
`,
			expectMatch: false,
		},
		{
			name: "method doc equals marker word",
			code: `package p

// incomplete returns what the draft still lacks; nil when nothing.
func (d draft) incomplete() error { return nil }
`,
			expectMatch: false,
		},
		{
			name: "grouped const doc equals marker word",
			code: `package p

const (
	// workaround is the mode name used by the CLI.
	workaround = "workaround"
)
`,
			expectMatch: false,
		},
		{
			name: "marker in prose before a function is still a marker",
			code: `package p

// temporary fix until the upstream bug is closed
func fetch() error { return nil }
`,
			expectMatch: true,
		},
		{
			name: "marker word not followed by its declaration",
			code: `package p

// incomplete: the parser stops at the first table
var x = 1
`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.FileContext{
				Path:    "/backend/service.go",
				RelPath: "backend/service.go",
				Lines:   splitLines(tt.code),
				Content: []byte(tt.code),
			}
			violations := rule.AnalyzeFile(ctx)
			if tt.expectMatch {
				require.NotEmpty(t, violations)
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}

func TestTechDebtRule_DeadCode(t *testing.T) {
	rule := NewTechDebtRule()

	code := "// dead code - not used anymore"
	ctx := createTechDebtContext(t, "backend/service.go", code)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations)
	assert.Equal(t, "dead_code_marker", violations[0].Context["pattern"])
}

// Репро из self-check самого glint: комментарий ссылается на имя правила unused-field,
// а не признаётся в мёртвом коде. Kebab-case идентификатор — не проза.
func TestTechDebtRule_RuleNameIsNotDeadCodeMarker(t *testing.T) {
	rule := NewTechDebtRule()

	for _, code := range []string{
		"// the shape of an optional filter belongs to unused-field's territory rather than here",
		"// see unused-param for the parameter case",
		"// unused-symbol reports this instead",
	} {
		ctx := createTechDebtContext(t, "backend/service.go", code)
		assert.Empty(t, rule.AnalyzeFile(ctx), "ссылка на имя правила не является меткой мёртвого кода: %s", code)
	}
}

// Прозаическое упоминание неиспользуемого кода метка по-прежнему ловится.
func TestTechDebtRule_UnusedProseStillFlagged(t *testing.T) {
	rule := NewTechDebtRule()

	// Матчер привязан к началу комментария — так правило устроено и до этой правки.
	for _, code := range []string{
		"// unused variable kept for compatibility",
		"// unused: remove after migration",
		"// unused, see task ABC-123",
	} {
		ctx := createTechDebtContext(t, "backend/service.go", code)
		require.NotEmpty(t, rule.AnalyzeFile(ctx), "метка мёртвого кода должна ловиться: %s", code)
	}
}

func TestTechDebtRule_TestFilesExcluded(t *testing.T) {
	rule := NewTechDebtRule()

	code := "// temporary fix that needs a real one"
	ctx := createTechDebtContext(t, "backend/service_test.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

func TestTechDebtRule_NonCommentLinesSkipped(t *testing.T) {
	rule := NewTechDebtRule()

	code := `package main

func legacy() {
	// This is fine
	x := "legacy code"
}

`
	ctx := &core.FileContext{
		Path:    "/backend/service.go",
		RelPath: "backend/service.go",
		Lines:   splitLines(code),
		Content: []byte(code),
	}
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Non-comment lines should not trigger violations")
}

// A project file that happens to share a name with a glint source is checked
// like any other file.
func TestTechDebtRuleChecksFilesNamedLikeGlintSources(t *testing.T) {
	ctx := core.NewFileContext(
		"/src/rules/legacy_comment_marker.go",
		"/src",
		[]byte("// deprecated code path kept for old clients"),
		core.DefaultConfig(),
	)

	assert.NotEmpty(t, NewTechDebtRule().AnalyzeFile(ctx))
}

// Helper functions
func createTechDebtContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	return &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   []string{code},
		Content: []byte(code),
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
