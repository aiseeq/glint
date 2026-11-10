package gorules

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

// An unexplained "ignore errors" is reported in Russian as in English; with a
// reason after it, it is not.
func TestTechDebtRule_IgnoreErrors(t *testing.T) {
	rule := NewTechDebtRule()
	for code, reported := range map[string]bool{
		"// ignore errors":                        true,
		"// игнорируем ошибки":                    true,
		"//Игнорирую ошибку":                      true,
		"// тут игнорируем ошибки":                true,
		"// игнорируем ошибки: кэш необязателен":  false,
		"// ignore errors, the cache is optional": false,
		"// неигнорируемые ошибки":                false,
	} {
		violations := rule.AnalyzeFile(createTechDebtContext(t, "backend/service.go", code))
		if !reported {
			assert.Empty(t, violations, code)
			continue
		}
		require.Len(t, violations, 1, code)
		assert.Equal(t, "ignore_errors", violations[0].Context["pattern"], code)
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

// "incomplete" and its Russian "незаверш..." also describe data or input;
// followed by a noun about data or as part of a name they mark nothing, any
// other use is still a marker. "в работе" marks work only as a label.
func TestTechDebtRule_UnfinishedWorkWords(t *testing.T) {
	rule := NewTechDebtRule()
	for _, code := range []string{
		"// Incomplete data cannot prove that earlier entries are gone, so",
		"// incomplete responses are retried once",
		"// незавершённые транзакции откатываются при старте",
		"// в работе сервиса бывают паузы при пересборке индекса",
		"// incomplete-data flag is set by the reader",
		"// задача в работе у пользователя.",
		"// incomplete.json holds a truncated upstream reply",
		"// incomplete_reply is the fixture name",
		"// incomplete.yaml is the truncated config fixture",
		"// в работе.md описан процесс",
		"// incomplete items are dropped by the reader",
		"// незавершённые записи журнала пропускаются",
		"// incomplete code points at the end of the buffer are kept",
		"// Incomplete rows are skipped by the importer",
		"// незавершённые заказы закрываются ночью",
		"// незавершённый платёж отменяется через сутки",
		"// incomplete.csv fixture is truncated",
		"// incomplete code units at the end are kept",
		"// incomplete.txt fixture is truncated",
		"// incomplete.log is the captured stream",
		"// незавершённые сделки откатываются ночью",
		"// incomplete utf8 sequences are buffered",
		"// incomplete rows which the reader drops are logged",
		"// incomplete requests such as HEAD probes are answered",
		"// incomplete data",
	} {
		ctx := createTechDebtContext(t, "backend/service.go", code)
		assert.Empty(t, rule.AnalyzeFile(ctx), "not a marker: %s", code)
	}
	for _, code := range []string{
		"// INCOMPLETE: retries are not wired yet",
		"// Incomplete - the parser skips nested blocks",
		"// incomplete implementation, finish after the API settles",
		"// Незавершено: нет обработки отмены",
		"// незавершённая реализация, доделать после ревью",
		"// В работе: перенос на новый клиент",
		"// Incomplete.",
		"// Incomplete. Finish after the API settles",
		"// incomplete; finish later",
		"// в работе.",
		"// незавершённый код ниже не вызывается",
		"// незавершённого кода тут больше нет?",
		"// незавершено",
		"// Incomplete! remove before release",
		"// Incomplete (see issue 12)",
		"// Incomplete — finish after release",
		"// Incomplete – the parser skips nested blocks",
		"// incomplete, finish later",
		"// незавершено, доделать",
		"// Incomplete...",
		"// Incomplete?",
		"// incomplete -- see issue 12",
		"// incomplete features below",
		"// incomplete implementations of the codec",
		"// incomplete fix for the retry path",
		"// incomplete code below",
		"// incomplete logic in the merger",
		"// incomplete refactoring of the loader",
		"// incomplete handling: cancel is ignored",
		"// incomplete support: retries are not wired",
		"// Incomplete--see issue 12",
		"// incomplete work - pagination",
		"// незавершённая работа: перенос",
		"// незавершённая функция экспорта",
		"// незавершённая логика слияния",
		"// незавершённый рефакторинг загрузчика",
		"// incomplete function",
		"// incomplete data handling: not wired yet",
		"// Incomplete data; WIP",
		"// incomplete rows - work in progress",
		"// incomplete records — stub",
		"// incomplete data tests",
		"// incomplete data checks",
		"// incomplete response decoding",
		"// incomplete message dispatch",
		"// incomplete payload management",
		"// incomplete readers",
		"// incomplete request validation",
		"// incomplete results serialization",
		"// incomplete rows; validation is skipped",
		"// незавершённые запросы: нет ретраев",
		"// незавершённые заказы, допилить",
		"// незавершённые заказы, доработать",
		"// незавершённые заказы: реализовать отмену",
		"// incomplete data handling",
		"// incomplete request parsing",
		"// incomplete output formatting",
		"// incomplete rows, finish after the API settles",
		"// incomplete results, later",
		"// Незавершённая операция импорта",
		"// незавершённые запросы обработчика",
		"// незавершённые заказы — доделать",
		"// incomplete_impl",
		"// incomplete-impl",
		"// incomplete-ish handling, finish later",
		"// incomplete reader implementation",
		"// в работе — перенос на новый клиент",
		"// incomplete stub",
		"// incomplete for now",
		"// incomplete until the v2 API lands",
		"// Незавершённый метод экспорта",
		"// Incomplete ",
		"// incomplete refactors",
		"// incomplete fixes of the retry path",
		"// incomplete codecs are skipped by the probe",
		"// WIP",
		"// work in progress on the exporter",
		"// not finished: pagination",
		"// incomplete results: not implemented",
		"// incomplete data: unimplemented",
		"// incomplete rows: XXX",
		"// incomplete data — HACK",
		"// incomplete entries - TBD",
		"// incomplete data, needs work",
		"// incomplete results: needs rework",
		"// incomplete rows, needs fix",
		"// incomplete data - not done",
		"// incomplete request: unfinished",
		"// incomplete orders, work-in-progress",
		"// incomplete rows — stubbed",
		"// incomplete payload (temporary)",
		"// незавершённые операции, не доделано",
		"// незавершённые записи — дописать",
		"// незавершённые данные: переделать",
		"// в работе. Перенос на новый клиент",
		"// в работе ",
		"// incomplete data path",
		"// incomplete stream reader",
		"// incomplete request builder",
		"// incomplete messages router",
		"// incomplete response cache",
		"// incomplete page layout",
		"// incomplete batch mode",
		"// incomplete orders flow",
		"// incomplete rows pipeline",
		"// incomplete data yet",
		"// incomplete data import",
		"// incomplete orders exports",
		"// incomplete message dispatches",
		"// incomplete data: in progress",
		"// incomplete response: placeholder",
		"// incomplete data: pending",
		"// incomplete orders (see issue 12)",
		"// incomplete records!",
		"// незавершённые записи — заглушка",
		"// незавершённые запросы: позже",
		"// незавершённые данные — нет проверки",
		"// незавершённые заказы, потом",
	} {
		ctx := createTechDebtContext(t, "backend/service.go", code)
		assert.Len(t, rule.AnalyzeFile(ctx), 1, "a marker: %s", code)
	}
}

// Markdown prose and fenced examples are documentation, not code comments.
// A hotfix is a release path in projects that ship them (hotfix/* branches,
// a hotfix label): a comment about hotfixes describes that path, not the code.
// Only a label on the code itself ("HOTFIX:", "hotfix for ...") is a marker.
func TestTechDebtRule_HotfixAsDomainWord(t *testing.T) {
	rule := NewTechDebtRule()
	for _, code := range []string{
		"// hotfixes already out keep the version they were built with",
		"// hotfix branches start from the commit production runs",
		"// Hotfix lets a branch from the commit production runs go out past the freeze",
		"// hotfixBase reads the commit the hotfix base target runs",
	} {
		ctx := createTechDebtContext(t, "backend/service.go", code)
		assert.Empty(t, rule.AnalyzeFile(ctx), "not a marker: %s", code)
	}
	for _, code := range []string{"// HOTFIX", "// hotfix: skip the check until the vendor fixes it", "// Hotfix (prod outage)"} {
		ctx := createTechDebtContext(t, "backend/service.go", code)
		assert.NotEmpty(t, rule.AnalyzeFile(ctx), "marker: %s", code)
	}
}

func TestTechDebtRule_OnlyCodeFiles(t *testing.T) {
	rule := NewTechDebtRule()
	code := "# Docs\n\n```go\n// temporary workaround for the vendor bug\nx := 1\n```\n"
	ctx := core.NewFileContext("/docs/README.md", "/", []byte(code), nil)
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
// name happens to be, or start with, a marker word (temporaryReadError,
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

// temporaryReadError tells a transient failure from a permanent one.
func temporaryReadError(err error) bool { return false }
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
			ctx := core.NewFileContext("/backend/service.go", "/", []byte(tt.code), nil)
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
	ctx := core.NewFileContext("/backend/service.go", "/", []byte(code), nil)
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
