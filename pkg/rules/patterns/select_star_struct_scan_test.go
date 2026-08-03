package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectStarStructScanRule_Metadata(t *testing.T) {
	rule := NewSelectStarStructScanRule()
	assert.Equal(t, "select-star-struct-scan", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestSelectStarStructScanRule_Detection(t *testing.T) {
	rule := NewSelectStarStructScanRule()
	tests := []struct {
		name        string
		code        string
		expectTable string
	}{
		{
			name:        "plain star over a table",
			code:        "package main\nfunc ex(db *D) {\n\tdb.Get(&x, `SELECT * FROM vault_snapshots WHERE id = $1`)\n}",
			expectTable: "vault_snapshots",
		},
		{
			name:        "aliased star over a table",
			code:        "package main\nfunc ex(db *D) {\n\tdb.Get(&x, `SELECT vs.*, vs.created_by FROM vault_snapshots vs WHERE vs.id = $1`)\n}",
			expectTable: "vault_snapshots",
		},
		{
			name:        "multiline query",
			code:        "package main\nfunc ex(db *D) {\n\tdb.Select(&x, `\n\t\tSELECT *\n\t\tFROM gift_wallets\n\t\tWHERE status = $1`)\n}",
			expectTable: "gift_wallets",
		},
		{
			// Колонки берутся из подзапроса, а он тут же в коде: миграция их не меняет.
			name: "derived table is not a violation",
			code: "package main\nfunc ex(db *D) {\n\tdb.Select(&x, `SELECT * FROM (SELECT id FROM a UNION SELECT id FROM b) t ORDER BY id`)\n}",
		},
		{
			name: "explicit columns",
			code: "package main\nfunc ex(db *D) {\n\tdb.Select(&x, `SELECT id, name FROM users`)\n}",
		},
		{
			name: "count star is not a column list",
			code: "package main\nfunc ex(db *D) {\n\tdb.Get(&n, `SELECT count(*) FROM investments`)\n}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createSelectStarContext(t, "repository.go", tt.code)
			violations := rule.AnalyzeFile(ctx)
			if tt.expectTable == "" {
				assert.Empty(t, violations, "expected no violations: %s", tt.name)
				return
			}
			require.Len(t, violations, 1, "expected one violation: %s", tt.name)
			assert.Equal(t, "select_star_struct_scan", violations[0].Context["pattern"])
			assert.Equal(t, tt.expectTable, violations[0].Context["table"])
		})
	}
}

func TestSelectStarStructScanRule_TestFilesExcluded(t *testing.T) {
	rule := NewSelectStarStructScanRule()
	code := "package main\nfunc ex(db *D) {\n\tdb.Get(&x, `SELECT * FROM users WHERE id = $1`)\n}"
	ctx := createSelectStarContext(t, "repository_test.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func createSelectStarContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   strings.Split(code, "\n"),
		Content: []byte(code),
	}
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile(path, []byte(code))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx.SetGoAST(fset, astFile)
	return ctx
}
