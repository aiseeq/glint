package patterns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestSchemaMutationWithoutCleanupRule_Metadata(t *testing.T) {
	rule := NewTestSchemaMutationWithoutCleanupRule()
	assert.Equal(t, "test-schema-mutation-without-cleanup", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
}

func TestSchemaMutationWithoutCleanupRule_Detection(t *testing.T) {
	rule := NewTestSchemaMutationWithoutCleanupRule()
	tests := []struct {
		name   string
		code   string
		expect bool
	}{
		{
			// Ровно тот случай, что отравил базу из пула: колонка осталась после прогона.
			name: "add column without cleanup",
			code: `package tests
func TestReadSurvivesNewColumn(t *testing.T) {
	db := CreateIsolatedTestDB(t)
	db.MustExec("ALTER TABLE vault_snapshots ADD COLUMN probe TEXT")
	require.NotNil(t, db)
}`,
			expect: true,
		},
		{
			name: "add column with t.Cleanup",
			code: `package tests
func TestReadSurvivesNewColumn(t *testing.T) {
	db := CreateIsolatedTestDB(t)
	db.MustExec("ALTER TABLE vault_snapshots ADD COLUMN probe TEXT")
	t.Cleanup(func() { db.MustExec("ALTER TABLE vault_snapshots DROP COLUMN probe") })
}`,
		},
		{
			name: "drop table with defer",
			code: `package tests
func TestScratch(t *testing.T) {
	db.MustExec("CREATE TABLE scratch (id int)")
	defer db.MustExec("DROP TABLE scratch")
}`,
		},
		{
			// Временная таблица исчезает вместе с сессией и общую базу не портит.
			name: "temporary table needs no cleanup",
			code: `package tests
func TestScratch(t *testing.T) {
	db.MustExec("CREATE TEMPORARY TABLE scratch (id int)")
}`,
		},
		{
			// Полезная нагрузка инъекции в security-тесте до базы не доезжает.
			name: "sql injection payload is not executed ddl",
			code: `package tests
func TestRejectsInjection(t *testing.T) {
	payloads := []string{"'; DROP TABLE users; --", "' OR '1'='1"}
	for _, p := range payloads {
		require.Error(t, validateTableName(p))
	}
}`,
		},
		{
			name: "no ddl at all",
			code: `package tests
func TestInsert(t *testing.T) {
	db.MustExec("INSERT INTO users (id) VALUES ($1)", 1)
}`,
		},
		{
			// Хелпер не тест: за ним чистит вызывающий, и правило туда не лезет.
			name: "helper function is not a test",
			code: `package tests
func seedProbeColumn(db *sqlx.DB) {
	db.MustExec("ALTER TABLE vault_snapshots ADD COLUMN probe TEXT")
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createOptDepContext(t, "schema_test.go", tt.code)
			violations := rule.AnalyzeFile(ctx)
			if !tt.expect {
				assert.Empty(t, violations, "ожидалось отсутствие находок: %s", tt.name)
				return
			}
			require.Len(t, violations, 1)
			assert.Equal(t, "test_schema_mutation_without_cleanup", violations[0].Context["pattern"])
		})
	}
}

func TestSchemaMutationWithoutCleanupRule_NonTestFileIgnored(t *testing.T) {
	rule := NewTestSchemaMutationWithoutCleanupRule()
	code := `package tests
func TestScratch(t *testing.T) {
	db.MustExec("ALTER TABLE users ADD COLUMN probe TEXT")
}`
	assert.Empty(t, rule.AnalyzeFile(createOptDepContext(t, "schema.go", code)))
}

func createOptDepContext(t *testing.T, path, code string) *core.FileContext {
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
