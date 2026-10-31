package qarules

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

import "testing"

func TestReadSurvivesNewColumn(t *testing.T) {
	db := CreateIsolatedTestStore(t)
	db.MustExec("ALTER TABLE vault_snapshots ADD COLUMN probe TEXT")
	require.NotNil(t, db)
}`,
			expect: true,
		},
		{
			name: "add column with t.Cleanup",
			code: `package tests

import "testing"

func TestReadSurvivesNewColumn(t *testing.T) {
	db := CreateIsolatedTestStore(t)
	db.MustExec("ALTER TABLE vault_snapshots ADD COLUMN probe TEXT")
	t.Cleanup(func() { db.MustExec("ALTER TABLE vault_snapshots DROP COLUMN probe") })
}`,
		},
		{
			name: "drop table with defer",
			code: `package tests

import "testing"

func TestScratch(t *testing.T) {
	db.MustExec("CREATE TABLE scratch (id int)")
	defer db.MustExec("DROP TABLE scratch")
}`,
		},
		{
			// Временная таблица исчезает вместе с сессией и общую базу не портит.
			name: "temporary table needs no cleanup",
			code: `package tests

import "testing"

func TestScratch(t *testing.T) {
	db.MustExec("CREATE TEMPORARY TABLE scratch (id int)")
}`,
		},
		{
			// Полезная нагрузка инъекции в security-тесте до базы не доезжает.
			name: "sql injection payload is not executed ddl",
			code: `package tests

import "testing"

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

import "testing"

func TestInsert(t *testing.T) {
	db.MustExec("INSERT INTO users (id) VALUES ($1)", 1)
}`,
		},
		{
			// Хелпер не тест: за ним чистит вызывающий, и правило туда не лезет.
			name: "helper function is not a test",
			code: `package tests

import "testing"

func seedProbeColumn(db *sqlx.DB) {
	db.MustExec("ALTER TABLE vault_snapshots ADD COLUMN probe TEXT")
}`,
		},
	}

	tests = append(tests, []struct {
		name   string
		code   string
		expect bool
	}{
		{
			// defer cancel() откатывает контекст, а не схему.
			name: "deferred cancel is not a schema undo",
			code: `package tests

import (
	"context"
	"testing"
)

func TestAlterWithCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _ = db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN tmp_flag bool")
}`,
			expect: true,
		},
		{
			name: "cleanup that only cancels is not a schema undo",
			code: `package tests

import (
	"context"
	"testing"
)

func TestAlterWithCleanupCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	_, _ = db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN tmp_flag bool")
}`,
			expect: true,
		},
		{
			name: "deferred closure that runs SQL is an undo",
			code: `package tests

import "testing"

func TestAlterDeferredClosure(t *testing.T) {
	db.MustExec("ALTER TABLE users ADD COLUMN tmp_flag bool")
	defer func() {
		db.MustExec("ALTER TABLE users DROP COLUMN tmp_flag")
	}()
}`,
		},
		{
			name: "benchmark is checked too",
			code: `package tests

import "testing"

func BenchmarkScan(b *testing.B) {
	db.MustExec("CREATE INDEX idx_probe ON users (email)")
}`,
			expect: true,
		},
	}...)

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

import "testing"

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

// A test whose database the project creates for it and drops on cleanup
// (through a chain of helpers) changes nothing the next run sees; a database
// handed out by a pool is reused, and the change is still reported.
func TestSchemaMutationWithoutCleanupRule_DisposableDatabase(t *testing.T) {
	files := map[string]string{
		"internal/testdb/testdb.go": `package testdb

import (
	"fmt"
	"testing"
)

func NewDSN(t *testing.T) string {
	name := uniqueName(t)
	admin.Exec(fmt.Sprintf("CREATE DATABASE %s TEMPLATE app_test_template", name))
	t.Cleanup(func() { dropDB(name) })
	return dsnFor(name)
}

func Connect(t *testing.T) *Pool { return open(NewDSN(t)) }
`,
		"internal/storage/storage_test.go": `package storage

import (
	"testing"

	"example.com/app/internal/testdb"
)

func testDB(t *testing.T) *Postgres { return &Postgres{Pool: testdb.Connect(t)} }

func TestSchemaBehind(t *testing.T) {
	db := testDB(t)
	db.Pool.Exec(ctx, "ALTER TABLE projects DROP COLUMN legacy_flag")
}
`,
		"tests/pool_test.go": `package tests

import "testing"

func createStoreFromSeed(t *testing.T) string {
	admin.Exec(fmt.Sprintf("CREATE DATABASE %s TEMPLATE tmpl", name(t)))
	return name(t)
}

func TestPooled(t *testing.T) {
	db := takeFromPool(t)
	db.MustExec("ALTER TABLE vault_snapshots ADD COLUMN probe TEXT")
}
`,
	}
	rule := NewTestSchemaMutationWithoutCleanupRule()
	var contexts []*core.FileContext
	for path, code := range files {
		contexts = append(contexts, rulestest.InMemoryFileContext(t, path, code))
	}
	rule.UseProjectFiles(contexts)
	var found []string
	for _, ctx := range contexts {
		for _, v := range rule.AnalyzeFile(ctx) {
			found = append(found, v.File)
		}
	}
	assert.Equal(t, []string{"tests/pool_test.go"}, found)
}

// A database from graft's testdb (Connect, NewDSN) is a copy of a template
// made for the test and dropped on cleanup, though the package lives outside
// the project. It is told by its import path, not by its name: the project's
// own testdb package with a Connect that hands out a shared pool does not
// make a test's database disposable.
func TestSchemaMutationWithoutCleanupRule_GraftTestDatabase(t *testing.T) {
	files := map[string]string{
		"internal/admin/env_test.go": `package admin

import (
	"testing"

	graftdb "github.com/aiseeq/graft/v2/testdb"
)

func setupEnv(t *testing.T) *Env { return &Env{Pool: graftdb.Connect(t)} }

func rawDSN(t *testing.T) string { return graftdb.NewDSN(t) }
`,
		"internal/admin/admin_test.go": `package admin

import "testing"

func TestBrokenTable(t *testing.T) {
	env := setupEnv(t)
	env.Pool.Exec(ctx, "ALTER TABLE projects RENAME TO projects_unreadable")
}

func TestBrokenDSN(t *testing.T) {
	db := open(rawDSN(t))
	db.Exec("DROP TABLE projects")
}
`,
		"internal/shared/shared_test.go": `package shared

import (
	"testing"

	"example.com/app/internal/testdb"
)

func TestSharedPool(t *testing.T) {
	pool := testdb.Connect(t)
	pool.Exec(ctx, "ALTER TABLE projects ADD COLUMN probe TEXT")
}
`,
	}
	rule := NewTestSchemaMutationWithoutCleanupRule()
	var contexts []*core.FileContext
	for path, code := range files {
		contexts = append(contexts, rulestest.InMemoryFileContext(t, path, code))
	}
	rule.UseProjectFiles(contexts)
	var found []string
	for _, ctx := range contexts {
		for _, v := range rule.AnalyzeFile(ctx) {
			found = append(found, v.File)
		}
	}
	assert.Equal(t, []string{"internal/shared/shared_test.go"}, found)
}
