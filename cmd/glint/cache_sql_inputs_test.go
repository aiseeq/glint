package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/dbrules"
	"github.com/stretchr/testify/require"
)

const sqlCacheSchema = `CREATE TABLE journals (id UUID PRIMARY KEY, status TEXT NOT NULL);
CREATE TABLE postings (id UUID PRIMARY KEY, journal_id UUID NOT NULL REFERENCES journals(id), account TEXT, amount NUMERIC);`

const sqlCacheTotal = "package repo\nfunc total() { _ = `SELECT account, SUM(amount) FROM postings GROUP BY account` }\n"
const sqlCacheFilter = "package repo\nfunc live() { _ = `SELECT p.* FROM postings p JOIN journals j ON j.id = p.journal_id WHERE j.status <> 'reversed'` }\n"

type countedSQLChildRule struct {
	*dbrules.SQLChildRowsIncludeVoidedParentRule
	indexes, calls int
}

func (r *countedSQLChildRule) UseProjectFiles(files []*core.FileContext) {
	r.indexes++
	r.SQLChildRowsIncludeVoidedParentRule.UseProjectFiles(files)
}

func (r *countedSQLChildRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	r.calls++
	return r.SQLChildRowsIncludeVoidedParentRule.AnalyzeFile(ctx)
}

func TestSQLChildScopedCache(t *testing.T) {
	if root := os.Getenv("GLINT_SQL_SCOPED_TEST_ROOT"); root != "" {
		t.Setenv("GLINT_CACHE_DIR", filepath.Join(root, "cache"))
		var files []*core.FileContext
		for _, name := range []string{"total.go", "filter.go"} {
			path := filepath.Join(root, name)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			files = append(files, core.NewFileContext(path, root, data, core.DefaultConfig()))
		}
		require.NoError(t, core.ParseGoFiles(root, files, false))
		cfg := core.DefaultConfig()
		cache := openRootCache(root, []string{files[0].Path}, cfg, false)
		require.NotNil(t, cache)
		rule := &countedSQLChildRule{SQLChildRowsIncludeVoidedParentRule: dbrules.NewSQLChildRowsIncludeVoidedParentRule()}
		rootRules := []rules.Rule{rule}
		found, panics, err := analyzeProjectContained(files[:1], files, []rules.Rule{rule}, rootRules, cfg, nil, cache)
		require.NoError(t, err)
		require.Empty(t, panics)
		require.NoError(t, cache.save())
		uncached := runIndexedUncached(t, dbrules.NewSQLChildRowsIncludeVoidedParentRule(), files, files[:1])
		require.Equal(t, fingerprint(uncached), fingerprint(found))
		require.NoError(t, os.WriteFile(filepath.Join(root, "result"), []byte{byte(len(found)), byte(rule.indexes), byte(rule.calls)}, 0o600))
		return
	}
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "migrations"), 0o700))
	write := func(path, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(root, path), []byte(content), 0o600))
	}
	write("total.go", sqlCacheTotal)
	write("filter.go", sqlCacheFilter)
	write("migrations/001.up.sql", sqlCacheSchema)
	run := func(want []byte) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSQLChildScopedCache$")
		cmd.Env = append(os.Environ(), "GLINT_SQL_SCOPED_TEST_ROOT="+root)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		got, err := os.ReadFile(filepath.Join(root, "result"))
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	run([]byte{1, 1, 1})
	run([]byte{1, 0, 0})
	write("migrations/001.up.sql", "CREATE TABLE other (id int);")
	run([]byte{0, 1, 1})
}

func TestSQLChildInvalidInputsNeverCacheFindings(t *testing.T) {
	root, dir := t.TempDir(), t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "migrations"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "migrations", "001.up.sql"), []byte("CREATE TABLE broken ("), 0o600))
	path := filepath.Join(root, "stats.go")
	content := []byte("package repo\nfunc f() { _ = `SELECT COUNT(*) FILTER (WHERE status = 'failed'), SUM(amount) FROM orders` }\n")
	ctx := core.NewFileContext(path, root, content, core.DefaultConfig())
	require.NoError(t, core.ParseGoFiles(root, []*core.FileContext{ctx}, false))
	files := []*core.FileContext{ctx}
	for range 2 {
		rule := &countedSQLChildRule{SQLChildRowsIncludeVoidedParentRule: dbrules.NewSQLChildRowsIncludeVoidedParentRule()}
		found := runIndexedCachedRoot(t, dir, root, rule, files, files)
		require.Len(t, found, 1)
		require.Equal(t, 1, rule.indexes)
		require.Equal(t, 1, rule.calls)
		cache, err := openResultCache(dir, root, "", "build", "stamp")
		require.NoError(t, err)
		cache.keyProject("test-inputs", nil, []rules.Rule{rule}, "")
		require.NotNil(t, cache.previousProject)
		require.NotContains(t, cache.previousProject.RootRules, rule.Name())
		require.NotContains(t, cache.previousProject.RootViolations, rule.Name())
	}
}

// Each child is a fresh analysis process with its own schema snapshot.
func TestSQLChildCacheInputsInvalidation(t *testing.T) {
	if root := os.Getenv("GLINT_SQL_CACHE_TEST_ROOT"); root != "" {
		var files []*core.FileContext
		for _, name := range []string{"total.go", "filter.go"} {
			path := filepath.Join(root, name)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			files = append(files, core.NewFileContext(path, root, data, core.DefaultConfig()))
		}
		require.NoError(t, core.ParseGoFiles(root, files, false))
		found := runIndexedCachedRoot(t, filepath.Join(root, "cache"), root, dbrules.NewSQLChildRowsIncludeVoidedParentRule(), files, files)
		require.NoError(t, os.WriteFile(filepath.Join(root, "result"), []byte{byte(len(found))}, 0o600))
		return
	}
	root := t.TempDir()
	migrationDir := filepath.Join(root, "migrations")
	require.NoError(t, os.Mkdir(migrationDir, 0o700))
	write := func(path, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(root, path), []byte(content), 0o600))
	}
	write("total.go", sqlCacheTotal)
	write("filter.go", "package repo\n")
	write("migrations/001.up.sql", sqlCacheSchema)
	run := func(want byte) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSQLChildCacheInputsInvalidation$")
		cmd.Env = append(os.Environ(), "GLINT_SQL_CACHE_TEST_ROOT="+root)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		got, err := os.ReadFile(filepath.Join(root, "result"))
		require.NoError(t, err)
		require.Equal(t, []byte{want}, got)
	}
	run(0)
	run(0)
	write("filter.go", sqlCacheFilter)
	run(1)
	require.NoError(t, os.Remove(filepath.Join(migrationDir, "001.up.sql")))
	run(0)
	write("migrations/001.up.sql", sqlCacheSchema)
	run(1)
	write("migrations/001.up.sql", "CREATE TABLE other (id int);")
	run(0)
}

func TestSQLChildCacheInputsSnapshot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "migrations"), 0o700))
	path := filepath.Join(root, "migrations", "001.up.sql")
	require.NoError(t, os.WriteFile(path, []byte(sqlCacheSchema), 0o600))
	rule := dbrules.NewSQLChildRowsIncludeVoidedParentRule()
	before, err := rule.CacheInputs(root)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("CREATE TABLE other (id int);"), 0o600))
	after, err := rule.CacheInputs(root)
	require.NoError(t, err)
	require.Equal(t, before, after)
	otherRoot := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(otherRoot, "migrations"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(otherRoot, "migrations", "001.up.sql"), []byte("CREATE TABLE other (id int);"), 0o600))
	changed, err := dbrules.NewSQLChildRowsIncludeVoidedParentRule().CacheInputs(otherRoot)
	require.NoError(t, err)
	require.NotEqual(t, before, changed)
}
