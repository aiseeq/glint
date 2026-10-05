package patterns

import (
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A template with a fixed name copied from a source database chosen at run
// time: a run against another source reuses the template of the first.
func TestTestTemplateDBSharedAcrossSources(t *testing.T) {
	assert.Equal(t, []string{"tests/db_test.go:9"}, deployFindings(t, "test-template-db-shared-across-sources", map[string]string{
		"tests/db_test.go": `package tests

import "fmt"

const templateName = "app_test_template"

func templateSQL(cfg Config) []string {
	return []string{
		fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", templateName, cfg.DBName),
		fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", templateOf(cfg), cfg.DBName),
		fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", "copy_db", "app_test_template"),
		fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", cfg.TestDB, templateName),
	}
}
`,
	}))
}

// The trigger writes NOW() over the updated_at the fixture sets; the same
// write of NOW() and a table without the trigger are left out.
func TestTestFixtureWriteOverriddenByDBTrigger(t *testing.T) {
	_, contexts := rulestest.Module(t, map[string]string{
		"migrations/001_init.up.sql": syncMigrations,
		"repo/sync_test.go": "package repo\n\nfunc fixtures(db DB, id string) {\n" +
			"\tdb.Exec(`UPDATE batches SET updated_at = NOW() - INTERVAL '30 days' WHERE id = $1`, id)\n" +
			"\tdb.Exec(`UPDATE batches SET updated_at = NOW(), name = 'x' WHERE id = $1`, id)\n" +
			"\tdb.Exec(`UPDATE items SET updated_at = $2 WHERE id = $1`, id)\n" +
			"}\n\nfunc disabled(db DB, id string) {\n" +
			"\tdb.Exec(`ALTER TABLE batches DISABLE TRIGGER batches_touch`)\n" +
			"\tdefer db.Exec(`ALTER TABLE batches ENABLE TRIGGER batches_touch`)\n" +
			"\tdb.Exec(`UPDATE batches SET updated_at = NOW() - INTERVAL '1 day' WHERE id = $1`, id)\n" +
			"}\n\nfunc replica(tx DB, id string) {\n" +
			"\ttx.Exec(`SET LOCAL session_replication_role = 'replica'`)\n" +
			"\ttx.Exec(`UPDATE batches SET updated_at = $2 WHERE id = $1`, id)\n" +
			"}\n\nfunc enabledAfter(db DB, id string) {\n" +
			"\tdb.Exec(`UPDATE batches SET updated_at = $2 WHERE id = $1`, id)\n" +
			"\tdb.Exec(`ALTER TABLE batches DISABLE TRIGGER ALL`)\n" +
			"}\n",
		"repo/sync.go": "package repo\n\nfunc backfill(db DB) {\n" +
			"\tdb.Exec(`UPDATE batches SET updated_at = $1`)\n" +
			"}\n",
	})
	rule, ok := rules.Get("test-fixture-write-overridden-by-db-trigger")
	require.True(t, ok)
	var lines []int
	for _, ctx := range contexts {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, ctx.Path, ctx.Content, parser.ParseComments)
		require.NoError(t, err)
		ctx.SetGoAST(fset, file)
		for _, v := range rule.AnalyzeFile(ctx) {
			assert.Equal(t, "repo/sync_test.go", v.File)
			lines = append(lines, v.Line)
		}
	}
	assert.Equal(t, []int{4, 21}, lines)
}

const proxySignalHelper = `package client

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func searchServer(t *testing.T, hits *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("[]"))
	}))
}
`

// The counter rises when the request arrives; the test then reads the cache
// the client fills only after the answer is parsed.
func TestTestWaitsOnProxySignalNotCompletion(t *testing.T) {
	assert.Equal(t, []string{"client/warm_test.go:24", "client/warm_test.go:40"}, deployFindings(t, "test-waits-on-proxy-signal-not-completion", map[string]string{
		"client/warm_test.go": proxySignalHelper + `
func TestWarm(t *testing.T) {
	var hits atomic.Int64
	server := searchServer(t, &hits)
	defer server.Close()
	client := NewClient(server.URL)
	client.Warm()
	if !waitForCondition(func() bool { return hits.Load() > 0 }, 5*time.Second) {
		t.Fatal("no request")
	}
	records, err := client.Search()
	if err != nil || len(records) != 1 {
		t.Fatal(err)
	}
}

func TestInline(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	client := NewClient(server.URL)
	client.Warm()
	require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, 10*time.Millisecond)
	client.Search()
}
`,
	}))
	// The test ends at the wait, waits for the stored result, or counts in
	// the client.
	assert.Empty(t, deployFindings(t, "test-waits-on-proxy-signal-not-completion", map[string]string{
		"client/warm_test.go": proxySignalHelper + `
func TestDefers(t *testing.T) {
	var hits atomic.Int64
	server := searchServer(t, &hits)
	client := NewClient(server.URL)
	client.Warm()
	if !waitForCondition(func() bool { return hits.Load() > 0 }, 5*time.Second) {
		t.Fatal("no request")
	}
}

func TestCached(t *testing.T) {
	var hits atomic.Int64
	server := searchServer(t, &hits)
	client := NewClient(server.URL)
	client.Warm()
	if !waitForCondition(func() bool { return client.Cached() }, 5*time.Second) {
		t.Fatal("not warmed")
	}
	client.Search()
}

func TestLocal(t *testing.T) {
	var done atomic.Int64
	go func() { done.Add(1) }()
	waitForCondition(func() bool { return done.Load() > 0 }, time.Second)
	run()
}
`,
	}))
}

const cookieAuthServer = `package server

import "net/http"

func auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		next.ServeHTTP(w, r)
	})
}
`

// The server reads only the session cookie; the tests send a bearer header.
func TestTestAuthSchemeDrift(t *testing.T) {
	assert.Equal(t, []string{"backend/server/api_test.go:5", "frontend/e2e/tests/stats-api.spec.ts:5"}, deployFindings(t, "test-auth-scheme-drift", map[string]string{
		"backend/server/auth.go": cookieAuthServer,
		"backend/server/api_test.go": `package server

func request(token string) *http.Request {
	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}
`,
		"frontend/e2e/tests/stats-api.spec.ts": `let headers: Record<string, string>
test.beforeAll(async () => {
  const token = await signTestToken('admin@example.test')
  headers = {
    'Authorization': ` + "`Bearer ${token}`" + `,
  }
})
`,
		"frontend/src/api.ts": `const headers = { Authorization: ` + "`Bearer ${token}`" + ` }
`,
	}))
	// The server reads the header too (directly or by a constant), or has no
	// cookie authentication.
	for name, server := range map[string]string{
		"header": cookieAuthServer + `
func bearer(r *http.Request) string { return r.Header.Get("Authorization") }
`,
		"constant": cookieAuthServer + `
const headerAuth = "Authorization"

func bearer(r *http.Request) string { return r.Header.Get(headerAuth) }
`,
		"no cookie": `package server

func ping() {}
`,
	} {
		assert.Empty(t, deployFindings(t, "test-auth-scheme-drift", map[string]string{
			"backend/server/auth.go": server,
			"frontend/e2e/stats.spec.ts": `const headers = { Authorization: ` + "`Bearer ${token}`" + ` }
`,
		}), name)
	}
}
