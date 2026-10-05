package architecture

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestLayerViolationRule_Metadata(t *testing.T) {
	rule := NewLayerViolationRule()

	assert.Equal(t, "layer-violation", rule.Name())
	assert.Equal(t, "architecture", rule.Category())
	assert.Equal(t, core.SeverityCritical, rule.DefaultSeverity())
}

func TestLayerViolationRule_DetermineLayer(t *testing.T) {
	tests := []struct {
		path     string
		expected LayerType
	}{
		{"backend/handlers/user_handler.go", HandlerLayer},
		{"backend/shared/routing/admin_router.go", HandlerLayer},
		{"backend/shared/services/user_service.go", ServiceLayer},
		{"backend/auth/repository/auth_repository.go", RepositoryLayer},
		{"backend/repo/user.go", RepositoryLayer},
		{"backend/repositories/user.go", RepositoryLayer},
		{"backend/storage/user_repo.go", RepositoryLayer},
		{"backend/models/user.go", UnknownLayer},
		{"backend/utils/helper.go", UnknownLayer},
		{"internal/reports/monthly.go", UnknownLayer},
		{"internal/reporting/export.go", UnknownLayer},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := determineLayerFromPath(tt.path)
			assert.Equal(t, tt.expected, result, "Path: %s", tt.path)
		})
	}
}

func analyzeLayers(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := NewLayerViolationRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

func TestLayerViolationRule_HandlerSQLViolation(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"backend/handlers/user_handler.go": `package handlers

import "database/sql"

func GetUser(db *sql.DB) {
	db.Query("SELECT * FROM users")
}
`})

	require.NotEmpty(t, violations, "Expected violation for SQL in handler")
	assert.Contains(t, violations[0].Message, "Handler")
	assert.Contains(t, violations[0].Message, "SQL")
}

func TestLayerViolationRule_ServiceSQLViolation(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"backend/services/user_service.go": `package services

import "database/sql"

func GetUser(db *sql.DB) {
	db.Exec("DELETE FROM users WHERE id = 1")
}
`})

	require.NotEmpty(t, violations, "Expected violation for SQL in service")
	assert.Contains(t, violations[0].Message, "Service")
}

// The database handle usually lives in a struct field; the receiver of the
// call is judged by its type, not by being spelled db.
func TestLayerViolationRule_ServiceSQLThroughField(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"internal/service/user.go": `package service

import (
	"context"
	"database/sql"
)

type Users struct{ store *sql.DB }

func (s *Users) Count(ctx context.Context, q string) (*sql.Rows, error) {
	return s.store.QueryContext(ctx, q)
}
`})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Service contains direct SQL call")
	assert.Contains(t, violations[0].Message, "QueryContext")
}

// A method named like a database call on a type that is not a database
// handle is not SQL.
func TestLayerViolationRule_IgnoresSQLNamedMethodOfOtherType(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"internal/service/cache.go": `package service

type memo struct{}

func (memo) Query(key string) string { return key }

func Lookup(db memo) string { return db.Query("k") }
`})

	assert.Empty(t, violations)
}

func TestLayerViolationRule_RepositorySQLAllowed(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"backend/repository/user_repository.go": `package repository

import "database/sql"

func GetUser(db *sql.DB) {
	db.Query("SELECT * FROM users WHERE id = $1")
}
`})

	assert.Empty(t, violations, "SQL should be allowed in repository")
}

// A getter whose name starts with HTTP is not an HTTP operation.
func TestLayerViolationRule_RepositoryGetterNamedHTTP(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"internal/repository/store.go": `package repository

import "time"

type Config struct{}

func (Config) HTTPTimeout() time.Duration { return time.Second }

type Store struct{ cfg Config }

func (s *Store) Timeout() time.Duration { return s.cfg.HTTPTimeout() }
`})

	assert.Empty(t, violations)
}

// Writing an HTTP response from the repository layer is an HTTP operation,
// whatever the writer variable is called.
func TestLayerViolationRule_RepositoryHTTPOperation(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"internal/repository/export.go": `package repository

import "net/http"

func Export(out http.ResponseWriter) {
	out.WriteHeader(http.StatusOK)
}
`})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Repository contains HTTP operation: WriteHeader")
}

// A production file whose name merely contains "test_" (latest_release.go)
// is not test infrastructure.
func TestLayerViolationRule_ChecksFileNamedLikeTestPrefix(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"internal/service/latest_release.go": `package service

import "database/sql"

func Release(db *sql.DB) {
	db.Exec("DELETE FROM releases WHERE id = 1")
}
`})

	assert.NotEmpty(t, violations)
}

func TestLayerViolationRule_HandlerSQLStringViolation(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"backend/handlers/user_handler.go": `package handlers

func GetUser() {
	query := "SELECT id, name FROM users WHERE active = true"
	_ = query
}
`})

	require.NotEmpty(t, violations, "Expected violation for SQL string in handler")
	assert.Contains(t, violations[0].Message, "SQL query")
}

// Without type information the SQL text is still SQL; a call is not judged.
func TestLayerViolationRule_UntypedFileKeepsSQLStringCheck(t *testing.T) {
	ctx := createTestContext(t, "backend/handlers/user_handler.go", `package handlers

func GetUser(db interface{ Query(string) }) {
	db.Query("SELECT id, name FROM users WHERE active = true")
}
`)
	violations := NewLayerViolationRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "SQL query")
}

func TestLayerViolationRule_NoFalsePositivesOnErrorMessages(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"backend/handlers/user_handler.go": `package handlers

func GetUser() {
	msg := "User not found in database"
	err := "Failed to select user"
	_ = msg
	_ = err
}
`})

	assert.Empty(t, violations, "Error messages should not trigger false positives")
}

func TestLayerViolationRule_TestFilesExcluded(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{
		"backend/handlers/user_handler.go": "package handlers\n",
		"backend/handlers/user_handler_test.go": `package handlers

import (
	"database/sql"
	"testing"
)

func TestGetUser(t *testing.T) {
	var db *sql.DB
	db.Query("SELECT * FROM users")
}
`,
	})

	assert.Empty(t, violations, "Test files should be excluded")
}

func TestLayerViolationRule_ReportsPackageNotRepository(t *testing.T) {
	// "reports" contains "repo" as a substring but is not a repository package
	violations := analyzeLayers(t, map[string]string{"internal/reports/render.go": `package reports

import "net/http"

func Render(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
}
`})

	assert.Empty(t, violations, "reports package must not be classified as repository layer")
}

// A health check asks the server for a scalar to prove the connection works:
// the query reads no table, so there is nothing a repository would own.
func TestLayerViolationRule_TablelessProbeQueryIsNotDataAccess(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"internal/services/health/health.go": `package health

import (
	"context"
	"database/sql"
	"time"
)

type Checker struct{ db *sql.DB }

func (c *Checker) ServerTime(ctx context.Context) (time.Time, error) {
	var now time.Time
	err := c.db.QueryRowContext(ctx, "SELECT NOW()").Scan(&now)
	return now, err
}

const pingQuery = "SELECT 1"

func (c *Checker) Ping(ctx context.Context) error {
	var one int
	return c.db.QueryRowContext(ctx, pingQuery).Scan(&one)
}
`})

	assert.Empty(t, violations)
}

// A constant query that reads tables stays a violation however it starts —
// a CTE opens with WITH, not SELECT — and so does a query whose text is not
// known.
func TestLayerViolationRule_QueryReadingTablesInService(t *testing.T) {
	violations := analyzeLayers(t, map[string]string{"internal/services/stats/stats.go": `package stats

import (
	"context"
	"database/sql"
)

type Service struct{ db *sql.DB }

func (s *Service) Active(ctx context.Context) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, ` + "`" + `
		WITH recent AS (SELECT account_id FROM events)
		SELECT account_id, COUNT(*) FROM recent GROUP BY account_id` + "`" + `)
}

func (s *Service) Stamp(ctx context.Context) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, "SELECT NOW() FROM ledger")
}

func (s *Service) Run(ctx context.Context, q string) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, q)
}

func (s *Service) Settle(ctx context.Context) *sql.Row {
	return s.db.QueryRowContext(ctx, "SELECT settle_pending_batches()")
}
`})

	lines := make([]int, 0, len(violations))
	for _, v := range violations {
		if v.Context["pattern"] == "direct_sql_call" {
			lines = append(lines, v.Line)
		}
	}
	assert.Equal(t, []int{11, 17, 21, 25}, lines, "a stored function called through SELECT is data access")
}

// Helper function to create test context with parsed Go AST
func createTestContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()

	return rulestest.InMemoryGoFile(t, "/"+path, "/", code, nil)
}
