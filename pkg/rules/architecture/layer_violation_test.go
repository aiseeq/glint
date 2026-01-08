package architecture

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLayerViolationRule_Metadata(t *testing.T) {
	rule := NewLayerViolationRule()

	assert.Equal(t, "layer-violation", rule.Name())
	assert.Equal(t, "architecture", rule.Category())
	assert.Equal(t, core.SeverityCritical, rule.DefaultSeverity())
}

func TestLayerViolationRule_DetermineLayer(t *testing.T) {
	rule := NewLayerViolationRule()

	tests := []struct {
		path     string
		expected LayerType
	}{
		{"backend/handlers/user_handler.go", HandlerLayer},
		{"backend/shared/routing/admin_router.go", HandlerLayer},
		{"backend/shared/services/user_service.go", ServiceLayer},
		{"backend/auth/repository/auth_repository.go", RepositoryLayer},
		{"backend/models/user.go", UnknownLayer},
		{"backend/utils/helper.go", UnknownLayer},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := rule.determineLayer(tt.path)
			assert.Equal(t, tt.expected, result, "Path: %s", tt.path)
		})
	}
}

func TestLayerViolationRule_HandlerSQLViolation(t *testing.T) {
	rule := NewLayerViolationRule()

	// Create a simple Go file context with SQL in handler
	goCode := `package handlers

import "database/sql"

func GetUser(db *sql.DB) {
	db.Query("SELECT * FROM users")
}
`
	ctx := createTestContext(t, "backend/handlers/user_handler.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations, "Expected violation for SQL in handler")
	assert.Contains(t, violations[0].Message, "Handler")
	assert.Contains(t, violations[0].Message, "SQL")
}

func TestLayerViolationRule_ServiceSQLViolation(t *testing.T) {
	rule := NewLayerViolationRule()

	goCode := `package services

import "database/sql"

func GetUser(db *sql.DB) {
	db.Exec("DELETE FROM users WHERE id = 1")
}
`
	ctx := createTestContext(t, "backend/services/user_service.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations, "Expected violation for SQL in service")
	assert.Contains(t, violations[0].Message, "Service")
}

func TestLayerViolationRule_RepositorySQLAllowed(t *testing.T) {
	rule := NewLayerViolationRule()

	goCode := `package repository

import "database/sql"

func GetUser(db *sql.DB) {
	db.Query("SELECT * FROM users WHERE id = $1")
}
`
	ctx := createTestContext(t, "backend/repository/user_repository.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "SQL should be allowed in repository")
}

func TestLayerViolationRule_HandlerSQLStringViolation(t *testing.T) {
	rule := NewLayerViolationRule()

	goCode := `package handlers

func GetUser() {
	query := "SELECT id, name FROM users WHERE active = true"
	_ = query
}
`
	ctx := createTestContext(t, "backend/handlers/user_handler.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations, "Expected violation for SQL string in handler")
	assert.Contains(t, violations[0].Message, "SQL query")
}

func TestLayerViolationRule_NoFalsePositivesOnErrorMessages(t *testing.T) {
	rule := NewLayerViolationRule()

	goCode := `package handlers

func GetUser() {
	msg := "User not found in database"
	err := "Failed to select user"
	_ = msg
	_ = err
}
`
	ctx := createTestContext(t, "backend/handlers/user_handler.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Error messages should not trigger false positives")
}

func TestLayerViolationRule_TestFilesExcluded(t *testing.T) {
	rule := NewLayerViolationRule()

	goCode := `package handlers

import "database/sql"

func TestGetUser(db *sql.DB) {
	db.Query("SELECT * FROM users")
}
`
	ctx := createTestContext(t, "backend/handlers/user_handler_test.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

// Helper function to create test context with parsed Go AST
func createTestContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()

	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitLines(code),
		Content: []byte(code),
	}

	// Parse Go AST
	parser := core.NewParser()
	fset, ast, err := parser.ParseGoFile(path, []byte(code))
	if err != nil {
		t.Fatalf("Failed to parse Go code: %v", err)
	}
	ctx.SetGoAST(fset, ast)

	return ctx
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
