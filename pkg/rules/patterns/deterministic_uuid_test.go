package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestDeterministicUUIDRule_Metadata(t *testing.T) {
	rule := NewDeterministicUUIDRule()
	assert.Equal(t, "deterministic-uuid", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestDeterministicUUIDRule(t *testing.T) {
	rule := NewDeterministicUUIDRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "generateDeterministicAdminUUID function",
			code: `package main

import "crypto/sha256"

func (am *Middleware) generateDeterministicAdminUUID(email string) string {
	hash := sha256.Sum256([]byte(email))
	adminUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return ""
	}
	return adminUUID.String()
}`,
			// func declaration + sha256.Sum256 + uuid.FromBytes = 3
			expectedCount: 3,
		},
		{
			name: "generateDeterministicUUID function with Sprintf",
			code: `package main

import "crypto/sha256"

func (s *Service) generateDeterministicUUID(email string) string {
	hash := sha256.Sum256([]byte(email))
	uuid := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
	return uuid
}`,
			// func declaration + sha256.Sum256 = 2
			expectedCount: 2,
		},
		{
			name: "admin-prefix string ID",
			code: `package main

func generateToken(email string) *Claims {
	return &Claims{
		AdminID: "admin-" + email,
		Subject: "admin-" + email,
	}
}`,
			expectedCount: 2,
		},
		{
			name: "fmt.Sprintf admin-ID pattern",
			code: `package main

func makeID(email string) string {
	return fmt.Sprintf("admin-%s", email)
}`,
			expectedCount: 1,
		},
		{
			name: "Clean code - no violations",
			code: `package main

import "github.com/google/uuid"

func getUser(db *sql.DB, email string) (string, error) {
	var id string
	err := db.QueryRow("SELECT id FROM users WHERE email = $1", email).Scan(&id)
	return id, err
}`,
			expectedCount: 0,
		},
		{
			name: "uuid.New is OK",
			code: `package main

import "github.com/google/uuid"

func createID() string {
	return uuid.New().String()
}`,
			expectedCount: 0,
		},
		{
			name: "sha256 not in UUID context is OK",
			code: `package main

import "crypto/sha256"

func hashPassword(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:]
}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/test/file.go", "/test", []byte(tt.code), core.DefaultConfig())

			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/test/file.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}

			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Test: %s\nCode: %s", tt.name, tt.code)
		})
	}
}

func TestDeterministicUUIDRule_NonGoFile(t *testing.T) {
	rule := NewDeterministicUUIDRule()
	ctx := core.NewFileContext("/test/file.ts", "/test", []byte("const id = 'admin-' + email"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)
	assert.Empty(t, violations)
}
