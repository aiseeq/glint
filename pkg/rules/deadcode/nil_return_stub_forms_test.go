package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func nilReturnStubLines(t *testing.T, code string) []int {
	t.Helper()
	var lines []int
	for _, v := range NewNilReturnStubRule().AnalyzeFile(parseGoContext(t, "svc.go", code)) {
		lines = append(lines, v.Line)
	}
	return lines
}

// A body that answers with fixed values and says in a comment that it is a
// stub: zeros, an empty list, a validation that always passes.
func TestNilReturnStubReportsCommentedConstantAnswer(t *testing.T) {
	code := `package svc

type Result struct{ IsValid bool }

type Item struct{}

type Repo struct{}

func (r *Repo) CountUsers(period string) (int64, error) {
	// DEVELOPMENT STAGE: returning 0 for compatibility
	return 0, nil
}

func (r *Repo) ListWithdrawals(limit int) ([]Item, int64, error) {
	// Simplified implementation for the MVP
	return []Item{}, 0, nil
}

func (r *Repo) ValidateAmount(amount int64) *Result {
	// TEMPORARY IMPLEMENTATION
	return &Result{IsValid: true}
}

func (r *Repo) Limit() int {
	// The limit the provider documents.
	return 100
}

// ProviderType is required for interface compliance.
func (r *Repo) ProviderType() string {
	return "PROVIDER"
}
`
	assert.Equal(t, []int{11, 16, 21}, nilReturnStubLines(t, code))
}

// A write method whose whole body is return nil loses the write; a null
// object says so by its name.
func TestNilReturnStubReportsWriteThatDoesNothing(t *testing.T) {
	code := `package svc

type Adapter struct{}

func (a *Adapter) UpdateTransactionStatus(id, status string) error {
	return nil
}

func (a *Adapter) SaveSnapshot(id string) error {
	_ = id
	return nil
}

type NopStore struct{}

func (NopStore) UpdateTransactionStatus(id, status string) error { return nil }

func (a *Adapter) Close() error {
	return nil
}
`
	assert.Equal(t, []int{5, 9}, nilReturnStubLines(t, code))
}

// The real call left in a comment next to the value that replaced it.
func TestNilReturnStubReportsCommentedOutCall(t *testing.T) {
	code := `package svc

type Config interface{ Strategies() []string }

type Manager struct{ cfg Config }

func (m *Manager) Strategies() []string {
	if m.cfg != nil {
		return nil // m.cfg.Strategies()
	}
	return []string{"default"}
}

func (m *Manager) Name() string {
	return "" // empty until configured
}
`
	assert.Equal(t, []int{9}, nilReturnStubLines(t, code))
}

// A handler that answers with a success it did not produce and says so.
func TestNilReturnStubReportsStubSuccessResponse(t *testing.T) {
	code := `package svc

import "net/http"

func SendSuccess(w http.ResponseWriter, data any, msg string) {}

type Router struct{}

func (r *Router) handleGetDepositAddress(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("user")
	_ = userID
	SendSuccess(w, map[string]any{"depositAddress": "0x0000000000000000000000000000000000000000"}, "Deposit address stub")
}

func (r *Router) handleHealth(w http.ResponseWriter, req *http.Request) {
	SendSuccess(w, map[string]any{"status": "ok"}, "healthy")
}
`
	assert.Equal(t, []int{12}, nilReturnStubLines(t, code))
}
