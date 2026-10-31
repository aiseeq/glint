package deadcode

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// A body that answers with fixed values and says in a comment that it is a
// stub: zeros, an empty list, a validation that always passes.
func TestNilReturnStubReportsCommentedConstantAnswer(t *testing.T) {
	code := `package svc

type Result struct{ IsValid bool }

type Item struct{}

type Repo struct{}

func (r *Repo) CountMembers(period string) (int64, error) {
	// DEVELOPMENT STAGE: returning 0 for compatibility
	return 0, nil
}

func (r *Repo) ListWidgetRows(limit int) ([]Item, int64, error) {
	// Simplified implementation for the MVP
	return []Item{}, 0, nil
}

func (r *Repo) ValidateItemAmount(amount int64) *Result {
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
	assert.Equal(t, []int{11, 16, 21}, rulestest.GoFileRuleLines(t, NewNilReturnStubRule(), "svc/svc.go", code))
}

// A write method whose whole body is return nil loses the write; a null
// object says so by its name.
func TestNilReturnStubReportsWriteThatDoesNothing(t *testing.T) {
	code := `package svc

type Adapter struct{}

func (a *Adapter) UpdateItemStatus(id, status string) error {
	return nil
}

func (a *Adapter) SaveSnapshot(id string) error {
	_ = id
	return nil
}

type NopStore struct{}

func (NopStore) UpdateItemStatus(id, status string) error { return nil }

func (a *Adapter) Close() error {
	return nil
}
`
	assert.Equal(t, []int{5, 9}, rulestest.GoFileRuleLines(t, NewNilReturnStubRule(), "svc/svc.go", code))
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
	assert.Equal(t, []int{9}, rulestest.GoFileRuleLines(t, NewNilReturnStubRule(), "svc/svc.go", code))
}

// A handler that answers with a success it did not produce and says so.
func TestNilReturnStubReportsStubSuccessResponse(t *testing.T) {
	code := `package svc

import "net/http"

func SendItemSuccess(w http.ResponseWriter, data any, msg string) {}

type Router struct{}

func (r *Router) handleGetItemAddress(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("user")
	_ = userID
	SendItemSuccess(w, map[string]any{"depositAddress": "0x0000000000000000000000000000000000000000"}, "Deposit address stub")
}

func (r *Router) handleStatusProbe(w http.ResponseWriter, req *http.Request) {
	SendItemSuccess(w, map[string]any{"status": "ok"}, "healthy")
}
`
	assert.Equal(t, []int{12}, rulestest.GoFileRuleLines(t, NewNilReturnStubRule(), "svc/svc.go", code))
}
