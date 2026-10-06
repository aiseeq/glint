package patterns

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func validationServerErrorFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewValidationErrorAnsweredAsServerErrorRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

// A service that refuses an input with a plain error, behind a handler
// whose mapper knows only the not-found and conflict sentinels and answers
// the rest with 500: the client's invalid input is a server failure.
func TestValidationErrorAnsweredAsServerError(t *testing.T) {
	assert.Equal(t, []string{"api/api.go:44", "api/api.go:68"}, validationServerErrorFindings(t, map[string]string{
		"store/store.go": `package store

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid item")
)

type Item struct {
	ID       string
	Name     string
	Category string
}

func (s *Service) Update(ctx context.Context, item *Item) error {
	if item.ID == "" {
		return fmt.Errorf("item id is required")
	}
	return nil
}

type Service struct{ limit int }

func (s *Service) Import(ctx context.Context, item *Item) error {
	if s.limit == 0 {
		return fmt.Errorf("import limit is required")
	}
	if item == nil {
		return fmt.Errorf("item is required")
	}
	return nil
}

func (s *Service) Create(ctx context.Context, item *Item) error {
	if item.Name == "" {
		return fmt.Errorf("item name is required")
	}
	return nil
}

func (s *Service) CreateChecked(ctx context.Context, item *Item) error {
	if item.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	return nil
}

func (s *Service) Rebuild(ctx context.Context, portfolioID string, apply bool) error {
	if portfolioID == "" {
		return fmt.Errorf("portfolio id is required")
	}
	return nil
}

func validateItem(item Item) error {
	if item.Category == "" {
		return fmt.Errorf("category is required")
	}
	return nil
}

func (s *Service) Save(ctx context.Context, item Item) error {
	if err := validateItem(item); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("item id is required")
	}
	return nil
}

func (s *Service) Load(ctx context.Context, id string) (*Item, error) {
	if id == "x" {
		return nil, fmt.Errorf("item %s: %w", id, ErrNotFound)
	}
	return &Item{}, nil
}
`,
		"api/api.go": `package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"example.com/rulestest/store"
)

type Router struct{ service *store.Service }

func sendInternalServerError(w http.ResponseWriter, message string) {
	http.Error(w, message, http.StatusInternalServerError)
}

func writeItemError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if errors.Is(err, store.ErrConflict) {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}
	sendInternalServerError(w, err.Error())
}

func sendWriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrInvalid) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeItemError(w, err)
}

func (r *Router) Create(w http.ResponseWriter, req *http.Request) {
	var item store.Item
	if err := json.NewDecoder(req.Body).Decode(&item); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := r.service.Create(req.Context(), &item); err != nil {
		writeItemError(w, err)
		return
	}
}

func (r *Router) CreateChecked(w http.ResponseWriter, req *http.Request) {
	var item store.Item
	if err := json.NewDecoder(req.Body).Decode(&item); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := r.service.CreateChecked(req.Context(), &item); err != nil {
		sendWriteError(w, err)
		return
	}
}

func (r *Router) CreateViaWriteMapper(w http.ResponseWriter, req *http.Request) {
	var item store.Item
	if err := json.NewDecoder(req.Body).Decode(&item); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := r.service.Create(req.Context(), &item); err != nil {
		sendWriteError(w, err)
		return
	}
}

func (r *Router) Import(w http.ResponseWriter, req *http.Request) {
	var item store.Item
	if err := json.NewDecoder(req.Body).Decode(&item); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := r.service.Import(req.Context(), &item); err != nil {
		writeItemError(w, err)
		return
	}
}

func (r *Router) Update(w http.ResponseWriter, req *http.Request) {
	var item store.Item
	if err := json.NewDecoder(req.Body).Decode(&item); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	item.ID = req.PathValue("id")
	if err := r.service.Update(req.Context(), &item); err != nil {
		writeItemError(w, err)
		return
	}
}

func (r *Router) Rebuild(w http.ResponseWriter, req *http.Request) {
	var body struct {
		PortfolioID string
		Apply       bool
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if body.PortfolioID == "" {
		http.Error(w, "portfolio id is required", http.StatusBadRequest)
		return
	}
	if err := r.service.Rebuild(req.Context(), body.PortfolioID, body.Apply); err != nil {
		writeItemError(w, err)
		return
	}
}

func (r *Router) Save(w http.ResponseWriter, req *http.Request) {
	var item store.Item
	if err := json.NewDecoder(req.Body).Decode(&item); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	err := r.service.Save(req.Context(), item)
	if errors.Is(err, store.ErrInvalid) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		writeItemError(w, err)
		return
	}
}

func (r *Router) Delete(w http.ResponseWriter, req *http.Request) {
	if err := r.service.Delete(req.Context(), req.URL.Query().Get("id")); err != nil {
		writeItemError(w, err)
		return
	}
}

func (r *Router) Load(w http.ResponseWriter, req *http.Request) {
	if _, err := r.service.Load(req.Context(), req.URL.Query().Get("id")); err != nil {
		writeItemError(w, err)
		return
	}
}
`,
	}))
}
