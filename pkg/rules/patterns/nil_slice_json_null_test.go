package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A list read from the database starts as a nil slice; with no rows it stays
// nil and the response carries "entries": null to a client that iterates it.
func TestNilSliceJSONNull(t *testing.T) {
	violations, err := NewNilSliceJSONNullRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"store/store.go": `package store

import "context"

type Entry struct{ ID string }

type DB struct{}

func (d *DB) SelectContext(ctx context.Context, dest any, query string, args ...any) error { return nil }

type Rows struct{}

func (r *Rows) Next() bool { return false }

func (r *Rows) Err() error { return nil }

type Repo struct{ db *DB }

func (r *Repo) ListEntries(ctx context.Context) ([]Entry, error) {
	var entries []Entry
	if err := r.db.SelectContext(ctx, &entries, "SELECT id FROM entries"); err != nil {
		return nil, err
	}
	return entries, nil
}

func (r *Repo) ListAddresses(ctx context.Context, rows *Rows) ([]string, error) {
	var out []string
	for rows.Next() {
		out = append(out, "addr")
	}
	return out, rows.Err()
}

func (r *Repo) ListPatched(ctx context.Context) ([]Entry, error) {
	var entries []Entry
	if err := r.db.SelectContext(ctx, &entries, "SELECT id FROM entries"); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		entries = []Entry{}
	}
	return entries, nil
}

func (r *Repo) ListMade(rows *Rows) []Entry {
	out := make([]Entry, 0)
	for rows.Next() {
		out = append(out, Entry{})
	}
	return out
}

func (r *Repo) ListConverted(rows *Rows) []Entry {
	var out []Entry
	for rows.Next() {
		out = append(out, Entry{})
	}
	return out
}

func (r *Repo) ListOmitted(rows *Rows) []Entry {
	var out []Entry
	for rows.Next() {
		out = append(out, Entry{})
	}
	return out
}
`,
		"api/api.go": `package api

import (
	"context"
	"encoding/json"
	"net/http"

	"example.com/rulestest/store"
)

type AddressLister interface {
	ListAddresses(ctx context.Context, rows *store.Rows) ([]string, error)
}

type Service struct{ lister AddressLister }

func (s *Service) Addresses(ctx context.Context) ([]string, error) {
	return s.lister.ListAddresses(ctx, &store.Rows{})
}

var _ AddressLister = (*store.Repo)(nil)

type entriesResponse struct {
	Entries []store.Entry ` + "`json:\"entries\"`" + `
	Older   []store.Entry ` + "`json:\"older,omitempty\"`" + `
}

type itemsResponse struct {
	Items []string ` + "`json:\"items\"`" + `
}

func writeJSON(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

type Handler struct {
	repo *store.Repo
	svc  *Service
}

func (h *Handler) entries(w http.ResponseWriter, r *http.Request) {
	entries, err := h.repo.ListEntries(r.Context())
	if err != nil {
		return
	}
	writeJSON(w, entriesResponse{Entries: entries})
}

func (h *Handler) addresses(w http.ResponseWriter, r *http.Request) {
	addresses, err := h.svc.Addresses(r.Context())
	if err != nil {
		return
	}
	writeJSON(w, map[string]any{"addresses": addresses})
}

func (h *Handler) patched(w http.ResponseWriter, r *http.Request) {
	entries, _ := h.repo.ListPatched(r.Context())
	writeJSON(w, entriesResponse{Entries: entries})
}

func (h *Handler) made(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, entriesResponse{Entries: h.repo.ListMade(&store.Rows{})})
}

func (h *Handler) converted(w http.ResponseWriter, r *http.Request) {
	items := h.repo.ListConverted(&store.Rows{})
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.ID)
	}
	writeJSON(w, itemsResponse{Items: names})
}

func (h *Handler) omitted(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, entriesResponse{Older: h.repo.ListOmitted(&store.Rows{})})
}

func (h *Handler) guarded(w http.ResponseWriter, r *http.Request) {
	addresses, _ := h.svc.Addresses(r.Context())
	if addresses == nil {
		addresses = []string{}
	}
	writeJSON(w, map[string]any{"addresses": addresses})
}

func (h *Handler) checks(w http.ResponseWriter, r *http.Request) {
	var checks []string
	checks = append(checks, "orphans")
	checks = append(checks, "balances")
	writeJSON(w, itemsResponse{Items: checks})
}

func (h *Handler) looped(w http.ResponseWriter, r *http.Request) {
	var names []string
	for _, entry := range h.repo.ListMade(&store.Rows{}) {
		names = append(names, entry.ID)
	}
	writeJSON(w, itemsResponse{Items: names})
}

func measure(h *Handler) int {
	data, _ := json.Marshal(h.repo.ListOmitted(&store.Rows{}))
	return len(data)
}
`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"api/api.go:93", "store/store.go:20", "store/store.go:28"}, foundLines(violations))
}
