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

// A list left nil reaches the client by three more roads: an argument of the
// handler's own JSON helper, an exported field without a json tag in a
// response type, and a field of the response filled only by append in a
// loop.
func TestNilSliceJSONNullResponseShapes(t *testing.T) {
	violations, err := NewNilSliceJSONNullRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"api/api.go": `package api

import (
	"encoding/json"
	"net/http"
)

type Device struct{ Name string }

type securityResponse struct {
	Enabled bool ` + "`json:\"enabled\"`" + `
	Devices []Device
	Methods []string ` + "`json:\"methods\"`" + `
}

// plain is not a JSON type: no field of it has a json tag.
type plain struct {
	Devices []Device
}

type Handler struct{ devices []Device }

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	var names []string
	for _, d := range h.devices {
		names = append(names, d.Name)
	}
	respondJSON(w, http.StatusOK, names)
}

func (h *Handler) listMade(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(h.devices))
	for _, d := range h.devices {
		names = append(names, d.Name)
	}
	respondJSON(w, http.StatusOK, names)
}

func (h *Handler) security(w http.ResponseWriter, r *http.Request) {
	var devices []Device
	for _, d := range h.devices {
		devices = append(devices, d)
	}
	respondJSON(w, http.StatusOK, securityResponse{Enabled: true, Devices: devices, Methods: []string{}})
}

func (h *Handler) methods(w http.ResponseWriter, r *http.Request) {
	resp := securityResponse{Enabled: true, Devices: []Device{}}
	for _, d := range h.devices {
		resp.Methods = append(resp.Methods, d.Name)
	}
	respondJSON(w, http.StatusOK, resp)
}

func (h *Handler) methodsMade(w http.ResponseWriter, r *http.Request) {
	resp := securityResponse{Devices: []Device{}, Methods: []string{}}
	for _, d := range h.devices {
		resp.Methods = append(resp.Methods, d.Name)
	}
	respondJSON(w, http.StatusOK, resp)
}

// Config hides its secret from a dump; it is not a payload.
type Config struct {
	APIKey  string ` + "`json:\"-\"`" + `
	Sources []string
}

func loadConfig(env []string) Config {
	var sources []string
	for _, s := range env {
		sources = append(sources, s)
	}
	return Config{Sources: sources}
}

func (h *Handler) internal() plain {
	var devices []Device
	for _, d := range h.devices {
		devices = append(devices, d)
	}
	return plain{Devices: devices}
}
`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"api/api.go:29", "api/api.go:45", "api/api.go:53"}, foundLines(violations))
}

// Repro from a real project: the handler answered through a generic helper
// that wrapped the list into the response envelope (Data: dataPtr(data)) and
// passed the envelope to the helper that encodes it - an empty table sent
// "data": null and the admin page failed on null.filter.
func TestNilSliceJSONNullThroughEnvelopeHelper(t *testing.T) {
	violations, err := NewNilSliceJSONNullRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"store/store.go": `package store

import "context"

type Hold struct{ ID int }

type DB struct{}

func (d *DB) SelectContext(ctx context.Context, dest any, query string) error { return nil }

type Repo struct{ db *DB }

func (r *Repo) ListAll(ctx context.Context) ([]Hold, error) {
	var holds []Hold
	if err := r.db.SelectContext(ctx, &holds, "SELECT 1"); err != nil {
		return nil, err
	}
	return holds, nil
}

func (r *Repo) ListFresh(ctx context.Context) ([]Hold, error) {
	holds := []Hold{}
	if err := r.db.SelectContext(ctx, &holds, "SELECT 1"); err != nil {
		return nil, err
	}
	return holds, nil
}
`,
		"web/web.go": `package web

import (
	"encoding/json"
	"net/http"
)

type Response[T any] struct {
	Success bool ` + "`json:\"success\"`" + `
	Data    *T   ` + "`json:\"data,omitempty\"`" + `
}

func dataPtr[T any](data T) *T { return &data }

func write[T any](w http.ResponseWriter, response Response[T]) {
	_ = json.NewEncoder(w).Encode(response)
}

type Response2[T any] struct {
	Data    *T     ` + "`json:\"data,omitempty\"`" + `
	Message string ` + "`json:\"message,omitempty\"`" + `
}

func write2[T any](w http.ResponseWriter, response Response2[T]) {
	_ = json.NewEncoder(w).Encode(response)
}

func ReplyOK[T any](w http.ResponseWriter, data T, message string) {
	write2(w, Response2[T]{Data: dataPtr(data), Message: message})
}

func SendCount(w http.ResponseWriter, data []int) {
	write(w, Response[int]{Success: true, Data: dataPtr(len(data))})
}
`,
		"api/api.go": `package api

import (
	"net/http"

	"example.com/rulestest/store"
	"example.com/rulestest/web"
)

type Service struct{ repo *store.Repo }

func (s *Service) List(r *http.Request) ([]store.Hold, error) {
	holds, err := s.repo.ListAll(r.Context())
	if err != nil {
		return nil, err
	}
	return holds, nil
}

func (s *Service) HandleList(w http.ResponseWriter, r *http.Request) {
	holds, err := s.List(r)
	if err != nil {
		return
	}
	web.ReplyOK(w, holds, "")
}

func (s *Service) HandleFresh(w http.ResponseWriter, r *http.Request) {
	holds, err := s.repo.ListFresh(r.Context())
	if err != nil {
		return
	}
	web.ReplyOK(w, holds, "")
}
`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"store/store.go:14"}, foundLines(violations))
}
