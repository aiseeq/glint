package httprules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Equal(t, []string{"api/api.go:93", "store/store.go:20", "store/store.go:28"}, patterntest.FoundLines(violations))
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
	assert.Equal(t, []string{"api/api.go:29", "api/api.go:45", "api/api.go:53"}, patterntest.FoundLines(violations))
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
	assert.Equal(t, []string{"store/store.go:14"}, patterntest.FoundLines(violations))
}

// nilSliceEnvelopeStore declares the nil lists the envelope tests answer
// with: holds at store/store.go:14, ids at store/store.go:22.
const nilSliceEnvelopeStore = `package store

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

func (r *Repo) ListIDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := r.db.SelectContext(ctx, &ids, "SELECT 1"); err != nil {
		return nil, err
	}
	return ids, nil
}
`

// nilSliceEnvelopeWeb is the head of the response package the envelope
// tests add their helpers to.
const nilSliceEnvelopeWeb = `package web

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

var _ = json.Marshal
`

// nilSliceEnvelopeFindings runs the rule on a handler that reads holds and
// ids and answers with the call through the response helpers of web.
func nilSliceEnvelopeFindings(t *testing.T, web, call string) []string {
	t.Helper()
	return nilSliceEnvelopeProject(t, map[string]string{
		"web/web.go": nilSliceEnvelopeWeb + web,
		"api/api.go": `package api

import (
	"net/http"

	"example.com/rulestest/store"
	"example.com/rulestest/web"
)

type Service struct{ repo *store.Repo }

func (s *Service) Handle(w http.ResponseWriter, r *http.Request) {
	holds, err := s.repo.ListAll(r.Context())
	if err != nil {
		return
	}
	ids, err := s.repo.ListIDs(r.Context())
	if err != nil {
		return
	}
	_, _ = holds, ids
	` + call + `
}
`,
	})
}

func nilSliceEnvelopeProject(t *testing.T, files map[string]string) []string {
	t.Helper()
	files["store/store.go"] = nilSliceEnvelopeStore
	violations, err := NewNilSliceJSONNullRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return patterntest.FoundLines(violations)
}

// A positional envelope literal sets the data field as the keyed one does.
func TestNilSliceJSONNullPositionalEnvelope(t *testing.T) {
	for name, literal := range map[string]string{
		"keyed":      "Response[T]{Success: true, Data: dataPtr(data)}",
		"positional": "Response[T]{true, dataPtr(data)}",
	} {
		t.Run(name, func(t *testing.T) {
			got := nilSliceEnvelopeFindings(t, `
func ReplyOK[T any](w http.ResponseWriter, data T) { write(w, `+literal+`) }
`, `web.ReplyOK(w, holds)`)
			assert.Equal(t, []string{"store/store.go:14"}, got)
		})
	}
}

// A helper encodes the message on its error path and the data on success,
// or two lists in one envelope: each parameter reaching the JSON is a
// payload, not only the first one found.
func TestNilSliceJSONNullEveryRespondedParam(t *testing.T) {
	t.Run("message encoded before the data", func(t *testing.T) {
		got := nilSliceEnvelopeFindings(t, `
func Reply(w http.ResponseWriter, data any, message string, failed bool) {
	if failed {
		_ = json.NewEncoder(w).Encode(message)
		return
	}
	_ = json.NewEncoder(w).Encode(data)
}
`, `web.Reply(w, holds, "", false)`)
		assert.Equal(t, []string{"store/store.go:14"}, got)
	})
	t.Run("message envelope before the data envelope", func(t *testing.T) {
		got := nilSliceEnvelopeFindings(t, `
type Resp struct {
	Data    *any   `+"`json:\"data,omitempty\"`"+`
	Message string `+"`json:\"message,omitempty\"`"+`
}

func writeResp(w http.ResponseWriter, r Resp) { _ = json.NewEncoder(w).Encode(r) }

func Reply(w http.ResponseWriter, data any, msg string) {
	if msg != "" {
		writeResp(w, Resp{Message: msg})
		return
	}
	writeResp(w, Resp{Data: &data})
}
`, `web.Reply(w, holds, "")`)
		assert.Equal(t, []string{"store/store.go:14"}, got)
	})
	pair := `
type Pair struct {
	A []int ` + "`json:\"a\"`" + `
	B []int ` + "`json:\"b\"`" + `
}

func Reply(w http.ResponseWriter, a, b []int) { _ = json.NewEncoder(w).Encode(Pair{A: a, B: b}) }
`
	t.Run("nil list in the first of two", func(t *testing.T) {
		assert.Equal(t, []string{"store/store.go:22"}, nilSliceEnvelopeFindings(t, pair, `web.Reply(w, ids, []int{})`))
	})
	t.Run("nil list in the second of two", func(t *testing.T) {
		assert.Equal(t, []string{"store/store.go:22"}, nilSliceEnvelopeFindings(t, pair, `web.Reply(w, []int{}, ids)`))
	})
}

// A response local filled only by append reaches a responder as its second
// payload.
func TestNilSliceJSONNullAppendOnlyFieldInSecondPayload(t *testing.T) {
	got := nilSliceEnvelopeProject(t, map[string]string{
		"web/web.go": `package web

import (
	"encoding/json"
	"net/http"
)

type Pair struct {
	Meta any ` + "`json:\"meta\"`" + `
	Body any ` + "`json:\"body\"`" + `
}

func Reply(w http.ResponseWriter, meta, body any) { _ = json.NewEncoder(w).Encode(Pair{Meta: meta, Body: body}) }
`,
		"api/api.go": `package api

import (
	"net/http"

	"example.com/rulestest/web"
)

type itemsResponse struct {
	Total int   ` + "`json:\"total\"`" + `
	Items []int ` + "`json:\"items\"`" + `
}

func Handle(w http.ResponseWriter, r *http.Request, found []int) {
	resp := itemsResponse{Total: len(found)}
	for _, id := range found {
		resp.Items = append(resp.Items, id)
	}
	web.Reply(w, map[string]int{}, resp)
}
`,
	})
	assert.Equal(t, []string{"api/api.go:15"}, got)
}

// A helper returning its argument passes a nil list on, wherever it is
// declared; a helper that replaces nil with an empty list answers [].
func TestNilSliceJSONNullThroughHelperCall(t *testing.T) {
	t.Run("helper replacing nil", func(t *testing.T) {
		got := nilSliceEnvelopeFindings(t, `
func nonNil(data []int) []int {
	if data == nil {
		return []int{}
	}
	return data
}

func ReplyList(w http.ResponseWriter, data []int) { _ = json.NewEncoder(w).Encode(nonNil(data)) }
`, `web.ReplyList(w, ids)`)
		assert.Empty(t, got)
	})
	t.Run("pointer helper of another package", func(t *testing.T) {
		got := nilSliceEnvelopeProject(t, map[string]string{
			"ptr/ptr.go": `package ptr

func To[T any](v T) *T { return &v }
`,
			"web/web.go": `package web

import (
	"encoding/json"
	"net/http"

	"example.com/rulestest/ptr"
)

type Response[T any] struct {
	Data *T ` + "`json:\"data,omitempty\"`" + `
}

func ReplyOK[T any](w http.ResponseWriter, data T) {
	_ = json.NewEncoder(w).Encode(Response[T]{Data: ptr.To(data)})
}
`,
			"api/api.go": `package api

import (
	"net/http"

	"example.com/rulestest/store"
	"example.com/rulestest/web"
)

func Handle(w http.ResponseWriter, r *http.Request, repo *store.Repo) {
	holds, err := repo.ListAll(r.Context())
	if err != nil {
		return
	}
	web.ReplyOK(w, holds)
}
`,
		})
		assert.Equal(t, []string{"store/store.go:14"}, got)
	})
}

// A field tagged omitempty that holds the type parameter itself drops a nil
// list, and a field tagged json:"-" is never written: neither sends null.
func TestNilSliceJSONNullTypeParamFieldTags(t *testing.T) {
	t.Run("T omitempty", func(t *testing.T) {
		got := nilSliceEnvelopeFindings(t, `
type RespT[T any] struct {
	Data T `+"`json:\"data,omitempty\"`"+`
}

func writeT[T any](w http.ResponseWriter, r RespT[T]) { _ = json.NewEncoder(w).Encode(r) }

func ReplyT[T any](w http.ResponseWriter, data T) { writeT(w, RespT[T]{Data: data}) }
`, `web.ReplyT(w, holds)`)
		assert.Empty(t, got)
	})
	t.Run("*T hidden", func(t *testing.T) {
		got := nilSliceEnvelopeFindings(t, `
type RespH[T any] struct {
	Data *T   `+"`json:\"-\"`"+`
	OK   bool `+"`json:\"ok\"`"+`
}

func writeH[T any](w http.ResponseWriter, r RespH[T]) { _ = json.NewEncoder(w).Encode(r) }

func ReplyH[T any](w http.ResponseWriter, data T) { writeH(w, RespH[T]{Data: dataPtr(data), OK: true}) }
`, `web.ReplyH(w, holds)`)
		assert.Empty(t, got)
	})
}

// The envelope is built into a local first and the local is written; a
// later reassignment on a failure path does not undo the success path.
func TestNilSliceJSONNullEnvelopeInLocal(t *testing.T) {
	t.Run("built once", func(t *testing.T) {
		got := nilSliceEnvelopeFindings(t, `
func ReplyOK[T any](w http.ResponseWriter, data T) {
	response := Response[T]{Success: true, Data: dataPtr(data)}
	write(w, response)
}
`, `web.ReplyOK(w, holds)`)
		assert.Equal(t, []string{"store/store.go:14"}, got)
	})
	t.Run("reassigned on failure", func(t *testing.T) {
		got := nilSliceEnvelopeFindings(t, `
func Reply[T any](w http.ResponseWriter, data T, failed bool) {
	response := Response[T]{Success: true, Data: dataPtr(data)}
	if failed {
		response = Response[T]{}
	}
	write(w, response)
}
`, `web.Reply(w, holds, false)`)
		assert.Equal(t, []string{"store/store.go:14"}, got)
	})
}

// An interface field is not empty when it holds a nil list: the list is
// written as null with or without omitempty.
func TestNilSliceJSONNullInterfaceField(t *testing.T) {
	for name, value := range map[string]string{"list": "data", "address": "&data"} {
		t.Run(name, func(t *testing.T) {
			got := nilSliceEnvelopeFindings(t, `
type RespAny struct {
	Data any `+"`json:\"data,omitempty\"`"+`
}

func writeAny(w http.ResponseWriter, r RespAny) { _ = json.NewEncoder(w).Encode(r) }

func Reply[T any](w http.ResponseWriter, data []T, msg string) { writeAny(w, RespAny{Data: `+value+`}) }
`, `web.Reply(w, holds, "")`)
			assert.Equal(t, []string{"store/store.go:14"}, got)
		})
	}
}

// A map envelope writes every value it holds.
func TestNilSliceJSONNullMapEnvelope(t *testing.T) {
	for name, web := range map[string]string{
		"map of any": `
func writeMap(w http.ResponseWriter, m map[string]any) { _ = json.NewEncoder(w).Encode(m) }

func Reply(w http.ResponseWriter, data any) { writeMap(w, map[string]any{"data": data}) }
`,
		"map of lists": `
func Reply[T any](w http.ResponseWriter, data []T) { _ = json.NewEncoder(w).Encode(map[string][]T{"data": data}) }
`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, []string{"store/store.go:14"}, nilSliceEnvelopeFindings(t, web, `web.Reply(w, holds)`))
		})
	}
}
