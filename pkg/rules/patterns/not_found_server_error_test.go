package patterns

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func notFoundServerErrorFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewNotFoundAnsweredAsServerErrorRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

const notFoundStoreSource = `package store

import (
	"context"
	"errors"
	"fmt"
)

var ErrRecordNotFound = errors.New("record not found")

type Position struct{ ID string }

type Store struct{ rows map[string]*Position }

func (s *Store) Position(ctx context.Context, id string) (*Position, error) {
	p, ok := s.rows[id]
	if !ok {
		return nil, fmt.Errorf("position %s: %w", id, ErrRecordNotFound)
	}
	return p, nil
}

func (s *Store) Report(ctx context.Context, id string) (string, error) {
	p, err := s.Position(ctx, id)
	if err != nil {
		return "", fmt.Errorf("load position: %w", err)
	}
	return p.ID, nil
}

func (s *Store) Totals(ctx context.Context) (int, error) {
	if len(s.rows) == 0 {
		return 0, errors.New("no rows")
	}
	return len(s.rows), nil
}
`

const notFoundAPISource = `package api

import (
	"errors"
	"net/http"

	"example.com/rulestest/store"
)

type Router struct{ store *store.Store }

func sendInternalServerError(w http.ResponseWriter, message string) {
	http.Error(w, message, http.StatusInternalServerError)
}

func sendRecordError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrRecordNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	sendInternalServerError(w, "failed")
}

func (r *Router) report(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	report, err := r.store.Report(req.Context(), id)
	if err != nil {
		sendInternalServerError(w, "report failed")
		return
	}
	_, _ = w.Write([]byte(report))
}

func (r *Router) reportStatus(w http.ResponseWriter, req *http.Request) {
	if _, err := r.store.Position(req.Context(), req.PathValue("id")); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (r *Router) reportMapped(w http.ResponseWriter, req *http.Request) {
	report, err := r.store.Report(req.Context(), req.PathValue("id"))
	if err != nil {
		sendRecordError(w, err)
		return
	}
	_, _ = w.Write([]byte(report))
}

func (r *Router) reportChecked(w http.ResponseWriter, req *http.Request) {
	report, err := r.store.Report(req.Context(), req.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrRecordNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		sendInternalServerError(w, "report failed")
		return
	}
	_, _ = w.Write([]byte(report))
}

func (r *Router) totals(w http.ResponseWriter, req *http.Request) {
	if _, err := r.store.Totals(req.Context()); err != nil {
		sendInternalServerError(w, "totals failed")
		return
	}
}
`

// A handler whose call can return the not-found sentinel and that answers
// every error with a 5xx tells a client's wrong id apart from nothing: the
// missing record is a server failure.
func TestNotFoundAnsweredAsServerError(t *testing.T) {
	assert.Equal(t, []string{"api/api.go:28", "api/api.go:36"}, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": notFoundStoreSource,
		"api/api.go":     notFoundAPISource,
	}))
}

func TestNotFoundAnsweredAsServerErrorRule_Metadata(t *testing.T) {
	rule := NewNotFoundAnsweredAsServerErrorRule()
	assert.Equal(t, "not-found-answered-as-server-error", rule.Name())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

// A helper that receives the error only to log it, checking the request's
// context, does not choose the status: the 5xx after it is still the answer.
func TestNotFoundAnsweredAsServerErrorAfterLogger(t *testing.T) {
	assert.Equal(t, []string{"api/api.go:25"}, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": notFoundStoreSource,
		"api/api.go": `package api

import (
	"context"
	"errors"
	"log"
	"net/http"

	"example.com/rulestest/store"
)

type Router struct{ store *store.Store }

func logFailure(req *http.Request, message string, err error) {
	if err == nil || errors.Is(req.Context().Err(), context.Canceled) {
		return
	}
	log.Print(message + ": " + err.Error())
}

func (r *Router) report(w http.ResponseWriter, req *http.Request) {
	report, err := r.store.Report(req.Context(), req.PathValue("id"))
	if err != nil {
		logFailure(req, "report failed", err)
		http.Error(w, "report failed", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(report))
}
`,
	}))
}

// A call handed nothing the client sent - an email the auth middleware put
// into the context, no arguments at all - cannot miss on the client's id.
func TestNotFoundAnsweredAsServerErrorNeedsClientValue(t *testing.T) {
	assert.Equal(t, []string{"api/api.go:35"}, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": notFoundStoreSource,
		"api/api.go": `package api

import (
	"context"
	"encoding/json"
	"net/http"

	"example.com/rulestest/store"
)

type Router struct{ store *store.Store }

type ctxKey struct{}

func emailFrom(ctx context.Context) string {
	email, _ := ctx.Value(ctxKey{}).(string)
	return email
}

func (r *Router) self(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	if _, err := r.store.Position(ctx, emailFrom(req.Context())); err != nil {
		http.Error(w, "staff unavailable", http.StatusInternalServerError)
		return
	}
}

func (r *Router) update(w http.ResponseWriter, req *http.Request) {
	var body struct{ ID string }
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if _, err := r.store.Position(req.Context(), body.ID); err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
}
`,
	}))
}

// A helper handed the request that reads only its context (the staff the
// auth middleware resolved) gives the call a server-side value.
func TestNotFoundAnsweredAsServerErrorContextHelper(t *testing.T) {
	assert.Empty(t, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": notFoundStoreSource,
		"api/api.go": `package api

import (
	"net/http"

	"example.com/rulestest/store"
)

type Router struct{ store *store.Store }

type ctxKey struct{}

func sendErrorWithTrace(w http.ResponseWriter, req *http.Request, status int, message string) {
	http.Error(w, message+" at "+req.URL.Path, status)
}

func (r *Router) currentStaff(w http.ResponseWriter, req *http.Request) (string, bool) {
	email, ok := req.Context().Value(ctxKey{}).(string)
	if !ok {
		sendErrorWithTrace(w, req, http.StatusUnauthorized, "no staff")
	}
	return email, ok
}

func (r *Router) status(w http.ResponseWriter, req *http.Request) {
	staff, ok := r.currentStaff(w, req)
	if !ok {
		return
	}
	if _, err := r.store.Position(req.Context(), staff); err != nil {
		http.Error(w, "status failed", http.StatusInternalServerError)
		return
	}
}
`,
	}))
}

// A limit the client sent names no record: a not-found from inside the call
// is not about the client's input.
func TestNotFoundAnsweredAsServerErrorNumberArgument(t *testing.T) {
	assert.Empty(t, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": notFoundStoreSource + `
func (s *Store) Classify(ctx context.Context, limit int) (int, error) {
	if _, err := s.Position(ctx, "settings"); err != nil {
		return 0, err
	}
	return limit, nil
}
`,
		"api/api.go": `package api

import (
	"net/http"
	"strconv"

	"example.com/rulestest/store"
)

type Router struct{ store *store.Store }

func (r *Router) classify(w http.ResponseWriter, req *http.Request) {
	limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
	if _, err := r.store.Classify(req.Context(), limit); err != nil {
		http.Error(w, "classify failed", http.StatusInternalServerError)
		return
	}
}
`,
	}))
}

// A record the handler has just written is read back by the id the server
// gave it: a miss there is a server inconsistency, not the client's unknown
// id, and 404 would make the client repeat the write.
func TestNotFoundAnsweredAsServerErrorReadBackOfWrittenRecord(t *testing.T) {
	assert.Empty(t, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": notFoundStoreSource,
		"ledger/ledger.go": `package ledger

import (
	"context"

	"example.com/rulestest/store"
)

type Entry struct {
	ID     string
	Amount string
}

func NewEntry(amount string) *Entry { return &Entry{ID: "generated", Amount: amount} }

type Ledger struct{ store *store.Store }

func (l *Ledger) RecordEntry(ctx context.Context, e *Entry) error { return nil }

func (l *Ledger) Entry(ctx context.Context, id string) (*store.Position, error) {
	return l.store.Position(ctx, id)
}
`,
		"api/api.go": `package api

import (
	"encoding/json"
	"net/http"

	"example.com/rulestest/ledger"
)

type Router struct{ ledger *ledger.Ledger }

func (r *Router) create(w http.ResponseWriter, req *http.Request) {
	var body struct{ Amount string }
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	entry := ledger.NewEntry(body.Amount)
	if err := r.ledger.RecordEntry(req.Context(), entry); err != nil {
		http.Error(w, "record failed", http.StatusInternalServerError)
		return
	}
	if _, err := r.ledger.Entry(req.Context(), entry.ID); err != nil {
		http.Error(w, "recorded, read back failed", http.StatusInternalServerError)
		return
	}
}
`,
	}))
}
