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

func TestNotFoundAnsweredAsServerErrorInService(t *testing.T) {
	assert.Equal(t, []string{"service/service.go:10"}, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": `package store
import "context"
import "errors"
var ErrItemNotFound = errors.New("missing")
type Store struct{}
func (*Store) Read(ctx context.Context, key string) (string, error) { return "", errors.New("database unavailable") }
`,
		"service/service.go": `package service
import (
 "context"
 "fmt"
 "example.com/rulestest/store"
)
type Service struct { store *store.Store }
func (s *Service) Load(ctx context.Context, key string) (string, error) {
 value, err := s.store.Read(ctx, key)
 if err != nil {
  return "", fmt.Errorf("%w", store.ErrItemNotFound)
 }
 return value, nil
}
`,
	}))
}

func TestNotFoundAnsweredAsServerErrorResultWrapperInService(t *testing.T) {
	assert.Equal(t, []string{"service/service.go:10"}, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": `package store
import ("context"; "errors")
var ErrRecordNotFound = errors.New("record not found")
type Result struct { Error error }
func (r Result) IsSuccess() bool { return r.Error == nil }
type Store struct{}
func (*Store) Read(context.Context, string) Result { return Result{Error: errors.New("database unavailable")} }
`,
		"service/service.go": `package service
import (
 "context"
 "fmt"
 "example.com/rulestest/store"
)
type Service struct { store *store.Store }
func (s *Service) Load(ctx context.Context, key string) (string, error) {
 result := s.store.Read(ctx, key)
 if !result.IsSuccess() {
  return "", fmt.Errorf("%w", store.ErrRecordNotFound)
 }
 return "value", nil
}
`,
	}))
}

func TestNotFoundAnsweredAsServerErrorResultWrapperPlainNotFound(t *testing.T) {
	assert.Equal(t, []string{"service/service.go:10"}, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": `package store
import ("context"; "errors")
type Result struct { Error error }
func (r Result) IsSuccess() bool { return r.Error == nil }
type Store struct{}
func (*Store) Read(context.Context, string) Result { return Result{Error: errors.New("database unavailable")} }
`,
		"service/service.go": `package service
import (
 "context"
 "fmt"
 "example.com/rulestest/store"
)
type Service struct { store *store.Store }
func (s *Service) Load(ctx context.Context, key string) (string, error) {
 result := s.store.Read(ctx, key)
 if !result.IsSuccess() { return "", fmt.Errorf("user not found") }
 return "value", nil
}
`,
	}))
}

func TestNotFoundAnsweredAsServerErrorResultWrapperIgnoresHandledError(t *testing.T) {
	assert.Empty(t, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": `package store
import ("context"; "errors")
var ErrRecordNotFound = errors.New("record not found")
type Result struct { Error error }
func (r Result) IsSuccess() bool { return r.Error == nil }
type Store struct{}
func (*Store) Read(context.Context, string) Result { return Result{Error: errors.New("database unavailable")} }
`,
		"service/service.go": `package service
import (
 "context"
 "errors"
 "fmt"
 "example.com/rulestest/store"
)
type Service struct { store *store.Store }
func (s *Service) Load(ctx context.Context, key string) (string, error) {
 result := s.store.Read(ctx, key)
 if !result.IsSuccess() {
  if errors.Is(result.Error, store.ErrRecordNotFound) { return "", store.ErrRecordNotFound }
  return "", fmt.Errorf("read failed: %w", result.Error)
 }
 return "value", nil
}
`,
	}))
}

func TestNotFoundAnsweredAsServerErrorInServiceIgnoresHandledErrors(t *testing.T) {
	assert.Empty(t, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": `package store
import ("context"; "errors")
var ErrRecordNotFound = errors.New("record not found")
type Store struct{}
func (*Store) Read(context.Context, string) (string, error) { return "", errors.New("database unavailable") }
`,
		"service/service.go": `package service
import (
 "context"
 "errors"
 "fmt"
 "example.com/rulestest/store"
)
type Service struct { store *store.Store }
func (s *Service) Load(ctx context.Context, key string) (string, error) {
 value, err := s.store.Read(ctx, key)
 if err != nil {
  if errors.Is(err, store.ErrRecordNotFound) { return "", store.ErrRecordNotFound }
  return "", fmt.Errorf("read failed: %w", err)
 }
 return value, nil
}
func (s *Service) KeepCause(ctx context.Context, key string) (string, error) {
 value, err := s.store.Read(ctx, key)
 if err != nil { return "", fmt.Errorf("read failed: %w", err) }
 return value, nil
}
func readBare(key string) (string, error) { return "", errors.New(key) }
func missingWithoutContext(key string) error {
 if _, err := readBare(key); err != nil { return store.ErrRecordNotFound }
 return nil
}
`,
	}))
}

func TestNotFoundAnsweredAsServerErrorServiceFalsePositives(t *testing.T) {
	assert.Empty(t, notFoundServerErrorFindings(t, map[string]string{
		"store/store.go": `package store
import ("context"; "errors")
var ErrRecordNotFound = errors.New("record not found")
type Record struct { ID string }
type Store struct{}
func (*Store) Collect(context.Context) (*Record, error) { return nil, ErrRecordNotFound }
func (*Store) Finish(context.Context, *Record, error) error { return ErrRecordNotFound }
func (*Store) Wait(context.Context) (*Record, error) { return nil, ErrRecordNotFound }
func (*Store) Read(context.Context) (string, error) { return "", ErrRecordNotFound }
func (*Store) Fallback(context.Context, error) (*Record, int, error) { return nil, 0, ErrRecordNotFound }
type Result struct { Error *Problem }
type Problem struct { Code string }
func (*Store) Lookup(context.Context) Result { return Result{} }
func (Result) IsSuccess() bool { return false }
`,
		"service/service.go": `package service
import (
 "context"
 "errors"
 "fmt"
 "example.com/rulestest/store"
)
type Service struct { store *store.Store }
func (s *Service) Combine(ctx context.Context, id string) (*store.Record, error) {
 res, runErr := s.store.Collect(ctx)
 if err := s.store.Finish(ctx, res, runErr); err != nil {
  return res, errors.Join(runErr, err)
 }
 return res, nil
}
func (s *Service) Wait(ctx context.Context) (*store.Record, error) {
 wb, err := s.store.Wait(ctx)
 if _, sleepErr := s.store.Read(ctx); sleepErr != nil {
  return wb, errors.Join(err, sleepErr)
 }
 return wb, nil
}
func (s *Service) Classify(ctx context.Context) (*store.Record, error) {
 result := s.store.Lookup(ctx)
 if !result.IsSuccess() {
  if result.Error != nil && result.Error.Code == "USER_NOT_FOUND" { return nil, store.ErrRecordNotFound }
  return nil, fmt.Errorf("lookup: %w", errors.New("database unavailable"))
 }
 return nil, nil
}
func (s *Service) Fallback(ctx context.Context) (*store.Record, int, error) {
 _, err := s.store.Read(ctx)
 if err != nil {
  value, detail, storedErr := s.store.Fallback(ctx, fmt.Errorf("live value: %w", err))
  return value, detail, storedErr
 }
 return nil, 0, nil
}
func (s *Service) PriorError(ctx context.Context) (*store.Record, error) {
 _, err := s.store.Collect(ctx)
 if _, inverseErr := s.store.Read(ctx); inverseErr != nil { return nil, err }
 return nil, nil
}
`,
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

// The callee says "not found" only in the text of a plain error: the handler
// cannot tell a currency the client mistyped from an outage and answers 502.
func TestNotFoundAnsweredAsServerErrorUntypedText(t *testing.T) {
	assert.Equal(t, []string{"api/api.go:25"}, notFoundServerErrorFindings(t, map[string]string{
		"rates/rates.go": `package rates

import "fmt"

func Rate(to string) (float64, error) {
	if to != "AAA" {
		return 0, fmt.Errorf("rates: currency %s not found", to)
	}
	return 1, nil
}

func Ping() error {
	return fmt.Errorf("rates: upstream down")
}

type Token struct{ Access string }

func Refresh(refresh string) Token { return Token{Access: refresh + "x"} }
`,
		"api/api.go": `package api

import (
	"net/http"

	"example.com/rulestest/rates"
)

func refreshed(w http.ResponseWriter, req *http.Request) {
	token := rates.Refresh(req.Header.Get("X-Refresh"))
	if _, err := rates.Rate(token.Access); err != nil {
		http.Error(w, "verify failed", http.StatusBadGateway)
		return
	}
}

func ping(w http.ResponseWriter, req *http.Request) {
	if err := rates.Ping(); err != nil {
		http.Error(w, "down", http.StatusBadGateway)
	}
}

func rate(w http.ResponseWriter, req *http.Request) {
	if _, err := rates.Rate(req.URL.Query().Get("to")); err != nil {
		http.Error(w, "rate failed", http.StatusBadGateway)
		return
	}
}
`,
	}))
}

// A handler helper takes what its caller parsed from the request as a value
// struct: a currency the client named still reaches the lookup.
func TestNotFoundAnsweredAsServerErrorHelperParams(t *testing.T) {
	assert.Equal(t, []string{"api/api.go:17"}, notFoundServerErrorFindings(t, map[string]string{
		"rates/rates.go": `package rates

import "fmt"

func Rate(to string) (float64, error) {
	return 0, fmt.Errorf("rates: currency %s not found", to)
}
`,
		"api/api.go": `package api

import (
	"net/http"

	"example.com/rulestest/rates"
)

type convertParams struct{ to string }

func convert(w http.ResponseWriter, req *http.Request) {
	convertTo(w, req, convertParams{to: req.URL.Query().Get("to")})
}

func convertTo(w http.ResponseWriter, req *http.Request, params convertParams) {
	if _, err := rates.Rate(params.to); err != nil {
		http.Error(w, "rate failed", http.StatusBadGateway)
		return
	}
}
`,
	}))
}
