package deadcode

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func neverAssignedPlaces(t *testing.T, files map[string]string) []string {
	t.Helper()
	var places []string
	for _, v := range analyzeNeverAssigned(t, files) {
		places = append(places, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	return places
}

// A field that only ever receives nil is never given a value: the typed nil
// written to make the code compile is still nil on the first call.
func TestNeverAssignedFieldCountsNilWriteAsNoWrite(t *testing.T) {
	places := neverAssignedPlaces(t, map[string]string{
		"handler.go": `package handler

type SessionManager struct{ ttl int }

func (m *SessionManager) TTL() int { return m.ttl }

type Conn interface{ Close() error }

type Handler struct {
	sessionManager *SessionManager
	conn           Conn
}

func New(dial func() Conn) *Handler {
	return &Handler{sessionManager: (*SessionManager)(nil), conn: dial()}
}

func (h *Handler) Serve() int { return h.sessionManager.TTL() }

func (h *Handler) Close() error {
	err := h.conn.Close()
	h.conn = nil
	return err
}
`,
	})
	assert.Equal(t, []string{"handler.go:10"}, places)
}

// A literal of a type written outside its constructor leaves nil the
// dependencies the constructor fills and the methods use.
func TestNeverAssignedFieldReportsLiteralBypassingConstructor(t *testing.T) {
	places := neverAssignedPlaces(t, map[string]string{
		"base.go": `package routing

type Logger interface{ Info(msg string) }

type ErrorHandler struct{ code int }

func (e *ErrorHandler) Handle() int { return e.code }

type BaseHandler struct {
	logger       Logger
	errorHandler *ErrorHandler
	name         string
}

func NewBaseHandler(logger Logger) *BaseHandler {
	return &BaseHandler{logger: logger, errorHandler: &ErrorHandler{}, name: "base"}
}

func (h *BaseHandler) Fail() int {
	h.logger.Info("failed")
	return h.errorHandler.Handle()
}
`,
		"vault.go": `package routing

type VaultHandler struct{ *BaseHandler }

func NewVaultHandler(logger Logger) *VaultHandler {
	return &VaultHandler{
		BaseHandler: &BaseHandler{logger: logger},
	}
}

func NewSSLHandler(logger Logger) *VaultHandler {
	base := &BaseHandler{logger: logger}
	base.errorHandler = &ErrorHandler{}
	return &VaultHandler{BaseHandler: base}
}

func NewNamedHandler(logger Logger) *VaultHandler {
	return &VaultHandler{BaseHandler: NewBaseHandler(logger)}
}

func cloneBase(h *BaseHandler) *BaseHandler {
	return &BaseHandler{logger: h.logger, errorHandler: h.errorHandler}
}
`,
	})
	assert.Equal(t, []string{"vault.go:7"}, places)
}

// A literal leaving nil what its type never goes through is not a bypass: an
// optional value of a data struct, the cause an error type returns, a field
// of a library type.
func TestNeverAssignedFieldLiteralLeavesUnusedFieldsAlone(t *testing.T) {
	places := neverAssignedPlaces(t, map[string]string{
		"filter.go": `package store

import (
	"net/http"
	"time"
)

type Filter struct {
	Limit *int
	From  *time.Time
	Tags  map[string]bool
}

func (f *Filter) Tag(name string) bool { return f.Tags[name] }

func (f *Filter) Since() string {
	if f.From == nil {
		return ""
	}
	return f.From.String()
}

func NewFilter(limit int, from time.Time) *Filter {
	return &Filter{Limit: &limit, From: &from, Tags: map[string]bool{}}
}

func Describe(f *Filter) string {
	if f.From != nil {
		return f.From.String()
	}
	return ""
}

type failure struct {
	code  string
	cause error
}

func newFailure(code string, cause error) *failure { return &failure{code: code, cause: cause} }

func (f *failure) Error() string {
	if f.cause != nil {
		return f.code + ": " + f.cause.Error()
	}
	return f.code
}

func (f *failure) Unwrap() error { return f.cause }

func query() (*Filter, error) {
	client := &http.Client{Timeout: time.Second}
	_ = client
	return &Filter{}, &failure{code: "empty"}
}
`,
	})
	assert.Empty(t, places)
}
