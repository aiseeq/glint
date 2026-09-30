package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// jsonAPIHelper makes its package a JSON API: responses are encoded as JSON
// straight into the ResponseWriter.
const jsonAPIHelper = `package api

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func sendError(w http.ResponseWriter, r *http.Request, status int, msg, code string) {
	writeJSON(w, status, map[string]string{"error": msg, "code": code})
}
`

func TestHTTPErrorPlaintextRule(t *testing.T) {
	rule := NewHTTPErrorPlaintextRule()

	tests := []struct {
		name          string
		path          string
		code          string
		withJSON      bool
		expectedCount int
	}{
		{
			// Репро: слой отклонял запрос текстом, клиент разбирал ответ как JSON
			// и падал на первом символе вместо показа причины отказа.
			name: "middleware rejects request with plain text",
			path: "api/guard.go",
			code: `package api

import "net/http"

type Guard struct{}

func (m *Guard) valid(r *http.Request) bool { return r != nil }

func (m *Guard) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.valid(r) {
			http.Error(w, "token is not valid", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}`,
			withJSON:      true,
			expectedCount: 1,
		},
		{
			name: "handler validates input with plain text",
			path: "api/orders.go",
			code: `package api

import "net/http"

func Reset(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, name)
}`,
			withJSON:      true,
			expectedCount: 1,
		},
		{
			name: "JSON envelope - OK",
			path: "api/orders.go",
			code: `package api

import "net/http"

func Reset(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("name") == "" {
		sendError(w, r, http.StatusBadRequest, "name is required", "VALIDATION_ERROR")
		return
	}
}`,
			withJSON:      true,
			expectedCount: 0,
		},
		{
			name: "webhook of an external provider - OK",
			path: "api/webhooks/provider_handler.go",
			code: `package webhooks

import (
	"encoding/json"
	"net/http"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Signature") == "" {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}`,
			expectedCount: 0,
		},
		{
			name: "server-sent events - OK",
			path: "api/events_stream.go",
			code: `package api

import "net/http"

func Stream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
}`,
			withJSON:      true,
			expectedCount: 0,
		},
		{
			name: "handler serving an image - OK",
			path: "api/card_image.go",
			code: `package api

import "net/http"

var png []byte

func Card(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") == "" {
		http.Error(w, "invalid request origin", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}`,
			withJSON:      true,
			expectedCount: 0,
		},
		{
			name: "handler serving HTML - OK",
			path: "api/pages.go",
			code: `package api

import "net/http"

func Page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Path == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
}`,
			withJSON:      true,
			expectedCount: 0,
		},
		{
			name: "http.Error inside a string literal - OK",
			path: "api/docs.go",
			code: `package api

func doc() string { return "use http.Error(w, msg, code) carefully" }`,
			withJSON:      true,
			expectedCount: 0,
		},
		{
			// Repro: a plain-text health probe for a load balancer, in a
			// module that never writes JSON. Nothing parses its answer as JSON.
			name: "plain-text endpoint outside a JSON API - OK",
			path: "api/health.go",
			code: `package api

import "net/http"

func Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, _ = w.Write([]byte("ok"))
}`,
			expectedCount: 0,
		},
		{
			// Repro: "text/html" in a comment silenced the whole file.
			name: "non-JSON content type only in a comment",
			path: "api/orders.go",
			code: `package api

import "net/http"

// Reset never serves text/html; it answers the JSON client.
func Reset(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("name") == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
}`,
			withJSON:      true,
			expectedCount: 1,
		},
		{
			name: "aliased net/http import",
			path: "api/orders.go",
			code: `package api

import nethttp "net/http"

func Reset(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.URL.Query().Get("name") == "" {
		nethttp.Error(w, "name is required", nethttp.StatusBadRequest)
	}
}`,
			withJSON:      true,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{tt.path: tt.code}
			if tt.withJSON {
				files["api/json.go"] = jsonAPIHelper
			}
			violations := runRuleOnFiles(t, rule, files)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

// A file checked on its own is judged by its own JSON responses.
func TestHTTPErrorPlaintextRule_SingleFile(t *testing.T) {
	rule := NewHTTPErrorPlaintextRule()
	jsonFile := rulestest.GoFile(t, "api/orders.go", `package api

import (
	"encoding/json"
	"net/http"
)

func Reset(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("name") == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"ok": "yes"})
}`)
	assert.Len(t, rule.AnalyzeFile(jsonFile), 1)

	plainFile := rulestest.GoFile(t, "api/health.go", `package api

import "net/http"

func Health(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}`)
	assert.Empty(t, rule.AnalyzeFile(plainFile))

	assert.Empty(t, rule.AnalyzeFile(rulestest.TextFile(t, "app/client.ts", `http.Error(w, "nope", 403)`)))
}
