package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestHTTPErrorPlaintextRule(t *testing.T) {
	rule := NewHTTPErrorPlaintextRule()

	tests := []struct {
		name          string
		path          string
		code          string
		expectedCount int
	}{
		{
			// Репро: слой отклонял запрос текстом, клиент разбирал ответ как JSON
			// и падал на первом символе вместо показа причины отказа.
			name: "middleware rejects request with plain text",
			path: "/src/middleware/guard.go",
			code: `package middleware
func (m *Guard) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.valid(r) {
			http.Error(w, "token is not valid", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}`,
			expectedCount: 1,
		},
		{
			name: "handler validates input with plain text",
			path: "/src/api/orders.go",
			code: `package api
func (h *Handler) Reset(w http.ResponseWriter, r *http.Request) {
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, req)
}`,
			expectedCount: 1,
		},
		{
			name: "JSON envelope - OK",
			path: "/src/api/orders.go",
			code: `package api
func (h *Handler) Reset(w http.ResponseWriter, r *http.Request) {
	if req.Name == "" {
		sendError(w, r, http.StatusBadRequest, "name is required", "VALIDATION_ERROR")
		return
	}
}`,
			expectedCount: 0,
		},
		{
			name: "webhook of an external provider - OK",
			path: "/src/handlers/webhooks/provider_handler.go",
			code: `package webhooks
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	if !h.validSignature(r) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
}`,
			expectedCount: 0,
		},
		{
			name: "server-sent events - OK",
			path: "/src/handlers/sse/events_handler.go",
			code: `package sse
func (h *Handler) Stream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
}`,
			expectedCount: 0,
		},
		{
			name: "handler serving an image - OK",
			path: "/src/api/card_image.go",
			code: `package api
func (h *Handler) Card(w http.ResponseWriter, r *http.Request) {
	if !h.trusted(r) {
		http.Error(w, "invalid request origin", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}`,
			expectedCount: 0,
		},
		{
			name: "handler serving HTML - OK",
			path: "/src/api/pages.go",
			code: `package api
func (h *Handler) Page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if page == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
}`,
			expectedCount: 0,
		},
		{
			name: "http.Error inside a string literal - OK",
			path: "/src/api/docs.go",
			code: `package api
func doc() string { return "use http.Error(w, msg, code) carefully" }`,
			expectedCount: 0,
		},
		{
			name:          "non-Go file - OK",
			path:          "/src/app/client.ts",
			code:          `http.Error(w, "nope", 403)`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.path, "/src", []byte(tt.code), core.DefaultConfig())
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}
