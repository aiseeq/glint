package patterns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestServerErrorHidesClientCancelRule_Metadata(t *testing.T) {
	rule := NewServerErrorHidesClientCancelRule()
	assert.Equal(t, "server-error-hides-client-cancel", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
}

// blindResponderSource — форма, с которой правило снято: один помощник на весь слой,
// принимает только writer и ошибку, спросить об отмене ему нечего.
const blindResponderSource = `package web

import "net/http"

func serverError(w http.ResponseWriter, err error) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
`

// threeHandlers — три обработчика, каждый зовёт помощника по своей ошибке.
const threeHandlers = `package web

import "net/http"

func fetchItems(r *http.Request) error { return nil }

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(w, err)
		return
	}
}

func handleDetail(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(w, err)
		return
	}
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(w, err)
		return
	}
}
`

func TestServerErrorHidesClientCancelRule_Detection(t *testing.T) {
	tests := []struct {
		name        string
		responder   string
		handlers    string
		expectName  string
		expectSites string
		expectInMsg string
	}{
		{
			name:        "shared blind responder with three call sites",
			responder:   blindResponderSource,
			handlers:    threeHandlers,
			expectName:  "serverError",
			expectSites: "3",
			expectInMsg: "answers 500 for 3 call sites",
		},
		{
			// Помощник видит запрос: отмену он спросить может, и это уже его выбор.
			name: "responder takes the request",
			responder: `package web

import "net/http"

func serverError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
`,
			handlers: `package web

import "net/http"

func fetchItems(r *http.Request) error { return nil }

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(w, r, err)
	}
}

func handleDetail(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(w, r, err)
	}
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(w, r, err)
	}
}
`,
		},
		{
			// Контекста достаточно: отмену видно и без самого запроса.
			name: "responder takes a context",
			responder: `package web

import (
	"context"
	"net/http"
)

func serverError(ctx context.Context, w http.ResponseWriter, err error) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
`,
			handlers: `package web

import "net/http"

func fetchItems(r *http.Request) error { return nil }

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(r.Context(), w, err)
	}
}

func handleDetail(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(r.Context(), w, err)
	}
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(r.Context(), w, err)
	}
}
`,
		},
		{
			// Отказ клиенту, а не сервера: 4xx помощник отменой не занимается.
			name: "responder answers 4xx",
			responder: `package web

import "net/http"

func badRequest(w http.ResponseWriter, err error) {
	http.Error(w, "Bad Request", http.StatusBadRequest)
}
`,
			handlers: `package web

import "net/http"

func parse(r *http.Request) error { return nil }

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if err := parse(r); err != nil {
		badRequest(w, err)
	}
}

func handleDetail(w http.ResponseWriter, r *http.Request) {
	if err := parse(r); err != nil {
		badRequest(w, err)
	}
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if err := parse(r); err != nil {
		badRequest(w, err)
	}
}
`,
		},
		{
			// Разовый ответ чинится на месте, общей точки отказа тут нет.
			name:      "single call site",
			responder: blindResponderSource,
			handlers: `package web

import "net/http"

func fetchItems(r *http.Request) error { return nil }

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(w, err)
	}
}
`,
		},
		{
			// Пакет уже разбирает отмену: где именно это делать, решает автор.
			name: "package already knows about context.Canceled",
			responder: `package web

import (
	"context"
	"errors"
	"net/http"
)

func serverError(w http.ResponseWriter, err error) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func canceled(err error) bool { return errors.Is(err, context.Canceled) }
`,
			handlers: threeHandlers,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := cancelResponderProject(t, map[string]string{
				"responder.go": tt.responder,
				"handlers.go":  tt.handlers,
			})
			violations, err := NewServerErrorHidesClientCancelRule().AnalyzeGoProject(project)
			require.NoError(t, err)
			if tt.expectName == "" {
				assert.Empty(t, violations, "ожидалось отсутствие находок: %s", tt.name)
				return
			}
			require.Len(t, violations, 1, "ожидалась одна находка: %s", tt.name)
			assert.Equal(t, "server_error_hides_client_cancel", violations[0].Context["pattern"])
			assert.Equal(t, tt.expectName, violations[0].Context["responder"])
			assert.Equal(t, tt.expectSites, violations[0].Context["call_sites"])
			assert.Contains(t, violations[0].Message, tt.expectInMsg)
		})
	}
}

// Помощник, который сам пишет статус в writer, ловится так же: имя вызова роли не играет.
func TestServerErrorHidesClientCancelRule_WriteHeaderForm(t *testing.T) {
	project := cancelResponderProject(t, map[string]string{
		"responder.go": `package web

import "net/http"

func fail(w http.ResponseWriter, err error) {
	w.WriteHeader(503)
}
`,
		"handlers.go": `package web

import "net/http"

func work(r *http.Request) error { return nil }

func handleA(w http.ResponseWriter, r *http.Request) {
	if err := work(r); err != nil {
		fail(w, err)
	}
}

func handleB(w http.ResponseWriter, r *http.Request) {
	if err := work(r); err != nil {
		fail(w, err)
	}
}

func handleC(w http.ResponseWriter, r *http.Request) {
	if err := work(r); err != nil {
		fail(w, err)
	}
}
`,
	})
	violations, err := NewServerErrorHidesClientCancelRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "answers 503 for 3 call sites")
}

// Вызовы из тестов точкой отказа не считаются: там помощника дёргают намеренно.
func TestServerErrorHidesClientCancelRule_TestFilesDoNotCount(t *testing.T) {
	project := cancelResponderProject(t, map[string]string{
		"responder.go": blindResponderSource,
		"handlers.go": `package web

import "net/http"

func fetchItems(r *http.Request) error { return nil }

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if err := fetchItems(r); err != nil {
		serverError(w, err)
	}
}
`,
		"responder_test.go": `package web

import (
	"errors"
	"net/http/httptest"
	"testing"
)

func TestOne(t *testing.T) { serverError(httptest.NewRecorder(), errors.New("x")) }
func TestTwo(t *testing.T) { serverError(httptest.NewRecorder(), errors.New("y")) }
`,
	})
	violations, err := NewServerErrorHidesClientCancelRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// Repro: every 5xx constant in any call counted as a status — a buffer of 512
// bytes made the JSON writer "answer 500/512". The writer takes no error, and
// its only 5xx is its own json.Marshal failure: it hides no client cancel.
func TestServerErrorHidesClientCancelRule_JSONWriterIsNotAResponder(t *testing.T) {
	project := cancelResponderProject(t, map[string]string{
		"responder.go": `package web

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	buf := make([]byte, 0, 512)
	b, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	buf = append(buf, b...)
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}

func reportFailure(w http.ResponseWriter, err error) {
	payload := make([]byte, 0, 512)
	b, merr := json.Marshal(map[string]string{"error": err.Error()})
	if merr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	payload = append(payload, b...)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}
`,
		"handlers.go": `package web

import "net/http"

func work(r *http.Request) error { return nil }

func handleA(w http.ResponseWriter, r *http.Request) {
	if err := work(r); err != nil {
		reportFailure(w, err)
		return
	}
	writeJSON(w, 200, 1)
}

func handleB(w http.ResponseWriter, r *http.Request) {
	if err := work(r); err != nil {
		reportFailure(w, err)
		return
	}
	writeJSON(w, 200, 2)
}

func handleC(w http.ResponseWriter, r *http.Request) {
	if err := work(r); err != nil {
		reportFailure(w, err)
		return
	}
	writeJSON(w, 200, 3)
}
`,
	})
	violations, err := NewServerErrorHidesClientCancelRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// A responder that hands its 5xx to the project's JSON writer answers 5xx all
// the same: the writer's status parameter reaches WriteHeader.
func TestServerErrorHidesClientCancelRule_StatusThroughJSONWriter(t *testing.T) {
	project := cancelResponderProject(t, map[string]string{
		"responder.go": `package web

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func serverError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
}
`,
		"handlers.go": threeHandlers,
	})
	violations, err := NewServerErrorHidesClientCancelRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "serverError", violations[0].Context["responder"])
	assert.Contains(t, violations[0].Message, "answers 502 for 3 call sites")
}

// Without an error among its parameters the helper has no failure to
// misclassify: it is told to answer 5xx and does.
func TestServerErrorHidesClientCancelRule_RequiresErrorParameter(t *testing.T) {
	project := cancelResponderProject(t, map[string]string{
		"responder.go": `package web

import "net/http"

func unavailable(w http.ResponseWriter) {
	w.WriteHeader(http.StatusServiceUnavailable)
}
`,
		"handlers.go": `package web

import "net/http"

func handleA(w http.ResponseWriter, r *http.Request) { unavailable(w) }
func handleB(w http.ResponseWriter, r *http.Request) { unavailable(w) }
func handleC(w http.ResponseWriter, r *http.Request) { unavailable(w) }
`,
	})
	violations, err := NewServerErrorHidesClientCancelRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// sightedResponderSource — помощник получает запрос и статус параметром, но в контекст
// запроса не смотрит; пакет при этом знает context.Canceled (разбор обёрнутых ошибок).
const sightedResponderSource = `package web

import (
	"context"
	"errors"
	"net/http"
)

func traceOf(r *http.Request) string { return r.Header.Get("traceparent") }

func sendError(w http.ResponseWriter, r *http.Request, status int, message string) {
	w.Header().Set("X-Trace", traceOf(r))
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message))
}

func classify(err error) int {
	if errors.Is(err, context.Canceled) {
		return 499
	}
	return http.StatusInternalServerError
}
`

func sightedHandlers(status string) string {
	return `package web

import "net/http"

func handleIndex(w http.ResponseWriter, r *http.Request) {
	sendError(w, r, ` + status + `, "index failed")
}

func handleDetail(w http.ResponseWriter, r *http.Request) {
	sendError(w, r, ` + status + `, "detail failed")
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	sendError(w, r, ` + status + `, "search failed")
}
`
}

func TestServerErrorHidesClientCancelRule_SightedResponder(t *testing.T) {
	tests := []struct {
		name      string
		responder string
		handlers  string
		expect    bool
	}{
		{name: "takes the request, never looks at its context", responder: sightedResponderSource,
			handlers: sightedHandlers("http.StatusInternalServerError"), expect: true},
		{name: "callers pass only client errors", responder: sightedResponderSource,
			handlers: sightedHandlers("http.StatusBadRequest")},
		{name: "responder checks the request context", responder: `package web

import (
	"context"
	"errors"
	"net/http"
)

func sendError(w http.ResponseWriter, r *http.Request, status int, message string) {
	if status >= 500 && errors.Is(r.Context().Err(), context.Canceled) {
		w.WriteHeader(499)
		return
	}
	w.WriteHeader(status)
}
`, handlers: sightedHandlers("http.StatusInternalServerError")},
		{name: "responder delegates the check", responder: `package web

import "net/http"

func gone(r *http.Request) bool { return r.Context().Err() != nil }

func sendError(w http.ResponseWriter, r *http.Request, status int, message string) {
	if gone(r) {
		return
	}
	w.WriteHeader(status)
}
`, handlers: sightedHandlers("http.StatusInternalServerError")},
		{name: "callers check the cancellation themselves", responder: sightedResponderSource, handlers: `package web

import "net/http"

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Context().Err() != nil {
		return
	}
	sendError(w, r, http.StatusInternalServerError, "index failed")
}

func handleDetail(w http.ResponseWriter, r *http.Request) {
	if r.Context().Err() != nil {
		return
	}
	sendError(w, r, http.StatusInternalServerError, "detail failed")
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	sendError(w, r, http.StatusInternalServerError, "search failed")
}
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := cancelResponderProject(t, map[string]string{
				"responder.go": tt.responder,
				"handlers.go":  tt.handlers,
			})
			violations, err := NewServerErrorHidesClientCancelRule().AnalyzeGoProject(project)
			require.NoError(t, err)
			if !tt.expect {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Equal(t, "sendError", violations[0].Context["responder"])
			assert.Equal(t, "3", violations[0].Context["call_sites"])
			assert.Contains(t, violations[0].Message, "answers 500 for 3 call sites and takes the request, but never looks at its context")
		})
	}
}

func TestServerErrorHidesClientCancelRule_NilProject(t *testing.T) {
	_, err := NewServerErrorHidesClientCancelRule().AnalyzeGoProject(nil)
	require.Error(t, err)
}

func cancelResponderProject(t *testing.T, files map[string]string) *core.GoProjectContext {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/web\n\ngo 1.24\n"), 0o644))

	var contexts []*core.FileContext
	for name, source := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(path, []byte(source), 0o644))
		ctx, err := core.NewFileContextChecked(path, root, []byte(source), core.DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}

	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	return project
}
