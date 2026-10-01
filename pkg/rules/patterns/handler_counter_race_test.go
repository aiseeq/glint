package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestHandlerCounterRaceRule_Metadata(t *testing.T) {
	rule := NewHandlerCounterRaceRule()
	assert.Equal(t, "handler-counter-race", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
}

// Test doubles — a fake provider server in a …test package, a mock or fake
// file — serve one test at a time; their counters are not production races.
func TestHandlerCounterRaceRule_TestDoublesAreLeftAlone(t *testing.T) {
	server := `import "net/http"

type Server struct{ nextID int }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.nextID++
}
`
	files := map[string]string{
		"go.mod":                    "module example.com/rulestest\n\ngo 1.24\n",
		"payprovtest/settings.go":   "package payprovtest\n\n" + server,
		"gateway/fake_gateway.go":   "package gateway\n\n" + server,
		"notifier/mock_notifier.go": "package notifier\n\n" + server,
	}
	violations, err := NewHandlerCounterRaceRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, foundLines(violations))
}

func TestHandlerCounterRaceRule_Detection(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		expects []string
	}{
		{
			// Репро: middleware ограничения размера считал отказы полем
			// структуры, общей для всех запросов, — ++ без мьютекса и atomic из
			// параллельных запросов теряет счёт и ловится race-детектором.
			name: "middleware counts violations in a method that takes the request",
			source: `package app

import "net/http"

type SizeLimit struct {
	max        int64
	violations int64
}

func (m *SizeLimit) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.check(r) {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *SizeLimit) check(r *http.Request) bool {
	if r.ContentLength > m.max {
		m.violations++
		return false
	}
	return true
}
`,
			expects: []string{"app/app.go:22"},
		},
		{
			name: "ServeHTTP and a handler closure add to shared fields",
			source: `package app

import "net/http"

type Stats struct{ served, bytes int }

func (s *Stats) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.served += 1
}

func (s *Stats) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.bytes += int(r.ContentLength)
		next.ServeHTTP(w, r)
	})
}
`,
			expects: []string{"app/app.go:13", "app/app.go:8"},
		},
		{
			name: "under a mutex or through atomic",
			source: `package app

import (
	"net/http"
	"sync"
	"sync/atomic"
)

type Stats struct {
	mu     sync.Mutex
	served int
	failed int64
}

func (s *Stats) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.served++
	s.mu.Unlock()
	atomic.AddInt64(&s.failed, 1)
}

func (s *Stats) bumpLocked(r *http.Request) { s.served++ }
`,
		},
		{
			name: "setup methods and locals are not on the request path",
			source: `package app

import "net/http"

type Router struct{ routes int }

func (rt *Router) Register(mux *http.ServeMux, path string, h http.Handler) {
	mux.Handle(path, h)
	rt.routes++
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	attempts := 0
	attempts++
	_ = attempts
}
`,
		},
		{
			name: "a per-request wrapper owns its fields",
			source: `package app

import "net/http"

type recorder struct {
	http.ResponseWriter
	written int
}

func (rec *recorder) Write(b []byte) (int, error) {
	n, err := rec.ResponseWriter.Write(b)
	rec.written += n
	return n, err
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"go.mod":     "module example.com/rulestest\n\ngo 1.24\n",
				"app/app.go": tt.source,
			}
			violations, err := NewHandlerCounterRaceRule().AnalyzeGoProject(rulestest.Project(t, files))
			require.NoError(t, err)
			assert.Equal(t, tt.expects, foundLines(violations))
		})
	}
}
