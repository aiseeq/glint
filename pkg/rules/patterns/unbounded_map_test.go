package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestUnboundedMapRule_Metadata(t *testing.T) {
	rule := NewUnboundedMapRule()
	assert.Equal(t, "unbounded-map", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
}

func TestUnboundedMapRule_Detection(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		expects []string
	}{
		{
			// Репро: лимитер запросов заводил корзину на каждый IP клиента и не
			// удалял ни одной — за недели работы карта росла на каждый адрес.
			name: "per-client bucket stored on every request, never removed",
			source: `package app

import "sync"

type bucket struct{ tokens int }

type limiter struct {
	mu      sync.Mutex
	clients map[string]*bucket
}

var reportLimiter = &limiter{clients: make(map[string]*bucket)}

func (l *limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.clients[ip]
	if !ok {
		b = &bucket{tokens: 10}
		l.clients[ip] = b
	}
	b.tokens--
	return b.tokens > 0
}
`,
			expects: []string{"app/app.go:9"},
		},
		{
			// Репро: сервис помечал отправленные алерты ключом каждого
			// элемента, набор помеченных только рос.
			name: "marks keyed by the elements of a parameter, filled in a method",
			source: `package app

import "sync"

type depositAlert struct{ id string }

func (d depositAlert) AlertKey() string { return d.id }

type Service struct {
	mu      sync.Mutex
	alerted map[string]struct{}
}

func NewService() *Service {
	return &Service{alerted: make(map[string]struct{})}
}

func (s *Service) fresh(deposits []depositAlert) []depositAlert {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []depositAlert
	for _, deposit := range deposits {
		if _, done := s.alerted[deposit.AlertKey()]; !done {
			out = append(out, deposit)
		}
	}
	return out
}

func (s *Service) markAlerted(deposits []depositAlert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, deposit := range deposits {
		s.alerted[deposit.AlertKey()] = struct{}{}
	}
}
`,
			expects: []string{"app/app.go:11"},
		},
		{
			name: "package-level set filled per call",
			source: `package app

var seen = map[string]bool{}

func Mark(txHash string) bool {
	if seen[txHash] {
		return false
	}
	seen[txHash] = true
	return true
}
`,
			expects: []string{"app/app.go:3"},
		},
		{
			name: "key read from the request",
			source: `package app

import (
	"net/http"
	"sync"
)

type Counter struct {
	mu      sync.Mutex
	byGroup map[string]int
}

var counter = &Counter{byGroup: map[string]int{}}

func (c *Counter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	group := r.Header.Get("X-Group")
	c.mu.Lock()
	c.byGroup[group]++
	c.mu.Unlock()
}
`,
			expects: []string{"app/app.go:10"},
		},
		{
			// Ключи из конечного набора, заданного кодом или конфигурацией:
			// имена клиентов, эндпоинтов, чатов, параметры корридора. Такая
			// карта не растёт с трафиком, и сообщать о ней — шум.
			name: "keys from a bounded set of names",
			source: `package app

import (
	"fmt"
	"sync"
)

type window struct{ events int }

type ClientLimiter struct {
	mu      sync.Mutex
	windows map[string]*window
}

func NewClientLimiter() *ClientLimiter { return &ClientLimiter{windows: map[string]*window{}} }

func (l *ClientLimiter) Allow(client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.windows[client]
	if !ok {
		w = &window{}
		l.windows[client] = w
	}
	w.events++
	return w.events < 100
}

type Metrics struct {
	mu        sync.Mutex
	endpoints map[string]int
}

func NewMetrics() *Metrics { return &Metrics{endpoints: map[string]int{}} }

func (m *Metrics) Record(endpoint string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoints[endpoint]++
}

type SendRequest struct {
	Chat   int64
	UserID int64
}

type FieldsRequest struct{ TransferType, PayoutCountry string }

type Bot struct {
	mu       sync.Mutex
	limiters map[string]int
	fields   map[string][]string
}

func NewBot() *Bot { return &Bot{limiters: map[string]int{}, fields: map[string][]string{}} }

func (b *Bot) limiter(req SendRequest) int {
	key := fmt.Sprintf("u:%d", req.UserID)
	if req.Chat != 0 {
		key = fmt.Sprintf("c:%d", req.Chat)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.limiters[key]++
	return b.limiters[key]
}

func (b *Bot) Fields(req FieldsRequest) []string {
	cacheKey := req.TransferType + "|" + req.PayoutCountry
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fields[cacheKey] = []string{"name"}
	return b.fields[cacheKey]
}
`,
		},
		{
			name: "delete evicts",
			source: `package app

type cache struct{ entries map[string]int }

func (c *cache) put(k string, v int) { c.entries[k] = v }

func (c *cache) drop(k string) { delete(c.entries, k) }
`,
		},
		{
			name: "clear and reassignment reset the map",
			source: `package app

type cache struct {
	byID   map[string]int
	byName map[string]int
}

func (c *cache) put(id, name string, v int) {
	c.byID[id] = v
	c.byName[name] = v
}

func (c *cache) reset() {
	clear(c.byID)
	c.byName = make(map[string]int)
}
`,
		},
		{
			name: "filled only while building or loading once",
			source: `package app

type registry struct{ handlers map[string]func() }

func NewRegistry(names []string) *registry {
	r := &registry{handlers: map[string]func(){}}
	for _, n := range names {
		r.handlers[n] = func() {}
	}
	return r
}

func (r *registry) loadDefaults(names []string) {
	for _, n := range names {
		r.handlers[n] = func() {}
	}
}

var byCode = map[int]string{}

func init() {
	for i := 0; i < 10; i++ {
		byCode[i] = "x"
	}
}
`,
		},
		{
			name: "constant key cannot add entries",
			source: `package app

type stats struct{ counters map[string]int }

func (s *stats) hit() { s.counters["hits"]++ }
`,
		},
		{
			name: "size checked against a cap",
			source: `package app

const maxEntries = 1000

type cache struct{ entries map[string]int }

func (c *cache) put(k string, v int) bool {
	if len(c.entries) >= maxEntries {
		return false
	}
	c.entries[k] = v
	return true
}
`,
		},
		{
			name: "map handed out escapes the analysis",
			source: `package app

type cache struct{ entries map[string]int }

func (c *cache) put(k string, v int) { c.entries[k] = v }

func (c *cache) snapshot() map[string]int { return c.entries }
`,
		},
		{
			// Analyzer and walker state lives as long as one pass: a struct with
			// no lock and no package-level instance is not a shared service.
			name: "per-pass state of an unshared struct",
			source: `package app

type walker struct{ seen map[string]bool }

func (w *walker) visit(name string) bool {
	if w.seen[name] {
		return false
	}
	w.seen[name] = true
	return true
}

func Walk(names []string) int {
	w := &walker{seen: map[string]bool{}}
	n := 0
	for _, name := range names {
		if w.visit(name) {
			n++
		}
	}
	return n
}
`,
		},
		{
			// A request-scoped cache carries a mutex for the goroutines of one
			// request, yet a new one is made per request and dropped with it.
			name: "request-scoped cache made per call",
			source: `package app

import (
	"context"
	"sync"
)

type requestCache struct {
	mu      sync.Mutex
	byRange map[string]int
}

type cacheKey struct{}

func WithRequestCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, cacheKey{}, &requestCache{byRange: map[string]int{}})
}

func (c *requestCache) remember(key string, v int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byRange[key] = v
}
`,
		},
		{
			// Results stored per component the code names: the key set is
			// fixed by the program.
			name: "results per named component",
			source: `package app

import "sync"

type Health struct {
	mu   sync.Mutex
	last map[string]bool
}

func (h *Health) save(component string, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.last[component] = ok
}

const dbComponent = "database"

func (h *Health) Check() {
	h.save("chain", true)
	h.save(dbComponent, false)
}
`,
		},
		{
			// A package-level error has a type without a declaration; it must
			// not make a function-local struct look shared.
			name: "struct declared inside a function",
			source: `package app

import "errors"

var errEmpty = errors.New("empty")

func group(ids []string) (int, error) {
	type bucket struct{ seen map[string]struct{} }
	b := &bucket{seen: map[string]struct{}{}}
	for _, id := range ids {
		b.seen[id] = struct{}{}
	}
	if len(ids) == 0 {
		return 0, errEmpty
	}
	return 1, nil
}
`,
		},
		{
			name: "local map lives as long as the call",
			source: `package app

func count(words []string) int {
	m := map[string]int{}
	for _, w := range words {
		m[w]++
	}
	return len(m)
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"go.mod":             "module example.com/rulestest\n\ngo 1.24\n",
				"app/app.go":         tt.source,
				"cmd/server/main.go": unboundedMapServer,
			}
			violations, err := NewUnboundedMapRule().AnalyzeGoProject(rulestest.Project(t, files))
			require.NoError(t, err)
			assert.Equal(t, tt.expects, foundLines(violations))
		})
	}
}

// unboundedMapServer makes the test project a long-running process.
const unboundedMapServer = `package main

import "net/http"

func main() {
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
`

// A command-line tool exits after its run: what its maps collect is freed
// with the process.
func TestUnboundedMapRule_CommandLineToolIsNotJudged(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"app/app.go": `package app

import "sync"

type timings struct {
	mu    sync.Mutex
	rules map[string]int
}

var collected = &timings{rules: map[string]int{}}

func Track(rule string, ms int) {
	collected.mu.Lock()
	defer collected.mu.Unlock()
	collected.rules[rule] += ms
}
`,
	}
	violations, err := NewUnboundedMapRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, foundLines(violations))
}
