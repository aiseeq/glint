package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A nil check guards only the code it dominates: a dereference after an if
// whose branch merely tests the field, and falls through either way, runs on
// the path where the field is nil.
func TestFieldNilCheckInconsistentCheckOnOtherPath(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"router.go": `package example

import ("context"; "log/slog")

type CatalogHandler struct{}
type Item struct{}
type Report struct{}
func (*CatalogHandler) Items(context.Context) ([]Item, error) { return nil, nil }
func (*CatalogHandler) Summary(context.Context) (*Report, error) { return nil, nil }

type Router struct { catalog *CatalogHandler }
func (r *Router) positions(ctx context.Context) ([]Item, error) {
	if r.catalog == nil { slog.Warn("catalog unavailable"); return nil, nil }
	return r.catalog.Items(ctx)
}
func (r *Router) report(ctx context.Context) *Report {
	if r.catalog != nil { slog.Info("catalog set") }
	v, _ := r.catalog.Summary(ctx)
	return v
}
func (r *Router) inside(ctx context.Context) *Report {
	if r.catalog != nil {
		v, _ := r.catalog.Summary(ctx)
		return v
	}
	return nil
}
func (r *Router) after(ctx context.Context) *Report {
	if r.catalog == nil { return nil }
	v, _ := r.catalog.Summary(ctx)
	return v
}
func (r *Router) afterElse(ctx context.Context) *Report {
	if r.catalog == nil {
		return nil
	} else {
		slog.Info("catalog set")
	}
	v, _ := r.catalog.Summary(ctx)
	return v
}
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"router.go:18"}, patterntest.FoundLines(violations))
}

// A nil branch that only logs and goes on leaves the field nil for the code
// after it; a branch ending in a helper of the package, or setting the field,
// still counts as the guard.
func TestFieldNilCheckInconsistentNilBranchThatGoesOn(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"store.go": `package example

import ("fmt"; "log/slog")

type Cache struct{}
func (*Cache) Get(string) string { return "" }
func load() *Cache { return &Cache{} }

type Store struct { cache *Cache }
func (s *Store) optional(key string) string {
	if s.cache == nil { return "" }
	return s.cache.Get(key)
}
func (s *Store) logged(key string) string {
	if s.cache == nil { slog.Warn("cache missing") }
	return s.cache.Get(key)
}
func (s *Store) failed(key string) string {
	if s.cache == nil { s.fail() }
	return s.cache.Get(key)
}
func (s *Store) loaded(key string) string {
	if s.cache == nil { s.cache = load(); slog.Info("cache loaded") }
	return s.cache.Get(key)
}
func (s *Store) fail() { panic("cache missing") }
func (s *Store) handed(key string) string {
	if s.cache == nil { fmt.Sscan(key, s) }
	return s.cache.Get(key)
}
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"store.go:16"}, patterntest.FoundLines(violations))
}

const fieldNilGuardHelperHeader = `package example

type Amount struct{ N int }
func load() *Amount { return nil }
func other() (int, bool) { return 0, true }
type Row struct { value *Amount; start *Amount; cached, strict bool }
func (b *Row) render() int { if b.value != nil { return b.value.N }; return 0 }
func (b *Row) delta() (d, net int, ok bool) {
	if b.start == nil || b.value == nil { return 0, 0, false }
	return b.value.N, 1, true
}
`

// A called method can do the check itself and answer through its last bool
// result: past an exit on that answer the field is not nil.
func TestFieldNilCheckInconsistentGuardInCalledMethod(t *testing.T) {
	tests := map[string]string{
		"exit on the answer": `
func (b *Row) use() int {
	d, net, ok := b.delta()
	if !ok { return 0 }
	return d + net + b.value.N
}`,
		"exit in if init": `
func (b *Row) use() int {
	if _, _, ok := b.delta(); !ok { return 0 }
	return b.value.N
}`,
		"inside the branch": `
func (b *Row) use() int {
	if _, _, ok := b.delta(); ok { return b.value.N }
	return 0
}`,
		"exit with another condition": `
func (b *Row) use(skip bool) int {
	_, _, ok := b.delta()
	if skip || !ok { return 0 }
	return b.value.N
}`,
		"single result in a variable": `
func (b *Row) ready() bool {
	if b.value == nil { return false }
	return true
}
func (b *Row) use() int {
	ok := b.ready()
	if !ok { return 0 }
	return b.value.N
}`,
		"answer variable used before": `
func (b *Row) use() int {
	n, ok := other()
	if !ok { return n }
	_, _, ok = b.delta()
	if !ok { return n }
	return b.value.N
}`,
		"nil branch in else": `
func (b *Row) peek() (int, bool) {
	if b.value == nil {
		return 0, false
	} else if b.cached {
		return 1, true
	}
	return b.value.N, true
}
func (b *Row) use() int {
	_, ok := b.peek()
	if !ok { return 0 }
	return b.value.N
}`,
		"answer computed from the field": `
func (b *Row) peek() (int, bool) { return 1, b.value != nil }
func (b *Row) use() int {
	_, ok := b.peek()
	if !ok { return 0 }
	return b.value.N
}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{
				"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
				"row.go": fieldNilGuardHelperHeader + body + "\n",
			}
			violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
			require.NoError(t, err)
			assert.Empty(t, violations)
		})
	}
}

// The answer guards only while it stands, on the path that exits on it, and only
// when the called method cannot answer true with the field nil.
func TestFieldNilCheckInconsistentGuardInCalledMethodDoesNotHold(t *testing.T) {
	tests := map[string]string{
		"answer ignored": `
func (b *Row) use() int {
	_, _, ok := b.delta()
	_ = ok
	return b.value.N // flagged
}`,
		"answer discarded": `
func (b *Row) use() int {
	d, _, _ := b.delta()
	return d + b.value.N // flagged
}`,
		"branch goes on": `
func (b *Row) use() int {
	_, _, ok := b.delta()
	if !ok { println("no value") }
	return b.value.N // flagged
}`,
		"answer overwritten": `
func (b *Row) use() int {
	_, _, ok := b.delta()
	ok = true
	if !ok { return 0 }
	return b.value.N // flagged
}`,
		"answer of another call": `
func (b *Row) use() int {
	_, _, ok := b.delta()
	_, ok = other()
	if !ok { return 0 }
	return b.value.N // flagged
}`,
		"field replaced after the call": `
func (b *Row) use() int {
	_, _, ok := b.delta()
	b.value = load()
	if !ok { return 0 }
	return b.value.N // flagged
}`,
		"answers true before the check": `
func (b *Row) peek() (int, bool) {
	if b.cached { return 1, true }
	if b.value == nil { return 0, false }
	return b.value.N, true
}
func (b *Row) use() int {
	_, ok := b.peek()
	if !ok { return 0 }
	return b.value.N // flagged
}`,
		"answers true on nil": `
func (b *Row) peek() (int, bool) {
	if b.value == nil { return 0, true }
	return b.value.N, false
}
func (b *Row) use() int {
	_, ok := b.peek()
	if !ok { return 0 }
	return b.value.N // flagged
}`,
		"check only on one path": `
func (b *Row) ready() bool {
	if b.strict {
		if b.value == nil { return false }
	}
	return true
}
func (b *Row) use() int {
	if !b.ready() { return 0 }
	return b.value.N // flagged
}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{
				"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
				"row.go": fieldNilGuardHelperHeader + body + "\n",
			}
			violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
			require.NoError(t, err)
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Code, "// flagged")
		})
	}
}
