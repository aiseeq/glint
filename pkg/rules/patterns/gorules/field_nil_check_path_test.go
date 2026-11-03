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
