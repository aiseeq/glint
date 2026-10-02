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

func cacheCancelledFindings(t *testing.T, source string) []string {
	t.Helper()
	violations, err := NewCacheStoresCancelledErrorRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{"usage/cache.go": source}))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

// A shared cache filled with the caller's context keeps the caller's
// cancellation as its answer: every later reader gets "canceled" until the
// entry expires.
func TestCacheStoresCancelledError(t *testing.T) {
	assert.Equal(t, []string{"usage/cache.go:24", "usage/cache.go:40"}, cacheCancelledFindings(t, `package usage

import (
	"context"
	"sync"
	"time"
)

type Report struct{}

type cache struct {
	mu        sync.Mutex
	report    *Report
	err       error
	expiresAt time.Time
}

func (c *cache) get(ctx context.Context, load func(context.Context) (*Report, error)) (*Report, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.expiresAt.After(time.Now()) {
		return c.report, c.err
	}
	c.report, c.err = load(ctx)
	c.expiresAt = time.Now().Add(time.Minute)
	return c.report, c.err
}

type single struct {
	value *Report
	err   error
	done  bool
}

func (s *single) get(ctx context.Context, load func(context.Context) (*Report, error)) (*Report, error) {
	if s.done {
		return s.value, s.err
	}
	value, err := load(ctx)
	s.value, s.err, s.done = value, err, true
	return value, err
}

func (c *cache) getChecked(ctx context.Context, load func(context.Context) (*Report, error)) (*Report, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.expiresAt.After(time.Now()) {
		return c.report, c.err
	}
	report, err := load(ctx)
	if ctx.Err() != nil {
		return nil, err
	}
	c.report, c.err = report, err
	c.expiresAt = time.Now().Add(time.Minute)
	return c.report, c.err
}

type worker struct{ lastErr error }

func (w *worker) run(ctx context.Context, step func(context.Context) error) {
	w.lastErr = step(ctx)
}

func (c *cache) getBackground(load func(context.Context) (*Report, error)) (*Report, error) {
	if c.expiresAt.After(time.Now()) {
		return c.report, c.err
	}
	c.report, c.err = load(context.Background())
	return c.report, c.err
}
`))
}

func TestCacheStoresCancelledErrorRule_Metadata(t *testing.T) {
	rule := NewCacheStoresCancelledErrorRule()
	assert.Equal(t, "cache-stores-cancelled-error", rule.Name())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}
