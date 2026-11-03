package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A caller may make the protected call from a function literal it creates
// after the nil check and hands to a helper (a lock, a loop over items): the
// literal runs on the path the check guards. A literal in a method without the
// check gives no protection.
func TestFieldNilCheckInconsistentCallerProtectionThroughClosure(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"service.go": `package example

import "context"

type Store struct{}
func (*Store) Version(context.Context) (int, error) { return 0, nil }
func (*Store) WithLock(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

func each(items []int, fn func(int) error) error {
	for _, item := range items {
		if err := fn(item); err != nil {
			return err
		}
	}
	return nil
}

type Service struct { store *Store; other *Store }
func (s *Service) Recompute(ctx context.Context) (int, error) {
	if s.store == nil { return 0, nil }
	var n int
	return n, s.store.WithLock(ctx, func(ctx context.Context) error {
		_, err := s.recomputeLocked(ctx)
		return err
	})
}
func (s *Service) RecomputeEach(ctx context.Context, items []int) (int, error) {
	if s.store == nil { return 0, nil }
	return len(items), each(items, func(int) error {
		_, err := s.recomputeLocked(ctx)
		return err
	})
}
func (s *Service) recomputeLocked(ctx context.Context) (int, error) {
	return s.store.Version(ctx)
}
func (s *Service) Checked(ctx context.Context) (int, error) {
	if s.other == nil { return 0, nil }
	return s.other.Version(ctx)
}
func (s *Service) Unchecked(ctx context.Context) error {
	return each([]int{1}, func(int) error { _, err := s.otherLocked(ctx); return err })
}
func (s *Service) otherLocked(ctx context.Context) (int, error) {
	return s.other.Version(ctx)
}
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"service.go:45"}, patterntest.FoundLines(violations))
}
