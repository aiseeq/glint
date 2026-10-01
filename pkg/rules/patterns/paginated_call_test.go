package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const paginatedCallSource = `package members

import (
	"context"
	"time"
)

type Filter struct{ Status string }
type Member struct{ ID string }
type Transfer struct{ ID string }

type Repo interface {
	ListMembers(ctx context.Context, f Filter, page int, limit int) ([]*Member, int64, error)
	CountMembers(ctx context.Context, status string) (int64, error)
}

type Client interface {
	ListTransfers(ctx context.Context, from, to time.Time, offset, limit int) ([]Transfer, error)
}

type Source struct {
	repo   Repo
	client Client
}

const pageSize = 100

// "All members" asked as one page with limit 0: no rows.
func (s *Source) Members(ctx context.Context) ([]*Member, error) {
	members, _, err := s.repo.ListMembers(ctx, Filter{}, 1, 0)
	return members, err
}

// "All members" capped at ten thousand: the rest is dropped silently.
func (s *Source) AllMembers(ctx context.Context) ([]*Member, error) {
	members, _, err := s.repo.ListMembers(ctx, Filter{}, 1, 10000)
	return members, err
}

// One page of a window: the tail of the window is never seen.
func (s *Source) CheckMissed(ctx context.Context, from time.Time) error {
	transfers, err := s.client.ListTransfers(ctx, from, time.Now(), 0, 100)
	if err != nil {
		return err
	}
	for range transfers {
	}
	return nil
}

// Paged until the end: no finding.
func (s *Source) CheckAll(ctx context.Context, from time.Time) error {
	for offset := 0; ; offset += pageSize {
		transfers, err := s.client.ListTransfers(ctx, from, time.Now(), offset, pageSize)
		if err != nil || len(transfers) < pageSize {
			return err
		}
	}
}

// The newest few for a widget: a small page is the intent.
func (s *Source) RecentMembers(ctx context.Context) ([]*Member, error) {
	members, _, err := s.repo.ListMembers(ctx, Filter{}, 1, 5)
	return members, err
}

// A function with its own page passes it on.
func (s *Source) Page(ctx context.Context, page, limit int) ([]*Member, error) {
	members, _, err := s.repo.ListMembers(ctx, Filter{}, page, limit)
	return members, err
}

// The list reports its total, which is dropped and counted again over
// other arguments.
func (s *Source) Listing(ctx context.Context, f Filter, page, limit int) ([]*Member, int64, error) {
	members, _, err := s.repo.ListMembers(ctx, f, page, limit)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountMembers(ctx, f.Status)
	return members, total, err
}

// A named cap is a decision; a cap checked by length is watched; a total
// read tells the caller what is missing; text clipped is no list.
func (s *Source) Watched(ctx context.Context, from time.Time) error {
	transfers, err := s.client.ListTransfers(ctx, from, time.Now(), 0, pageSize)
	if err != nil {
		return err
	}
	more, err := s.client.ListTransfers(ctx, from, time.Now(), 0, 1001)
	if len(more) > 1000 || len(transfers) == 0 {
		return err
	}
	members, total, err := s.repo.ListMembers(ctx, Filter{}, 1, 1000)
	if int64(len(members)) < total {
		return err
	}
	_ = clip("long text", 200)
	return err
}

func clip(text string, limit int) string { return text[:limit] }

// The list's own total is used.
func (s *Source) Listing2(ctx context.Context, f Filter, page, limit int) ([]*Member, int64, error) {
	return s.repo.ListMembers(ctx, f, page, limit)
}
`

func TestPaginatedCallFirstPageOnly(t *testing.T) {
	violations, err := NewPaginatedCallFirstPageOnlyRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"members/source.go": paginatedCallSource,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"members/source.go:30", "members/source.go:36", "members/source.go:42"}, foundLines(violations))
}

func TestPaginatedTotalRecounted(t *testing.T) {
	violations, err := NewPaginatedTotalRecountedRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"members/source.go": paginatedCallSource,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"members/source.go:80"}, foundLines(violations))
}
