package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const paginationAppliedSource = `package catalog

import "context"

type Pagination struct {
	Page  int
	Limit int
	Sort  string
}

type Item struct{ ID string }

type Page struct {
	Items              []Item
	Page, Limit, Total int
}

type Repo interface {
	ListAll(ctx context.Context) ([]Item, error)
	List(ctx context.Context, offset, limit int) ([]Item, error)
	ListPage(ctx context.Context, p Pagination) ([]Item, error)
}

type Logger interface{ Info(msg string, args ...any) }

type Service struct {
	repo Repo
	log  Logger
}

func NewPageResponse(items []Item, page, limit, total int) *Page {
	return &Page{Items: items, Page: page, Limit: limit, Total: total}
}

// The page reaches only the response: every call returns all rows.
func (s *Service) ListAll(ctx context.Context, p *Pagination) (*Page, error) {
	if p.Limit <= 0 {
		p.Limit = 20
	}
	items, err := s.repo.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	s.log.Info("listing", "page", p.Page)
	return NewPageResponse(items, p.Page, p.Limit, len(items)), nil
}

// Every row is loaded, the page is cut in memory.
func (s *Service) ListSliced(ctx context.Context, p Pagination) (*Page, error) {
	items, err := s.repo.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	start := (p.Page - 1) * p.Limit
	end := start + p.Limit
	if start > len(items) {
		start = len(items)
	}
	if end > len(items) {
		end = len(items)
	}
	return NewPageResponse(items[start:end], p.Page, p.Limit, len(items)), nil
}

// The query takes the page.
func (s *Service) ListPaged(ctx context.Context, p *Pagination) (*Page, error) {
	items, err := s.repo.List(ctx, (p.Page-1)*p.Limit, p.Limit)
	if err != nil {
		return nil, err
	}
	return NewPageResponse(items, p.Page, p.Limit, 0), nil
}

// The repository gets the whole pagination.
func (s *Service) ListDelegated(ctx context.Context, p Pagination) (*Page, error) {
	items, err := s.repo.ListPage(ctx, p)
	if err != nil {
		return nil, err
	}
	return &Page{Items: items, Page: p.Page, Limit: p.Limit}, nil
}

// A helper that pages a list it is given: the caller decided what to load.
func paginate(items []Item, p Pagination) []Item {
	start := (p.Page - 1) * p.Limit
	end := start + p.Limit
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

// The page of a list loaded with the page itself is no in-memory cut.
func (s *Service) ListWindow(ctx context.Context, p Pagination) []Item {
	items, err := s.repo.List(ctx, 0, p.Page*p.Limit)
	if err != nil {
		return nil
	}
	return items[(p.Page-1)*p.Limit:]
}

// The whole page goes to a helper, which may cut the list.
func (s *Service) ListHelper(ctx context.Context, p *Pagination) (*Page, error) {
	items, err := s.repo.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	return NewPageResponse(paginateSlice(items, p), p.Page, p.Limit, len(items)), nil
}

func paginateSlice(items []Item, p *Pagination) []Item { return items }

// A size alone clips text: no page.
func clip(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
`

func TestPaginationParamNotApplied(t *testing.T) {
	violations, err := NewPaginationParamNotAppliedRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"catalog/service.go": paginationAppliedSource,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"catalog/service.go:45"}, foundLines(violations))
}

func TestPaginationInMemory(t *testing.T) {
	violations, err := NewPaginationInMemoryRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"catalog/service.go": paginationAppliedSource,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"catalog/service.go:62"}, foundLines(violations))
}
