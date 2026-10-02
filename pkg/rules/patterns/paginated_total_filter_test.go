package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const statsFilterRepoSource = `package txrepo

import (
	"context"
	"fmt"
)

type Filter struct {
	Wallet    *string
	Chain     *string
	Direction *string
	Status    *string
	MinUSD    *float64
}

type Tx struct{ ID string }
type Stats struct{ Count int }

type queryBuilder struct {
	conds []string
	args  []any
}

func (b *queryBuilder) add(column string, value *string) {
	if value != nil {
		b.args = append(b.args, *value)
		b.conds = append(b.conds, fmt.Sprintf("%s = $%d", column, len(b.args)))
	}
}

func applyFilter(b *queryBuilder, f *Filter) {
	b.add("wallet", f.Wallet)
	b.add("chain", f.Chain)
	b.add("direction", f.Direction)
	b.add("status", f.Status)
	if f.MinUSD != nil {
		b.args = append(b.args, *f.MinUSD)
	}
}

type Repo struct{}

func (r *Repo) List(ctx context.Context, f *Filter) ([]Tx, int, error) {
	b := &queryBuilder{}
	applyFilter(b, f)
	return nil, len(b.args), nil
}

// The totals rebuild the filter by hand.
func (r *Repo) StatsByFilter(ctx context.Context, f *Filter) (*Stats, error) {
	var conds []string
	if f.Wallet != nil {
		conds = append(conds, "wallet = $1")
	}
	if f.Chain != nil {
		conds = append(conds, "chain = $2")
	}
	if f.MinUSD != nil {
		conds = append(conds, "usd >= $3")
	}
	return &Stats{Count: len(conds)}, nil
}

// The count goes through the same builder: no finding.
func (r *Repo) CountByFilter(ctx context.Context, f *Filter) (int, error) {
	b := &queryBuilder{}
	applyFilter(b, f)
	return len(b.args), nil
}
`

const statsFilterHandlerSource = `package txapi

import (
	"net/http"
	"net/url"
)

type Filter struct {
	Wallet    *string
	Chain     *string
	Direction *string
	MinUSD    string
}

func parseFilter(q url.Values) *Filter {
	f := &Filter{}
	set := func(key string, target **string) {
		if v := q.Get(key); v != "" {
			*target = &v
		}
	}
	set("wallet", &f.Wallet)
	set("chain", &f.Chain)
	set("direction", &f.Direction)
	f.MinUSD = q.Get("min_usd")
	return f
}

type Handler struct{}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	_ = parseFilter(r.URL.Query())
}

// The stats endpoint reads two of the list's keys by hand.
func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	wallet := r.URL.Query().Get("wallet")
	minUSD := r.URL.Query().Get("min_usd")
	_, _ = wallet, minUSD
}

// Through the list's parser: no finding.
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	_ = parseFilter(r.URL.Query())
}

// A key of its own, not the list's: no finding.
func (h *Handler) CountJobs(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("queue")
}
`

func TestPaginatedTotalRecountedHandMappedFilter(t *testing.T) {
	violations, err := NewPaginatedTotalRecountedRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"txrepo/repo.go":   statsFilterRepoSource,
		"txapi/handler.go": statsFilterHandlerSource,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"txapi/handler.go:37", "txrepo/repo.go:52"}, foundLines(violations))
}
