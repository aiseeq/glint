package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const paginatedCallShapesSource = `package ledger

import (
	"context"
	"encoding/json"
)

const MaxLimit = 1000

const snapshotLimit = 500

const assetsLimit = 1000

const pageSize = 100

type Leg struct{ ID string }
type Snap struct{ Date string }
type Asset struct{ ID string }

type LegFilter struct {
	Wallet *string
	Limit  int
	Offset int
}

type LegRepo interface {
	GetByFilter(ctx context.Context, f *LegFilter) ([]*Leg, int, error)
}

type SnapRepo struct{}

func (r *SnapRepo) GetHistoryPage(ctx context.Context, id string, limit, offset int) ([]Snap, int, error) {
	return nil, 0, nil
}

// One page handed out as the history, its total dropped: a caller asking
// for more than the callee's cap gets fewer rows without a sign.
func (r *SnapRepo) GetHistory(ctx context.Context, id string, limit int) ([]Snap, error) {
	snaps, _, err := r.GetHistoryPage(ctx, id, limit, 0)
	return snaps, err
}

// The page passed on with its total: no finding.
func (r *SnapRepo) GetHistoryCounted(ctx context.Context, id string, limit int) ([]Snap, int, error) {
	return r.GetHistoryPage(ctx, id, limit, 0)
}

func (r *SnapRepo) GetByPosition(ctx context.Context, id string, limit int) ([]Snap, error) {
	return nil, nil
}

type Service struct {
	legs  LegRepo
	snaps *SnapRepo
}

// A page size set in the filter literal: legs past it are never seen.
func (s *Service) Reconcile(ctx context.Context, wallet string) (int, error) {
	filter := &LegFilter{Wallet: &wallet, Limit: 1000}
	legs, _, err := s.legs.GetByFilter(ctx, filter)
	return len(legs), err
}

// The same, inline.
func (s *Service) ReconcileInline(ctx context.Context, wallet string) (int, error) {
	legs, _, err := s.legs.GetByFilter(ctx, &LegFilter{Wallet: &wallet, Limit: 1000})
	return len(legs), err
}

// The total is kept and compared: no finding.
func (s *Service) ReconcileChecked(ctx context.Context, wallet string) (int, error) {
	legs, total, err := s.legs.GetByFilter(ctx, &LegFilter{Wallet: &wallet, Limit: 1000})
	if total > 1000 {
		return 0, err
	}
	return len(legs), err
}

// Paged through by offset: no finding.
func (s *Service) ReconcileAll(ctx context.Context, wallet string) (int, error) {
	n := 0
	for offset := 0; ; offset += 1000 {
		legs, _, err := s.legs.GetByFilter(ctx, &LegFilter{Wallet: &wallet, Limit: 1000, Offset: offset})
		if err != nil || len(legs) == 0 {
			return n, err
		}
		n += len(legs)
	}
}

// The whole history read through the pager's maximum: the tail is cut.
func (s *Service) FeeBase(ctx context.Context, id string) (int, error) {
	history, err := s.snaps.GetHistory(ctx, id, MaxLimit)
	return len(history), err
}

// A cap constant of its own: the same.
func (s *Service) Rewards(ctx context.Context, id string) (int, error) {
	snaps, err := s.snaps.GetByPosition(ctx, id, snapshotLimit)
	return len(snaps), err
}

// A page size constant is a page, chosen on purpose: no finding.
func (s *Service) Page(ctx context.Context, id string) (int, error) {
	snaps, err := s.snaps.GetByPosition(ctx, id, pageSize)
	return len(snaps), err
}

type envelope struct {
	Result struct {
		Total int     ` + "`json:\"total\"`" + `
		Items []Asset ` + "`json:\"items\"`" + `
	} ` + "`json:\"result\"`" + `
}

// One request with the page size in its body, the items taken as all of
// them.
func Holdings(owner string, send func([]byte) []byte) ([]Asset, error) {
	payload := map[string]any{
		"method": "searchAssets",
		"params": map[string]any{
			"owner": owner,
			"limit": assetsLimit,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(send(body), &env); err != nil {
		return nil, err
	}
	return env.Result.Items, nil
}

// A full page is an error: no finding.
func HoldingsChecked(owner string, send func([]byte) []byte) ([]Asset, error) {
	body, err := json.Marshal(map[string]any{"owner": owner, "limit": assetsLimit})
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(send(body), &env); err != nil {
		return nil, err
	}
	if len(env.Result.Items) >= assetsLimit {
		return nil, err
	}
	return env.Result.Items, nil
}

// Paged by cursor: no finding.
func HoldingsPaged(owner, cursor string, send func([]byte) []byte) ([]byte, error) {
	return json.Marshal(map[string]any{"owner": owner, "limit": 1000, "cursor": cursor})
}

// A small page on purpose: no finding.
func HoldingsPreview(owner string) ([]byte, error) {
	return json.Marshal(map[string]any{"owner": owner, "limit": 20})
}

// A response a fake server writes, not a request: no finding.
func FakeList(items []Asset) ([]byte, error) {
	return json.Marshal(map[string]any{"items": items, "total": len(items), "limit": 100, "offset": 0})
}

const topErrorsLimit = 200

// A short list for a screen, capped by a named size: no finding.
func (s *Service) ErrorSummary(ctx context.Context, id string) (int, error) {
	snaps, err := s.snaps.GetByPosition(ctx, id, topErrorsLimit)
	return len(snaps), err
}

// The helper checks the cap itself and reports no total to drop: no
// finding.
func (s *Service) ReconcileThroughHelper(ctx context.Context, wallet string) (int, error) {
	legs, err := s.loadLegs(ctx, &LegFilter{Wallet: &wallet, Limit: 1000})
	return len(legs), err
}

func (s *Service) loadLegs(ctx context.Context, filter *LegFilter) ([]*Leg, error) {
	legs, total, err := s.legs.GetByFilter(ctx, filter)
	if total > filter.Limit {
		return nil, err
	}
	return legs, err
}
`

func TestPaginatedCallFirstPageOnlyShapes(t *testing.T) {
	violations, err := NewPaginatedCallFirstPageOnlyRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"ledger/ledger.go": paginatedCallShapesSource,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{
		"ledger/ledger.go:123",
		"ledger/ledger.go:39",
		"ledger/ledger.go:60",
		"ledger/ledger.go:66",
		"ledger/ledger.go:93",
		"ledger/ledger.go:99",
	}, foundLines(violations))
}
