package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const structMappingPersistSource = `package snapshots

import "context"

type Token struct{ Symbol string }

type Position struct {
	ID           string
	APY          float64
	CurrentValue float64
	Tokens       []Token
}

type Snapshot struct {
	PositionID   string
	Date         string
	APY          float64
	CurrentValue float64
	Tokens       []Token
}

type Repo struct{}

func (r *Repo) CreateSnapshot(ctx context.Context, s *Snapshot) error { return nil }

type Service struct{ repo *Repo }

// A repository write stores the literal as it is: Tokens never reach the
// snapshot.
func (s *Service) Take(ctx context.Context, pos *Position, date string) error {
	snap := &Snapshot{
		PositionID:   pos.ID,
		Date:         date,
		APY:          pos.APY,
		CurrentValue: pos.CurrentValue,
	}
	return s.repo.CreateSnapshot(ctx, snap)
}

// A helper may fill what the literal leaves out: no finding.
func (s *Service) TakeEnriched(ctx context.Context, pos *Position, date string) error {
	snap := &Snapshot{
		PositionID:   pos.ID,
		Date:         date,
		APY:          pos.APY,
		CurrentValue: pos.CurrentValue,
	}
	enrich(snap, pos)
	return s.repo.CreateSnapshot(ctx, snap)
}

func enrich(s *Snapshot, pos *Position) {}
`

func TestStructMappingDropsFieldThroughRepositoryWrite(t *testing.T) {
	violations, err := NewStructMappingDropsFieldRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"snapshots/service.go": structMappingPersistSource,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"snapshots/service.go:31"}, foundLines(violations))
}
