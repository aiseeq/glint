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

// A nested request maps into a flat model under a prefix: Sender.FirstName
// becomes SenderFirstName. A request field added later (Sender.Gender) is
// never copied into SenderGender, and a service call that gets only the
// model cannot fill it from the request. A field the model lacks under the
// prefix is not a drop.
func TestStructMappingDropsFieldNestedToFlat(t *testing.T) {
	violations, err := NewStructMappingDropsFieldRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"quotes/handler.go": `package quotes

import "context"

type Party struct {
	FirstName string
	LastName  string
	Gender    string
	Nickname  string
}

type Request struct {
	Amount   int64
	Sender   Party
	Receiver Party
}

type Transaction struct {
	Amount            int64
	SenderFirstName   string
	SenderLastName    string
	SenderGender      string
	ReceiverFirstName string
	ReceiverLastName  string
	ReceiverGender    string
}

type Service struct{}

func (s *Service) CreateQuote(ctx context.Context, tx *Transaction) error { return nil }

func handle(ctx context.Context, s *Service, req Request) error {
	tx := &Transaction{
		Amount:            req.Amount,
		SenderFirstName:   req.Sender.FirstName,
		SenderLastName:    req.Sender.LastName,
		SenderGender:      req.Sender.Gender,
		ReceiverFirstName: req.Receiver.FirstName,
		ReceiverLastName:  req.Receiver.LastName,
	}
	return s.CreateQuote(ctx, tx)
}
`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"quotes/handler.go:33"}, foundLines(violations))
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "ReceiverGender")
}
