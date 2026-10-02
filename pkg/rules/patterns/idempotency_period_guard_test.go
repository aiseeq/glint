package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// "Done today?" read from the latest record with its error dropped: a failed
// lookup reads as not done, and two runners pass the check together.
func TestIdempotencyCheckThenCreateRule_PeriodGuardOnLatestRecord(t *testing.T) {
	code := `package fees

func (s *Service) Run(ctx context.Context, ids []string) {
	for _, id := range ids {
		today := time.Now().UTC().Format("2006-01-02")
		existing, _ := s.nav.GetLatestNAV(ctx, id)
		if existing == nil || existing.Date != today {
			if err := s.fees.AccrueFees(ctx, id); err != nil {
				s.log.Error("accrue", err)
			}
		}
	}
}

// The lookup error is handled: the remaining race is the plain one, no
// finding here.
func (s *Service) RunChecked(ctx context.Context, id string) error {
	today := time.Now().UTC().Format("2006-01-02")
	existing, err := s.nav.GetLatestNAV(ctx, id)
	if err != nil {
		return err
	}
	if existing == nil || existing.Date != today {
		return s.fees.AccrueFees(ctx, id)
	}
	return nil
}

// No period in the guard: no finding.
func (s *Service) Show(ctx context.Context, id string) string {
	latest, _ := s.nav.GetLatestNAV(ctx, id)
	if latest == nil || latest.Status != "ok" {
		return "stale"
	}
	return "ok"
}
`
	ctx := createIdempotencyCheckThenCreateContext(t, "fees.go", code)
	violations := NewIdempotencyCheckThenCreateRule().AnalyzeFile(ctx)
	assert.Equal(t, []int{6}, violationLines(violations))
}
