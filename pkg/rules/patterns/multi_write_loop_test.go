package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One write repeated over the items of a loop, the first failure returning:
// the items before it stay written, the rest do not.
func TestMultiWriteNoTransactionRule_LoopWriteAbortsHalfway(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) Backfill(ctx context.Context, ids []string) error {
	for range ids {
		if err := s.repo.UpdateThing(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) BackfillAssigned(ctx context.Context, ids []string) error {
	for i := 0; i < len(ids); i++ {
		err := s.repo.UpdateThing(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}
`)
	require.Len(t, violations, 2)
	assert.Contains(t, violations[0].Message, "loop")
	assert.Contains(t, violations[0].Message, "UpdateThing")
}

// An item that fails is skipped and the loop goes on, or the loop runs
// inside a transaction: nothing half-applied by an abort.
func TestMultiWriteNoTransactionRule_LoopWriteNotAborting(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) Each(ctx context.Context, ids []string) int {
	failed := 0
	for range ids {
		if err := s.repo.UpdateThing(ctx); err != nil {
			failed++
			continue
		}
	}
	return failed
}

func (s *Service) All(ctx context.Context, ids []string) error {
	return s.repo.RunInTx(ctx, func(ctx context.Context) error {
		for range ids {
			if err := s.repo.UpdateThing(ctx); err != nil {
				return err
			}
		}
		return nil
	})
}

// A page walk storing each page with its cursor: a failure keeps the pages
// already stored, and the next run resumes after them.
func (s *Service) Pull(ctx context.Context, pages []string) error {
	cursor := ""
	for range pages {
		if err := s.repo.UpdateThing(ctx); err != nil {
			return err
		}
		cursor = cursor + "x"
	}
	return nil
}

func (s *Service) Retry(ctx context.Context) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = s.repo.UpdateThing(ctx); err == nil {
			return nil
		}
	}
	return err
}
`)
	assert.Empty(t, violations)
}
