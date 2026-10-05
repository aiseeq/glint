package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A repeat of an idempotency key answered with the stored record without
// comparing it with the incoming request: a different request that reuses
// the key silently gets the first one's result.
func TestIdempotencyCheckThenCreateRule_ReplayWithoutPayloadCheck(t *testing.T) {
	code := `package orders

func (s *Service) existing(ctx context.Context, order *Order) (bool, error) {
	stored, err := s.repo.GetByIdempotencyKey(ctx, order.IdempotencyKey)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	*order = *stored
	return true, nil
}

func (s *Service) replay(ctx context.Context, order *Order) error {
	stored, err := s.repo.FindByKey(ctx, order.IdempotencyKey)
	if err == nil {
		*order = *stored
		return nil
	}
	return err
}

func (s *Service) Create(ctx context.Context, req *Request) (*Order, error) {
	if stored, err := s.repo.GetByIdempotencyKey(ctx, req.IdempotencyKey); err == nil {
		return stored, nil
	}
	return s.repo.Create(ctx, req)
}

// A plain reader by key returns what it found: no finding.
func (s *Service) lookup(ctx context.Context, key string) (*Order, error) {
	stored, err := s.repo.GetByIdempotencyKey(ctx, key)
	if err != nil {
		return nil, err
	}
	return stored, nil
}

// The fingerprint of the request is compared with the stored one: no finding.
func (s *Service) checked(ctx context.Context, order *Order) (bool, error) {
	stored, err := s.repo.GetByIdempotencyKey(ctx, order.IdempotencyKey)
	if err != nil {
		return false, err
	}
	if stored.Fingerprint != order.Fingerprint {
		return false, ErrKeyReused
	}
	*order = *stored
	return true, nil
}

// A comparison helper decides: no finding.
func (s *Service) matched(ctx context.Context, order *Order) (bool, error) {
	stored, err := s.repo.GetByIdempotencyKey(ctx, order.IdempotencyKey)
	if err == nil {
		if !sameRequest(stored, order) {
			return false, ErrKeyReused
		}
		*order = *stored
		return true, nil
	}
	return false, err
}

// A replay validator given the stored record and the request: no finding.
func (s *Service) validated(ctx context.Context, order *Order) (bool, error) {
	stored, err := s.repo.GetByIdempotencyKey(ctx, order.IdempotencyKey)
	if err == nil {
		if err := s.ValidateReplay(stored, order); err != nil {
			return false, err
		}
		*order = *stored
		return true, nil
	}
	return false, err
}

// The record is acted on, not handed back as the answer: no finding.
func (s *Service) approve(ctx context.Context, key string) error {
	stored, err := s.repo.GetByIdempotencyKey(ctx, key)
	if err != nil {
		return err
	}
	return s.approver.Approve(ctx, stored.ID)
}
`
	ctx := createIdempotencyCheckThenCreateContext(t, "orders.go", code)
	violations := NewIdempotencyCheckThenCreateRule().AnalyzeFile(ctx)
	// 28 is the plain race of the lookup and the create.
	assert.ElementsMatch(t, []int{4, 16, 25, 28}, violationLines(violations))
}
