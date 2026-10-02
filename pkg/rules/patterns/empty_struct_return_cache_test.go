package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A cache that was never filled answers with a zero summary and no error:
// the screen shows no wallets and a zero total instead of "not loaded yet".
func TestEmptyStructReturn_CacheMissAnsweredAsEmptySuccess(t *testing.T) {
	const source = `package balances

func (s *Service) Summary(ctx context.Context) (*Summary, error) {
	s.mu.RLock()
	data := s.cachedData
	at := s.cachedAt
	s.mu.RUnlock()

	if len(data) > 0 {
		return s.build(data, at), nil
	}
	return &Summary{
		WalletCount: 0,
		Wallets:     []*Wallet{},
		LastUpdated: time.Time{},
	}, nil
}

func (s *Service) List(ctx context.Context) ([]*Wallet, error) {
	items := s.repo.Items()
	if len(items) > 0 {
		return items, nil
	}
	return []*Wallet{}, nil
}
`
	violations := NewEmptyStructReturnRule().AnalyzeFile(rulestest.GoFile(t, "balances/summary.go", source))
	assert.Equal(t, []int{12}, violationLines(violations))
}
