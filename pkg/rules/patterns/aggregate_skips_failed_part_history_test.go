package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Results that carry their own failure (an Error field) are cached, summed
// and returned with a nil error by a function that never looks at the field:
// a failed wallet is served as a zero balance.
func TestAggregateSkipsFailedPart_ResultsWithErrorFieldNeverRead(t *testing.T) {
	assert.Equal(t, []string{"wallets/refresh.go:13", "wallets/refresh.go:30"}, aggregateSkipFindings(t, map[string]string{
		"wallets/model.go": `package wallets

type WalletBalance struct {
	Address  string
	TotalUSD int64
	Error    string
}
`,
		"wallets/refresh.go": `package wallets

func (s *Service) Refresh(ctx context.Context) (*Summary, error) {
	if len(s.wallets) == 0 {
		return &Summary{}, nil
	}
	results := make([]*WalletBalance, len(s.wallets))
	for i, addr := range s.wallets {
		results[i] = s.fetch(ctx, addr)
	}
	s.cached = results
	go s.persist(results)
	return s.summary(results), nil
}

func (s *Service) RefreshChecked(ctx context.Context) (*Summary, error) {
	results := make([]*WalletBalance, len(s.wallets))
	for i, addr := range s.wallets {
		results[i] = s.fetch(ctx, addr)
		if results[i].Error != "" {
			return nil, fmt.Errorf("wallet %s: %s", addr, results[i].Error)
		}
	}
	return s.summary(results), nil
}

func (s *Service) Sync(ctx context.Context, wallet string) ([]*WalletBalance, error) {
	var results []*WalletBalance
	results = append(results, s.syncBatch(ctx, wallet)...)
	return results, nil
}
`,
	}))
}

// Two optional sources feed one total: a failed one is logged and its share
// is simply missing from the total the function returns as complete.
func TestAggregateSkipsFailedPart_SequentialSourcesLoggedAndSkipped(t *testing.T) {
	assert.Equal(t, []string{"positions/total.go:6"}, aggregateSkipFindings(t, map[string]string{
		"positions/total.go": `package positions

func (s *Service) total(ctx context.Context, address string) (decimal.Decimal, error) {
	total := decimal.Zero
	lending, lendingErr := s.fetchLending(ctx, address)
	if lendingErr != nil {
		s.logger.Warn("lending positions fetch failed", "error", lendingErr)
	} else {
		for _, p := range lending {
			total = total.Add(p.Value)
		}
	}
	vaults, vaultsErr := s.fetchVaults(ctx, address)
	if vaultsErr != nil {
		return decimal.Zero, vaultsErr
	}
	for _, p := range vaults {
		total = total.Add(p.Value)
	}
	return total, nil
}
`,
	}))
}

// A failed item counted together with the deliberately skipped ones: the
// function reports a clean run with some "skipped" items.
func TestAggregateSkipsFailedPart_FailureCountedAsSkipped(t *testing.T) {
	assert.Equal(t, []string{"linking/link.go:7"}, aggregateSkipFindings(t, map[string]string{
		"linking/link.go": `package linking

func (s *Service) autoLink(ctx context.Context, txs []*Tx) (int, int, error) {
	linked, skipped := 0, 0
	for _, tx := range txs {
		ok, err := s.tryLink(ctx, tx)
		if err != nil {
			s.logger.Error("auto-link failed", "error", err)
			skipped++
			continue
		}
		if !ok {
			skipped++
			continue
		}
		linked++
	}
	return linked, skipped, nil
}
`,
	}))
}

// Errors are collected and logged, and the function reports success unless
// every item failed.
func TestAggregateSkipsFailedPart_SuccessUnlessAllFailed(t *testing.T) {
	assert.Equal(t, []string{"alerts/check.go:16"}, aggregateSkipFindings(t, map[string]string{
		"alerts/check.go": `package alerts

func (s *Service) check(ctx context.Context, positions []*Position) ([]Alert, error) {
	var alerts []Alert
	var errs []error
	for _, p := range positions {
		a, err := s.evaluate(ctx, p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		alerts = append(alerts, a...)
	}
	if len(errs) > 0 {
		s.logger.Error("positions skipped after errors", "count", len(errs))
		if len(errs) == len(positions) {
			return nil, errors.Join(errs...)
		}
	}
	return alerts, nil
}
`,
	}))
}

// Each result handed to a helper that reads its failure is inspected.
func TestAggregateSkipsFailedPart_ResultsInspectedByHelper(t *testing.T) {
	assert.Empty(t, aggregateSkipFindings(t, map[string]string{
		"wallets/model.go": `package wallets

type WalletBalance struct {
	Address string
	Error   string
}

func issueOf(wb *WalletBalance) string { return wb.Error }
`,
		"wallets/gate.go": `package wallets

func (s *Service) gate(fresh []*WalletBalance) ([]*WalletBalance, error) {
	out := make([]*WalletBalance, len(fresh))
	for i, wb := range fresh {
		out[i] = wb
		if issueOf(wb) != "" {
			out[i] = s.previous(wb.Address)
		}
	}
	return out, nil
}
`,
	}))
}

// A result appended to the slice and handed to a helper that records the
// failure in its Error field is not a failure lost.
func TestAggregateSkipsFailedPart_AppendedResultFailureRecordedByHelper(t *testing.T) {
	assert.Empty(t, aggregateSkipFindings(t, map[string]string{
		"sync/model.go": `package sync

type RunResult struct {
	Account string
	Count   int
	Error   string
}

func recordFailure(result *RunResult, err error) {
	if result.Error != "" {
		result.Error += "; " + err.Error()
		return
	}
	result.Error = err.Error()
}
`,
		"sync/run.go": `package sync

func (s *Service) Run(accounts []string) ([]*RunResult, error) {
	results := make([]*RunResult, 0, len(accounts))
	for _, account := range accounts {
		result := &RunResult{Account: account}
		results = append(results, result)
		n, err := s.read(account)
		if err != nil {
			recordFailure(result, err)
			continue
		}
		result.Count = n
	}
	return results, nil
}
`,
	}))
}
