package errrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// Results that carry their own failure (an Error field) are cached, summed
// and returned with a nil error by a function that never looks at the field:
// a failed wallet is served as a zero balance.
func TestAggregateSkipsFailedPart_ResultsWithErrorFieldNeverRead(t *testing.T) {
	assert.Equal(t, []string{"wallets/refresh.go:13", "wallets/refresh.go:30"}, rulestest.ProjectFilesRulePlaces(t, NewAggregateSkipsFailedPartRule(), map[string]string{
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
	assert.Equal(t, []string{"positions/indexed.go:6", "positions/total.go:6"}, rulestest.ProjectFilesRulePlaces(t, NewAggregateSkipsFailedPartRule(), map[string]string{
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
		// A loop by index adds the part through a local bound to it.
		"positions/indexed.go": `package positions

func (s *Service) totalIndexed(ctx context.Context, address string) (decimal.Decimal, error) {
	total := decimal.Zero
	lending, lendingErr := s.fetchLending(ctx, address)
	if lendingErr != nil {
		s.logger.Warn("lending positions fetch failed", "error", lendingErr)
	} else {
		for i := range lending {
			p := &lending[i]
			total = total.Add(p.Value)
		}
	}
	return total, nil
}
`,
	}))
}

// A failed item counted together with the deliberately skipped ones: the
// function reports a clean run with some "skipped" items.
func TestAggregateSkipsFailedPart_FailureCountedAsSkipped(t *testing.T) {
	assert.Equal(t, []string{"linking/link.go:7"}, rulestest.ProjectFilesRulePlaces(t, NewAggregateSkipsFailedPartRule(), map[string]string{
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
	assert.Equal(t, []string{"alerts/check.go:16"}, rulestest.ProjectFilesRulePlaces(t, NewAggregateSkipsFailedPartRule(), map[string]string{
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
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewAggregateSkipsFailedPartRule(), map[string]string{
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
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewAggregateSkipsFailedPartRule(), map[string]string{
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

// A record of a run that classifies its own failure: next to the failure text
// the reader sets an explicit status to a failure value, and the caller sees
// the failed run as failed, not as a valid one.
func TestAggregateSkipsFailedPart_ErrorNextToExplicitFailureStatus(t *testing.T) {
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewAggregateSkipsFailedPartRule(), map[string]string{
		"report/row.go": `package report

type runRow struct {
	Name   string
	Status string ` + "`json:\"status\"`" + `
	Error  string ` + "`json:\"error,omitempty\"`" + `
}

func readRun(dir string) (*runRow, error) {
	res, err := parse(dir)
	if err != nil {
		return nil, err
	}
	r := &runRow{Name: dir, Error: strings.Join(res.errs, "; ")}
	if len(res.errs) > 0 {
		r.Status = "error"
	} else {
		r.Status = "done"
	}
	return r, nil
}

func readRuns(dirs []string) ([]*runRow, error) {
	var rows []*runRow
	for _, d := range dirs {
		r, err := readRun(d)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}
`,
		// The failure status set through a keyed literal of a named constant.
		"jobs/job.go": `package jobs

const StatusFailed = "failed"

type JobResult struct {
	ID     string
	State  string
	Error  string
}

func (s *Service) run(id string) *JobResult {
	if err := s.exec(id); err != nil {
		return &JobResult{ID: id, State: StatusFailed, Error: err.Error()}
	}
	return &JobResult{ID: id, State: "ok"}
}

func (s *Service) RunAll(ids []string) ([]*JobResult, error) {
	var results []*JobResult
	for _, id := range ids {
		results = append(results, s.run(id))
	}
	return results, nil
}
`,
	}))
}

// A status field that never takes a failure value does not classify the
// failure: the failed item still looks like a valid one.
func TestAggregateSkipsFailedPart_ErrorNextToStatusWithoutFailureValue(t *testing.T) {
	assert.Equal(t, []string{"quotes/sync.go:10"}, rulestest.ProjectFilesRulePlaces(t, NewAggregateSkipsFailedPartRule(), map[string]string{
		"quotes/model.go": `package quotes

type Quote struct {
	Symbol  string
	Status  string
	Error   string
}
`,
		"quotes/sync.go": `package quotes

func (s *Service) Sync(ctx context.Context, symbols []string) ([]*Quote, error) {
	var results []*Quote
	for _, w := range symbols {
		q := s.fetch(ctx, w)
		q.Status = "synced"
		results = append(results, q)
	}
	return results, nil
}
`,
	}))
}
