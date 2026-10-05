package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func aggregateSkipFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule := NewAggregateSkipsFailedPartRule()
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	return foundLines(violations)
}

// The balance is built from every stablecoin; a failed load of one is logged
// and skipped, and the user sees a balance computed from part of the money.
func TestAggregateSkipsFailedPart(t *testing.T) {
	assert.Equal(t, []string{"balance/calc.go:21", "balance/calc.go:7"}, aggregateSkipFindings(t, map[string]string{
		"balance/currencies.go": `package balance

var stablecoins = []string{"USDC", "USDT"}
`,
		"balance/calc.go": `package balance

func (c *Calc) load(ctx context.Context) error {
	var all []*Tx
	for _, cur := range stablecoins {
		txs, err := c.repo.ByCurrency(ctx, c.user, cur)
		if err != nil {
			c.log.Error("load failed", "currency", cur, "error", err)
			continue
		}
		all = append(all, txs...)
	}
	c.txs = all
	return nil
}

func (c *Calc) total(ctx context.Context) (decimal.Decimal, error) {
	sum := decimal.Zero
	for _, network := range []string{"net-a", "net-b"} {
		amount, err := c.balances.Get(ctx, network)
		if err != nil {
			c.log.Warn("skip network", "error", err)
			continue
		}
		sum = sum.Add(amount)
	}
	return sum, nil
}
`,
	}))
}

// Rows of a query are data: skipping a bad one is a decision about the data.
// A loop that returns the error, and a function with no error to return, are
// left alone.
func TestAggregateSkipsFailedPartAllowed(t *testing.T) {
	assert.Empty(t, aggregateSkipFindings(t, map[string]string{
		"balance/calc.go": `package balance

var stablecoins = []string{"USDC", "USDT"}

func (c *Calc) parse(rows []Row) ([]decimal.Decimal, error) {
	var out []decimal.Decimal
	for _, row := range rows {
		d, err := decimal.NewFromString(row.Amount)
		if err != nil {
			c.log.Warn("bad amount", "error", err)
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

func (c *Calc) load(ctx context.Context) error {
	var all []*Tx
	for _, cur := range stablecoins {
		txs, err := c.repo.ByCurrency(ctx, c.user, cur)
		if err != nil {
			return err
		}
		all = append(all, txs...)
	}
	c.txs = all
	return nil
}

func (c *Calc) warm(ctx context.Context) {
	var all []*Tx
	for _, cur := range stablecoins {
		txs, err := c.repo.ByCurrency(ctx, c.user, cur)
		if err != nil {
			continue
		}
		all = append(all, txs...)
	}
	c.cache = all
}
`,
	}))
}

// A loop over pairs read from configuration that fetches each from a remote
// client and logs and skips every failure: a timeout or a block drops the
// pair like a missing page, and the run reports success. A branch that
// classifies the error keeps the skip a decision.
func TestAggregateSkipsFailedPart_RemoteFetchSkipsEveryError(t *testing.T) {
	const source = `package sched

func (r *Refresher) fetchAll(ctx context.Context, pairs [][2]string) error {
	var stored []Rate
	for _, pair := range pairs {
		rate, err := r.client.FetchRate(ctx, pair[0], pair[1])
		if err != nil {
			r.logger.Warn("fetch failed", "error", err)
			continue
		}
		stored = append(stored, NewRate(pair, rate))
	}
	return r.store.Save(ctx, stored)
}

func (r *Refresher) fetchKnown(ctx context.Context, pairs [][2]string) error {
	var stored []Rate
	for _, pair := range pairs {
		rate, err := r.client.FetchRate(ctx, pair[0], pair[1])
		if err != nil {
			if !errors.Is(err, ErrNoPage) {
				return err
			}
			continue
		}
		stored = append(stored, NewRate(pair, rate))
	}
	return r.store.Save(ctx, stored)
}

func (s *Importer) importRows(ctx context.Context, rows []Row) error {
	var saved []Item
	for _, row := range rows {
		item, err := parseRow(row)
		if err != nil {
			s.logger.Warn("bad row", "error", err)
			continue
		}
		saved = append(saved, item)
	}
	return s.store.Save(ctx, saved)
}
`
	rule := NewAggregateSkipsFailedPartRule()
	ctx := rulestest.GoFile(t, "sched/refresh.go", source)
	rule.UseProjectFiles([]*core.FileContext{ctx})
	assert.Equal(t, []int{7}, violationLines(rule.AnalyzeFile(ctx)))
}
