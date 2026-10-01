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
