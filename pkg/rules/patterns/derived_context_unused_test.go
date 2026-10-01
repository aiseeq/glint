package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The loop waits on the timeout context while every call inside gets the
// parent: a call that hangs is never cut by the timeout.
func TestDerivedContextUnused(t *testing.T) {
	assert.Equal(t, []int{16, 28}, sqlFileRuleLines(t, NewDerivedContextUnusedRule(), "chain/receipt.go", `package chain

import (
	"context"
	"time"
)

func (c *Client) WaitReceipt(ctx context.Context, hash string, timeout time.Duration) (*Receipt, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		select {
		case <-timeoutCtx.Done():
			return nil, timeoutCtx.Err()
		default:
			receipt, err := c.rpc.Receipt(ctx, hash)
			if err == nil {
				return receipt, nil
			}
		}
	}
}

func (c *Client) Poll(ctx context.Context) error {
	deadlineCtx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Minute))
	defer cancel()
	for deadlineCtx.Err() == nil {
		if err := c.rpc.Ping(ctx); err == nil {
			return nil
		}
	}
	return deadlineCtx.Err()
}

func (c *Client) Fetch(ctx context.Context, hash string) (*Receipt, error) {
	callCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	c.audit.Record(ctx, hash)
	return c.rpc.Receipt(callCtx, hash)
}

func (c *Client) Run(ctx context.Context) {
	workerCtx, cancel := context.WithCancel(ctx)
	c.stop = cancel
	go func() { c.loop(workerCtx) }()
	c.audit.Record(ctx, "started")
}

func (c *Client) Retry(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return c.rpc.Ping(ctx)
}
`))
}
