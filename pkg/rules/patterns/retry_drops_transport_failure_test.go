package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestRetryDropsTransportFailureRule_Metadata(t *testing.T) {
	rule := NewRetryDropsTransportFailureRule()

	assert.Equal(t, "retry-drops-transport-failure", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

// retryClientPrelude declares what the retry loops below call, so every case
// type-checks on its own.
const retryClientPrelude = `package client

import (
	"context"
	"time"
)

const maxRetries = 3

var retryBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}

type Client struct{}

func (c *Client) doGetRaw(ctx context.Context, url string) ([]byte, int, error) { return nil, 0, nil }

func (c *Client) doGet(ctx context.Context, url string) ([]byte, error) { return nil, nil }

func (c *Client) orderState(ctx context.Context, id string) ([]byte, string, error) { return nil, "", nil }

func retriableStatus(code int) bool { return code >= 500 }

func retriable(ctx context.Context, err error) bool { return err != nil }

func sleep(d time.Duration) { time.Sleep(d) }
`

func TestRetryDropsTransportFailureRule_Detection(t *testing.T) {
	rule := NewRetryDropsTransportFailureRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			// Repro (projectA, 2026-09): the loop retried a "slow down" answer
			// and returned on a TLS handshake timeout, where statusCode is 0.
			name: "loop returns on every status but the one it retries",
			code: `package client

import (
	"context"
	"net/http"
)

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, statusCode, err := c.doGetRaw(ctx, url)
		if err == nil {
			return body, nil
		}
		if statusCode != http.StatusTooManyRequests {
			return nil, err
		}
		lastErr = err
		sleep(retryBackoff[attempt])
	}
	return nil, lastErr
}
`,
			expectMatch: true,
		},
		{
			// The send failure has its own branch that reaches the next attempt.
			name: "transport failure continues the loop",
			code: `package client

import (
	"context"
	"net/http"
)

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, statusCode, err := c.doGetRaw(ctx, url)
		if err != nil {
			lastErr = err
			sleep(retryBackoff[attempt])
			continue
		}
		if statusCode != http.StatusTooManyRequests {
			return body, nil
		}
		sleep(retryBackoff[attempt])
	}
	return nil, lastErr
}
`,
			expectMatch: false,
		},
		{
			// The decision is made from the error as well, so a failure with no
			// status is classified on its own terms.
			name: "loop asks the error whether to retry",
			code: `package client

import "context"

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, statusCode, err := c.doGetRaw(ctx, url)
		if err == nil {
			return body, nil
		}
		if !retriableStatus(statusCode) && !retriable(ctx, err) {
			return nil, err
		}
		lastErr = err
		sleep(retryBackoff[attempt])
	}
	return nil, lastErr
}
`,
			expectMatch: false,
		},
		{
			// One attempt only: the body ends on a return either way, and there
			// is nothing a retry could have covered.
			name: "loop that always leaves on the first pass",
			code: `package client

import (
	"context"
	"net/http"
)

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, statusCode, err := c.doGetRaw(ctx, url)
		if statusCode != http.StatusOK {
			return nil, err
		}
		return body, nil
	}
	return nil, nil
}
`,
			expectMatch: false,
		},
		{
			// No status among the results: the loop has nothing to decide by
			// status, and this rule has nothing to say about it.
			name: "send that returns no status code",
			code: `package client

import "context"

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, err := c.doGet(ctx, url)
		if err == nil {
			return body, nil
		}
		sleep(retryBackoff[attempt])
	}
	return nil, nil
}
`,
			expectMatch: false,
		},
		{
			// Repro: a pagination loop asks for the next page, not for the same
			// one again. Nothing in it repeats a request — no backoff, no
			// attempt counter, no continue — so an error ending it is right.
			name: "pagination loop is not a retry",
			code: `package client

import (
	"context"
	"fmt"
	"net/http"
)

func (c *Client) all(ctx context.Context) ([][]byte, error) {
	var out [][]byte
	cursor := ""
	for {
		page, status, err := c.doGetRaw(ctx, cursor)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("status %d: %w", status, err)
		}
		out = append(out, page)
		if len(page) == 0 {
			break
		}
		cursor = string(page)
	}
	return out, nil
}
`,
			expectMatch: false,
		},
		{
			// A result named like a status is not a status unless it is an
			// HTTP code: an order state string decides nothing about transport.
			name: "status-named string result is not a status code",
			code: `package client

import "context"

func (c *Client) wait(ctx context.Context, id string) ([]byte, error) {
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, status, err := c.orderState(ctx, id)
		if err == nil {
			return body, nil
		}
		if status != "pending" {
			return nil, err
		}
		sleep(retryBackoff[attempt])
	}
	return nil, nil
}
`,
			expectMatch: false,
		},
		{
			// The status is an int result whatever its name: code, rc, httpCode.
			name: "int status under any name",
			code: `package client

import (
	"context"
	"net/http"
	"time"
)

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for {
		body, rc, err := c.doGetRaw(ctx, url)
		if err == nil {
			return body, nil
		}
		if rc != http.StatusServiceUnavailable {
			return nil, err
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	return nil, lastErr
}
`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := runRuleOnFiles(t, rule, map[string]string{
				"client/prelude.go": retryClientPrelude,
				"client/client.go":  tt.code,
			})

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Contains(t, violations[0].Message, "transport failure")
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

func TestRetryDropsTransportFailureRule_TestFilesExcluded(t *testing.T) {
	rule := NewRetryDropsTransportFailureRule()

	code := `package client

import (
	"context"
	"testing"
)

func TestGet(t *testing.T) {
	c := &Client{}
	for attempt := 0; attempt < 3; attempt++ {
		body, statusCode, err := c.doGetRaw(context.Background(), "u")
		if statusCode != 429 {
			t.Fatal(err)
		}
		_ = body
		sleep(retryBackoff[attempt])
	}
}
`
	violations := runRuleOnFiles(t, rule, map[string]string{
		"client/prelude.go":     retryClientPrelude,
		"client/client_test.go": code,
	})
	assert.Empty(t, violations)
}
