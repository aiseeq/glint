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

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, statusCode, resp, err := c.doGetRaw(ctx, url)
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

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, statusCode, resp, err := c.doGetRaw(ctx, url)
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

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, statusCode, resp, err := c.doGetRaw(ctx, url)
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

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, statusCode, resp, err := c.doGetRaw(ctx, url)
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

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, err := c.doGetRaw(ctx, url)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createDeferContext(t, "client.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

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

func TestGet(t *testing.T) {
	for attempt := 0; attempt < 3; attempt++ {
		body, statusCode, err := fetch()
		if statusCode != 429 {
			return nil, err
		}
		_ = body
	}
}
`
	ctx := createDeferContext(t, "client_test.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}
