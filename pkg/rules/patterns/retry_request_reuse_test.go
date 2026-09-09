package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryRequestReuseRule_Metadata(t *testing.T) {
	rule := NewRetryRequestReuseRule()

	assert.Equal(t, "retry-request-reuse", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestRetryRequestReuseRule_Detection(t *testing.T) {
	rule := NewRetryRequestReuseRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			// Repro (projectA, 2026-09): a payment client retried the same
			// *http.Request. The body is drained after the first send, so the
			// second attempt died with "ContentLength=82 with Body length 0"
			// without ever reaching the provider — a retry that never retried.
			name: "request built once, sent inside retry loop",
			code: `package client

func (c *Client) send(payload []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		resp, err := c.httpClient.Do(req)
		if err == nil {
			return resp, nil
		}
		time.Sleep(time.Second)
	}
	return nil, errors.New("failed")
}
`,
			expectMatch: true,
		},
		{
			name: "request rebuilt on every attempt",
			code: `package client

func (c *Client) send(payload []byte) (*http.Response, error) {
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewBuffer(payload))
		if err != nil {
			return nil, err
		}
		resp, err := c.httpClient.Do(req)
		if err == nil {
			return resp, nil
		}
	}
	return nil, errors.New("failed")
}
`,
			expectMatch: false,
		},
		{
			name: "single send outside any loop",
			code: `package client

func (c *Client) send(payload []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", c.url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	return c.httpClient.Do(req)
}
`,
			expectMatch: false,
		},
		{
			// A request built per item is the loop's own request, not a reused one.
			name: "range loop builds its own request per item",
			code: `package client

func (c *Client) sendAll(items []Item) error {
	for _, item := range items {
		req, _ := http.NewRequest("POST", c.url, item.Body())
		if _, err := c.httpClient.Do(req); err != nil {
			return err
		}
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			// The parameter arrives already built, and the loop resends it:
			// same defect, the caller cannot rebuild it from here either.
			name: "request taken as parameter and resent in loop",
			code: `package client

func (c *Client) executeWithRetry(req *http.Request) (*http.Response, error) {
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.httpClient.Do(req)
		if err == nil {
			return resp, nil
		}
	}
	return nil, errors.New("failed")
}
`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createDeferContext(t, "client.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Contains(t, violations[0].Message, "http.Request")
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

func TestRetryRequestReuseRule_TestFilesExcluded(t *testing.T) {
	rule := NewRetryRequestReuseRule()

	code := `package client

func TestSend(t *testing.T) {
	req, _ := http.NewRequest("POST", url, body)
	for i := 0; i < 3; i++ {
		client.Do(req)
	}
}
`
	ctx := createDeferContext(t, "client_test.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}
