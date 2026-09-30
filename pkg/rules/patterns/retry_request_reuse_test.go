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

// requestClientPrelude declares the client the cases below send through.
const requestClientPrelude = `package client

import (
	"io"
	"net/http"
	"strings"
)

type Client struct {
	url        string
	maxRetries int
	httpClient *http.Client
}

type Item struct{ payload string }

func (i Item) Body() io.Reader { return strings.NewReader(i.payload) }
`

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

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"
)

func (c *Client) send(ctx context.Context, payload []byte) (*http.Response, error) {
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

import (
	"bytes"
	"context"
	"errors"
	"net/http"
)

func (c *Client) send(ctx context.Context, payload []byte) (*http.Response, error) {
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

import (
	"bytes"
	"net/http"
)

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

import (
	"net/http"
)

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
			// Repro: a GET without a body is safe to send again — there is no
			// drained body, and polling it in a loop is the normal thing to do.
			name: "polling a request without a body",
			code: `package client

import (
	"context"
	"fmt"
	"net/http"
)

func (c *Client) poll(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
	}
	return fmt.Errorf("poll failed")
}
`,
			expectMatch: false,
		},
		{
			name: "request built with http.NoBody",
			code: `package client

import "net/http"

func (c *Client) probe() error {
	req, err := http.NewRequest(http.MethodHead, c.url, http.NoBody)
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		if resp, err := c.httpClient.Do(req); err == nil {
			return resp.Body.Close()
		}
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			// Repro: the request builder was recognized only through the
			// identifier http, so an aliased import hid the reuse.
			name: "aliased net/http import",
			code: `package client

import (
	"bytes"
	"errors"
	nethttp "net/http"
)

func (c *Client) send(payload []byte) (*nethttp.Response, error) {
	req, err := nethttp.NewRequest("POST", c.url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
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
		{
			// The parameter arrives already built, and the loop resends it:
			// same defect, the caller cannot rebuild it from here either.
			name: "request taken as parameter and resent in loop",
			code: `package client

import (
	"errors"
	"net/http"
)

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
			violations := runRuleOnFiles(t, rule, map[string]string{
				"client/prelude.go": requestClientPrelude,
				"client/client.go":  tt.code,
			})

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

import (
	"net/http"
	"strings"
	"testing"
)

func TestSend(t *testing.T) {
	client := &http.Client{}
	req, _ := http.NewRequest("POST", "http://example.com", strings.NewReader("x"))
	for i := 0; i < 3; i++ {
		client.Do(req)
	}
}
`
	ctx := createDeferContext(t, "client_test.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

// Without type information the request builder and the send are still known
// through the file's import of net/http.
func TestRetryRequestReuseRule_UntypedFile(t *testing.T) {
	code := `package client

import (
	"bytes"
	nethttp "net/http"
)

func send(c *nethttp.Client, payload []byte) {
	req, _ := nethttp.NewRequest("POST", "http://example.com", bytes.NewReader(payload))
	for i := 0; i < 3; i++ {
		if _, err := c.Do(req); err == nil {
			return
		}
	}
}
`
	ctx := createDeferContext(t, "client.go", code)
	assert.Len(t, NewRetryRequestReuseRule().AnalyzeFile(ctx), 1)
}
