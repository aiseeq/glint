package security

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestSecretInQueryURLRule(t *testing.T) {
	rule := NewSecretInQueryURLRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			// Repro: backoffice helius_das.go before 658dac0 — ?api-key= in the
			// query, raw Do, error wrapped without sanitation.
			name: "query api-key with raw Do and no sanitizer",
			code: `package api
import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)
func (c *Client) GetHoldings(ctx context.Context, address string) error {
	q := url.Values{}
	q.Set("api-key", c.apiKey)
	endpoint := c.baseURL + "/?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("helius searchAssets: %w", err)
	}
	defer resp.Body.Close()
	return nil
}`,
			expectedCount: 1,
		},
		{
			// Post-fix shape: the transport error passes through a sanitizer.
			name: "sanitized transport error is silent",
			code: `package api
import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)
func (c *Client) GetHoldings(ctx context.Context, address string) error {
	q := url.Values{}
	q.Set("api-key", c.apiKey)
	endpoint := c.baseURL + "/?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("helius searchAssets: %w", httpclient.SanitizeTransportError(err))
	}
	defer resp.Body.Close()
	return nil
}`,
			expectedCount: 0,
		},
		{
			// Etherscan post-fix shape: apikey in query, but the request goes
			// through a shared helper that owns the sanitation.
			name: "shared HTTP helper is silent",
			code: `package api
import (
	"context"
	"fmt"
	"net/url"
)
func (c *Client) Get(ctx context.Context, params url.Values) ([]byte, error) {
	query := url.Values{}
	query.Set("apikey", c.apiKey)
	requestURL := c.baseURL + "?" + query.Encode()
	body, err := httpclient.DoGet(ctx, c.httpClient, requestURL)
	if err != nil {
		return nil, fmt.Errorf("etherscan request: %w", err)
	}
	return body, nil
}`,
			expectedCount: 0,
		},
		{
			name: "sprintf url literal with api key",
			code: `package api
import (
	"fmt"
	"net/http"
)
func fetch(key string) error {
	resp, err := http.Get(fmt.Sprintf("https://api.example.com/v1/items?api-key=%s", key))
	if err != nil {
		return fmt.Errorf("fetch items: %w", err)
	}
	defer resp.Body.Close()
	return nil
}`,
			expectedCount: 1,
		},
		{
			name: "header token is not a query secret",
			code: `package api
import (
	"context"
	"fmt"
	"net/http"
)
func (c *Client) Fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("token", c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	return nil
}`,
			expectedCount: 0,
		},
		{
			name: "non-secret query parameter is silent",
			code: `package api
import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)
func (c *Client) List(ctx context.Context, page string) error {
	q := url.Values{}
	q.Set("currency", "usd")
	q.Set("page", page)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	defer resp.Body.Close()
	return nil
}`,
			expectedCount: 0,
		},
		{
			name: "suppression comment is honored",
			code: `package api
import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)
func (c *Client) GetHoldings(ctx context.Context) error {
	q := url.Values{}
	q.Set("api-key", c.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	// nolint:secret-in-query-url — ошибка не логируется, а сразу заменяется статической
	resp, err := c.http.Do(req)
	if err != nil {
		return errUnavailable
	}
	defer resp.Body.Close()
	return nil
}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/file.go", "/src", []byte(tt.code), core.DefaultConfig())
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/src/file.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}
