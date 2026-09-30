package security

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestSecretInQueryURLRule(t *testing.T) {
	rule := NewSecretInQueryURLRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			// Repro: a provider client that put ?api-key= in the
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
		return fmt.Errorf("search assets: %w", err)
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

	"example.com/rulestest/httpclient"
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
		return fmt.Errorf("search assets: %w", httpclient.SanitizeTransportError(err))
	}
	defer resp.Body.Close()
	return nil
}`,
			expectedCount: 0,
		},
		{
			// Post-fix shape: apikey in query, but the request goes through a
			// shared helper that owns the sanitation.
			name: "shared HTTP helper is silent",
			code: `package api
import (
	"context"
	"fmt"
	"net/url"

	"example.com/rulestest/httpclient"
)
func (c *Client) Get(ctx context.Context, params url.Values) ([]byte, error) {
	query := url.Values{}
	query.Set("apikey", c.apiKey)
	requestURL := c.baseURL + "?" + query.Encode()
	body, err := httpclient.DoGet(ctx, c.httpClient, requestURL)
	if err != nil {
		return nil, fmt.Errorf("explorer request: %w", err)
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
			t.Parallel() // each case loads its own module
			violations := analyzeSecretInQueryURL(t, rule, tt.code)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

// secretInQueryURLSupport declares what the cases use besides the standard
// library: the client type and a shared HTTP helper package.
var secretInQueryURLSupport = map[string]string{
	"api/client.go": `package api

import (
	"errors"
	"net/http"
)

type Client struct {
	http       *http.Client
	httpClient *http.Client
	apiKey     string
	baseURL    string
	token      string
}

var errUnavailable = errors.New("unavailable")
`,
	"httpclient/httpclient.go": `package httpclient

import (
	"context"
	"net/http"
)

func SanitizeTransportError(err error) error { return err }

func DoGet(ctx context.Context, c *http.Client, url string) ([]byte, error) { return nil, nil }
`,
}

// analyzeSecretInQueryURL loads code as api/case.go of a typed module and
// returns the rule's findings in it.
func analyzeSecretInQueryURL(t *testing.T, rule *SecretInQueryURLRule, code string) []*core.Violation {
	t.Helper()
	files := map[string]string{"api/case.go": code}
	for name, content := range secretInQueryURLSupport {
		files[name] = content
	}
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var inCase []*core.Violation
	for _, v := range violations {
		if filepath.ToSlash(v.File) == "api/case.go" {
			inCase = append(inCase, v)
		}
	}
	return inCase
}

// Only an HTTP transport is a transport: sync.Once.Do, a worker pool's Do or
// any other one-argument Do does not wrap errors in *url.Error.
func TestSecretInQueryURLTransportByReceiverType(t *testing.T) {
	code := `package api

import (
	"net/http"
	"net/url"
	"sync"
)

var once sync.Once

func Link(base, t string) string {
	once.Do(func() {})
	return base + "?token=" + url.QueryEscape(t)
}

func Fetch(c *http.Client, base, key string) error {
	u := base + "?api_key=" + key
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

func FetchVia(d Doer, base, key string) error {
	req, _ := http.NewRequest(http.MethodGet, base+"?api_key="+key, nil)
	resp, err := d.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
`
	violations := analyzeSecretInQueryURL(t, NewSecretInQueryURLRule(), code)
	var functions []any
	for _, v := range violations {
		functions = append(functions, v.Context["function"])
	}
	assert.Equal(t, []any{"Fetch", "FetchVia"}, functions)
}
