package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPBodyCloseRule_Metadata(t *testing.T) {
	rule := NewHTTPBodyCloseRule()

	assert.Equal(t, "http-body-close", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestHTTPBodyCloseRule_Detection(t *testing.T) {
	rule := NewHTTPBodyCloseRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "http.Get without close",
			code: `package main

import "net/http"

func example() {
	resp, err := http.Get("http://example.com")
	if err != nil {
		return
	}
	_ = resp
}
`,
			expectMatch: true,
		},
		{
			name: "http.Get with defer close",
			code: `package main

import "net/http"

func example() {
	resp, err := http.Get("http://example.com")
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
`,
			expectMatch: false,
		},
		{
			name: "aliased http.Get without close",
			code: `package main

import nethttp "net/http"

func example() {
	resp, err := nethttp.Get("http://example.com")
	if err != nil {
		return
	}
	_ = resp
}
`,
			expectMatch: true,
		},
		{
			name: "http.Get with close",
			code: `package main

import "net/http"

func example() {
	resp, err := http.Get("http://example.com")
	if err != nil {
		return
	}
	resp.Body.Close()
}
`,
			expectMatch: false,
		},
		{
			name: "client.Do without close",
			code: `package main

import "net/http"

func example(client *http.Client, req *http.Request) {
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp
}
`,
			expectMatch: true,
		},
		{
			name: "aliased http client Do without close",
			code: `package main

import nethttp "net/http"

func example(client *nethttp.Client, req *nethttp.Request) {
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp
}
`,
			expectMatch: true,
		},
		{
			name: "arbitrary Do without close is not HTTP",
			code: `package main

import "net/http"

type executor struct{}
type result struct{}

func (executor) Do() (*result, error) { return nil, nil }

func example(worker executor) {
	_ = http.MethodGet
	resp, err := worker.Do()
	if err != nil {
		return
	}
	_ = resp
}
`,
			expectMatch: false,
		},
		{
			name: "custom Do with HTTP request is not HTTP client",
			code: `package main

import (
	"io"
	"net/http"
)

type customResult struct { Body io.Reader }
type worker struct{}

func (worker) Do(req *http.Request) (*customResult, error) { return nil, nil }

func example(w worker, req *http.Request) {
	resp, err := w.Do(req)
	if err != nil {
		return
	}
	_ = resp
}
`,
			expectMatch: false,
		},
		{
			name: "break skips unreachable response assignment",
			code: `package main

import "net/http"

func example() {
	for {
		break
		resp, _ := http.Get("http://example.com")
		_ = resp
	}
}
`,
			expectMatch: false,
		},
		{
			name: "break skips unreachable close",
			code: `package main

import "net/http"

func example() {
	for {
		resp, _ := http.Get("http://example.com")
		break
		resp.Body.Close()
	}
}
`,
			expectMatch: true,
		},
		{
			name: "continue skips unreachable response assignment",
			code: `package main

import "net/http"

func example() {
	for i := 0; i < 1; i++ {
		continue
		resp, _ := http.Get("http://example.com")
		_ = resp
	}
}
`,
			expectMatch: false,
		},
		{
			name: "continue skips unreachable close",
			code: `package main

import "net/http"

func example() {
	for i := 0; i < 1; i++ {
		resp, _ := http.Get("http://example.com")
		continue
		resp.Body.Close()
	}
}
`,
			expectMatch: true,
		},
		{
			name: "panic skips unreachable response assignment",
			code: `package main

import "net/http"

func example() {
	panic("stop")
	resp, _ := http.Get("http://example.com")
	_ = resp
}
`,
			expectMatch: false,
		},
		{
			name: "panic skips unreachable close",
			code: `package main

import "net/http"

func example() {
	resp, _ := http.Get("http://example.com")
	panic("stop")
	resp.Body.Close()
}
`,
			expectMatch: true,
		},
		{
			name: "response returned to caller",
			code: `package main

import "net/http"

func example() (*http.Response, error) {
	resp, err := http.Get("http://example.com")
	if err != nil {
		return nil, err
	}
	return resp, nil
}
`,
			expectMatch: false, // ответственность за Close переходит вызывающему
		},
		{
			name: "close delegated to helper",
			code: `package main

import "net/http"

func drainAndClose(resp *http.Response) {
	resp.Body.Close()
}

func example() {
	resp, err := http.Get("http://example.com")
	if err != nil {
		return
	}
	defer drainAndClose(resp)
}
`,
			expectMatch: false, // resp передан в вызов — закрытие в хелпере
		},
		{
			name: "response ignored",
			code: `package main

import "net/http"

func example() {
	_, err := http.Get("http://example.com")
	if err != nil {
		return
	}
}
`,
			expectMatch: false, // Ignored with _
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := runRuleOnFiles(t, rule, map[string]string{"service.go": tt.code})

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "http_body_leak", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

func TestHTTPBodyCloseRule_ClientsKnownByType(t *testing.T) {
	code := `package main

import (
	nethttp "net/http"
)

type worker struct{}
type result struct{}

func (worker) Do() (*result, error) { return nil, nil }

func (w worker) example(client *nethttp.Client, req *nethttp.Request) {
	httpResp, httpErr := client.Do(req)
	if httpErr != nil {
		return
	}
	_ = httpResp

	var declaredClient *nethttp.Client = nethttp.DefaultClient
	declaredResp, declaredErr := declaredClient.Get("http://example.com")
	if declaredErr != nil {
		return
	}
	_ = declaredResp

	assignedClient := &nethttp.Client{}
	assignedResp, assignedErr := assignedClient.Do(req)
	if assignedErr != nil {
		return
	}
	_ = assignedResp

	workerResp, workerErr := w.Do()
	if workerErr != nil {
		return
	}
	_ = workerResp
}
`
	violations := runRuleOnFiles(t, NewHTTPBodyCloseRule(), map[string]string{"service.go": code})
	require.Len(t, violations, 3)
	variables := make([]string, 0, len(violations))
	for _, violation := range violations {
		variable, ok := violation.Context["variable"].(string)
		require.True(t, ok)
		variables = append(variables, variable)
	}
	assert.ElementsMatch(t, []string{"httpResp", "declaredResp", "assignedResp"}, variables)
}

// Repro: a client kept in a struct field and a response taken inside a handler
// closure were both invisible — only function declarations were walked, and a
// field was not recognized as an *http.Client.
func TestHTTPBodyCloseRule_FieldClientAndClosures(t *testing.T) {
	code := `package payprov

import (
	"database/sql"
	"io"
	"net/http"
)

type API struct {
	client *http.Client
	db     *sql.DB
}

func (a *API) Fetch(u string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	fieldResp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(fieldResp.Body)
	return b, err
}

func Register(mux *http.ServeMux) {
	mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
		closureResp, err := http.Get("http://example.com")
		if err != nil {
			return
		}
		_, _ = io.ReadAll(closureResp.Body)
	})
}

func (a *API) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		closedResp, err := a.client.Get("http://example.com")
		if err != nil {
			return
		}
		defer closedResp.Body.Close()
	}
}
`
	violations := runRuleOnFiles(t, NewHTTPBodyCloseRule(), map[string]string{"api.go": code})
	variables := make([]string, 0, len(violations))
	for _, violation := range violations {
		variable, ok := violation.Context["variable"].(string)
		require.True(t, ok)
		variables = append(variables, variable)
	}
	assert.ElementsMatch(t, []string{"fieldResp", "closureResp"}, variables)
}

// A response handed to a helper of the same file is released only when the
// helper closes it: the leak is one call away otherwise. The same rule as for
// SQL rows.
func TestHTTPBodyCloseRule_SameFileHelperMustClose(t *testing.T) {
	code := `package payprov

import (
	"io"
	"net/http"
)

func consume(resp *http.Response) ([]byte, error) {
	return io.ReadAll(resp.Body)
}

func closeBody(body io.Closer) { _ = body.Close() }

func leaks() ([]byte, error) {
	leakedResp, err := http.Get("http://example.com")
	if err != nil {
		return nil, err
	}
	b, err := consume(leakedResp)
	return b, err
}

func closes() error {
	resp, err := http.Get("http://example.com")
	if err != nil {
		return err
	}
	defer closeBody(resp.Body)
	return nil
}
`
	violations := runRuleOnFiles(t, NewHTTPBodyCloseRule(), map[string]string{"api.go": code})
	require.Len(t, violations, 1)
	assert.Equal(t, "leakedResp", violations[0].Context["variable"])
}

// A client helper that reads the body, closes it and hands back the response
// for its status and headers leaves nothing for the caller to close. A helper
// that returns the response unread still does.
func TestHTTPBodyCloseRule_HelperThatClosesTheBody(t *testing.T) {
	files := map[string]string{
		"client.go": `package payprov

import (
	"io"
	"net/http"
)

type Client struct{ http *http.Client }

func (c *Client) do(req *http.Request) (*http.Response, []byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, raw, nil
}

func (c *Client) send(req *http.Request) (*http.Response, error) {
	return c.http.Do(req)
}
`,
		"status.go": `package payprov

import "net/http"

func (c *Client) Status(req *http.Request) (string, error) {
	resp, raw, err := c.do(req)
	if err != nil {
		return "", err
	}
	return resp.Header.Get("X-Request-Id") + string(raw), nil
}

func (c *Client) Ping(req *http.Request) (int, error) {
	openResp, err := c.send(req)
	if err != nil {
		return 0, err
	}
	return openResp.StatusCode, nil
}
`,
	}
	violations := runRuleOnFiles(t, NewHTTPBodyCloseRule(), files)
	require.Len(t, violations, 1)
	assert.Equal(t, "openResp", violations[0].Context["variable"])
}
