package patterns

import (
	"go/ast"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnboundedResponseReadRule_Metadata(t *testing.T) {
	rule := NewUnboundedResponseReadRule()

	assert.Equal(t, "unbounded-response-read", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestUnboundedResponseReadRule_Detection(t *testing.T) {
	rule := NewUnboundedResponseReadRule()

	tests := []struct {
		name      string
		path      string
		code      string
		wantCount int
	}{
		{
			name: "ProPay client Do response body",
			path: "client.go",
			code: `package payment

import (
	"io"
	"net/http"
)

func send(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}`,
			wantCount: 1,
		},
		{
			name: "package http Get response body",
			path: "fetch.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch() {
	resp, _ := http.Get("https://example.com")
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 1,
		},
		{
			name: "aliased package Get response body",
			path: "aliased_fetch.go",
			code: `package fetch

import (
	"io"
	nethttp "net/http"
)

func fetch() {
	resp, _ := nethttp.Get("https://example.com")
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 1,
		},
		{
			name: "client Post response body",
			path: "post.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func post(client *http.Client) {
	resp, _ := client.Post("https://example.com", "text/plain", nil)
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 1,
		},
		{
			name: "incoming request body",
			path: "handler.go",
			code: `package handler

import (
	"io"
	"net/http"
)

func handle(r *http.Request) {
	_, _ = io.ReadAll(r.Body)
}`,
			wantCount: 0,
		},
		{
			name: "arbitrary Do method is not HTTP",
			path: "executor.go",
			code: `package execute

import (
	"io"
	"net/http"
)

type result struct { Body io.Reader }
type executor struct{}

func (executor) Do() (*result, error) { return nil, nil }

func run(worker executor) {
	_ = http.MethodGet
	resp, _ := worker.Do()
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "custom Do with HTTP request is not HTTP client",
			path: "custom_worker.go",
			code: `package execute

import (
	"io"
	"net/http"
)

type customResult struct { Body io.Reader }
type worker struct{}

func (worker) Do(req *http.Request) (*customResult, error) { return nil, nil }

func run(w worker, req *http.Request) {
	resp, _ := w.Do(req)
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "aliased typed HTTP client Do response body",
			path: "aliased_client.go",
			code: `package fetch

import (
	"io"
	nethttp "net/http"
)

func fetch(customClient *nethttp.Client, req *nethttp.Request) {
	resp, _ := customClient.Do(req)
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 1,
		},
		{
			name: "file read",
			path: "file.go",
			code: `package files

import (
	"io"
	"os"
)

func read(file *os.File) {
	_, _ = io.ReadAll(file)
}`,
			wantCount: 0,
		},
		{
			name: "bounded response body",
			path: "bounded.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch() {
	resp, _ := http.Get("https://example.com")
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}`,
			wantCount: 0,
		},
		{
			name: "non HTTP Body field",
			path: "message.go",
			code: `package message

import "io"

type message struct { Body io.Reader }

func read(msg message) {
	_, _ = io.ReadAll(msg.Body)
}`,
			wantCount: 0,
		},
		{
			name: "response assigned in another function",
			path: "scope.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

var resp *http.Response

func assign() {
	resp, _ = http.Get("https://example.com")
}

func read() {
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "read before response assignment",
			path: "order.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch(resp *http.Response) {
	_, _ = io.ReadAll(resp.Body)
	resp, _ = http.Get("https://example.com")
}`,
			wantCount: 0,
		},
		{
			name: "nested function is separate scope",
			path: "nested.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch() {
	resp, _ := http.Get("https://example.com")
	func() {
		_, _ = io.ReadAll(resp.Body)
	}()
}`,
			wantCount: 0,
		},
		{
			name: "shadowed response name is not HTTP response",
			path: "shadowed.go",
			code: `package fetch

import (
	"io"
	"net/http"
	"strings"
)

func fetch() {
	resp, _ := http.Get("https://example.com")
	_ = resp
	{
		resp := struct{ Body io.Reader }{Body: strings.NewReader("safe")}
		_, _ = io.ReadAll(resp.Body)
	}
}`,
			wantCount: 0,
		},
		{
			name: "response variable reassigned before read",
			path: "reassigned.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch() {
	resp, _ := http.Get("https://example.com")
	resp = &http.Response{Body: http.NoBody}
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "conditional non-response reassignment preserves possible response",
			path: "conditional_reassignment.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch(reset bool) {
	resp, _ := http.Get("https://example.com")
	if reset {
		resp = &http.Response{Body: http.NoBody}
	}
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 1,
		},
		{
			name: "returning branch response does not reach later read",
			path: "returning_branch.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch(resp *http.Response, stop bool) {
	if stop {
		resp, _ = http.Get("https://example.com")
		return
	}
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "read after unconditional return is unreachable",
			path: "unreachable.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch() {
	resp, _ := http.Get("https://example.com")
	return
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "break skips response assignment",
			path: "break_assignment.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch(resp *http.Response) {
	for {
		break
		resp, _ = http.Get("https://example.com")
	}
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "break preserves response and skips unreachable read",
			path: "break_read.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch() {
	var resp *http.Response
	for {
		resp, _ = http.Get("https://example.com")
		break
		_, _ = io.ReadAll(resp.Body)
	}
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 1,
		},
		{
			name: "continue skips response assignment",
			path: "continue_assignment.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch(resp *http.Response) {
	for i := 0; i < 1; i++ {
		continue
		resp, _ = http.Get("https://example.com")
	}
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "continue preserves response and skips unreachable read",
			path: "continue_read.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch() {
	var resp *http.Response
	for i := 0; i < 1; i++ {
		resp, _ = http.Get("https://example.com")
		continue
		_, _ = io.ReadAll(resp.Body)
	}
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 1,
		},
		{
			name: "panic skips unreachable assignment and read",
			path: "panic.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch(resp *http.Response) {
	panic("stop")
	resp, _ = http.Get("https://example.com")
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "if init response does not escape its scope",
			path: "if_init_scope.go",
			code: `package fetch

import (
	"io"
	"net/http"
	"strings"
)

func fetch(client *http.Client, req *http.Request) {
	resp := struct{ Body io.Reader }{Body: strings.NewReader("safe")}
	if resp, err := client.Do(req); err == nil {
		_ = resp
	}
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "self-contained closure response body",
			path: "closure.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch() {
	func() {
		resp, _ := http.Get("https://example.com")
		_, _ = io.ReadAll(resp.Body)
	}()
}`,
			wantCount: 1,
		},
		{
			name: "standard suppression",
			path: "suppressed.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch() {
	resp, _ := http.Get("https://example.com")
	//nolint:unbounded-response-read -- endpoint has a documented hard limit
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
		{
			name: "test file excluded",
			path: "client_test.go",
			code: `package fetch

import (
	"io"
	"net/http"
)

func fetch() {
	resp, _ := http.Get("https://example.com")
	_, _ = io.ReadAll(resp.Body)
}`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createUnboundedResponseReadContext(t, tt.path, tt.code)
			violations := rule.AnalyzeFile(ctx)
			require.Len(t, violations, tt.wantCount)
			if tt.wantCount == 0 {
				return
			}

			require.NotEmpty(t, violations[0].Suggestion)
			assert.Equal(t, "unbounded_response_read", violations[0].Context["pattern"])
			assert.Equal(t, "resp", violations[0].Context["variable"])
			assert.Contains(t, violations[0].Code, "io.ReadAll(resp.Body)")
		})
	}
}

func TestUnboundedResponseAnalyzer_UnexpectedClausesDoNotPanic(t *testing.T) {
	analyzer := &unboundedResponseAnalyzer{}
	state := newResponseState()

	require.NotPanics(t, func() {
		analyzer.checkClauses([]ast.Stmt{&ast.EmptyStmt{}}, state)
		analyzer.checkSelect(&ast.SelectStmt{
			Body: &ast.BlockStmt{List: []ast.Stmt{&ast.EmptyStmt{}}},
		}, state)
	})
}

func createUnboundedResponseReadContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   strings.Split(code, "\n"),
		Content: []byte(code),
	}
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile(path, []byte(code))
	require.NoError(t, err)
	ctx.SetGoAST(fset, astFile)
	return ctx
}
