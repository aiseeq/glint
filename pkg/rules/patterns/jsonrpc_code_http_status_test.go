package patterns

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func jsonRPCStatusFindings(t *testing.T, source string) []string {
	t.Helper()
	violations, err := NewJSONRPCCodeComparedToHTTPStatusRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{"rpc/client.go": source}))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

// A JSON-RPC error code is negative (-32005, -32429) and never equals an HTTP
// status: a retry decision made by HTTP statuses on it treats every RPC-level
// failure as fatal.
func TestJSONRPCCodeComparedToHTTPStatus(t *testing.T) {
	assert.Equal(t, []string{"rpc/client.go:43", "rpc/client.go:49"}, jsonRPCStatusFindings(t, `package rpc

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type rpcResponse struct {
	Result json.RawMessage `+"`json:\"result\"`"+`
	Error  *rpcError       `+"`json:\"error\"`"+`
	ID     int             `+"`json:\"id\"`"+`
}

type rpcError struct {
	Code    int    `+"`json:\"code\"`"+`
	Message string `+"`json:\"message\"`"+`
}

type apiError struct {
	Code    int    `+"`json:\"code\"`"+`
	Message string `+"`json:\"message\"`"+`
}

func statusIsRetryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable:
		return true
	default:
		return false
	}
}

func decode(resp *http.Response, body []byte) (json.RawMessage, bool, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, statusIsRetryable(resp.StatusCode), fmt.Errorf("http %d", resp.StatusCode)
	}
	var out rpcResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, false, err
	}
	if out.Error != nil {
		return nil, statusIsRetryable(out.Error.Code), fmt.Errorf("rpc error %d", out.Error.Code)
	}
	return out.Result, false, nil
}

func throttled(out rpcResponse) bool {
	return out.Error != nil && out.Error.Code == http.StatusTooManyRequests
}

func apiRetryable(body []byte) bool {
	var e apiError
	if err := json.Unmarshal(body, &e); err != nil {
		return false
	}
	return statusIsRetryable(e.Code)
}
`))
}

func TestJSONRPCCodeComparedToHTTPStatusRule_Metadata(t *testing.T) {
	rule := NewJSONRPCCodeComparedToHTTPStatusRule()
	assert.Equal(t, "jsonrpc-code-compared-to-http-status", rule.Name())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}
