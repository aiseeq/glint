package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// The default client has no timeout: a node that accepts the connection
// and never answers holds the caller forever.
func TestHTTPDefaultClient(t *testing.T) {
	rule := NewHTTPDefaultClientRule()
	lines := violationLines(rule.AnalyzeFile(rulestest.GoFile(t, "chain/rpc.go", `package chain

import (
	"bytes"
	"context"
	"net/http"
	"time"
)

func Call(ctx context.Context, url string, body []byte) error {
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if _, err := http.Get(url); err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if _, err := http.DefaultClient.Do(req); err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	if _, err := client.Post(url, "application/json", nil); err != nil {
		return err
	}
	return nil
}

func WithContext(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	_, err = http.DefaultClient.Do(req)
	return err
}

func WithoutContext(url string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	_, err = http.DefaultClient.Do(req)
	return err
}

func Shadowed(url string) {
	http := fakeClient{}
	http.Get(url)
}

func Rebound(ctx context.Context, url string) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req = req.WithContext(ctx)
	http.DefaultClient.Do(req)
}
`)))
	// A request built with NewRequestWithContext carries its cancellation
	// and deadline; one from NewRequest does not.
	assert.Equal(t, []int{11, 16, 44}, lines)

	assert.Empty(t, rule.AnalyzeFile(rulestest.GoFile(t, "chain/rpc_test.go", `package chain

import "net/http"

func probe(url string) { http.Get(url) }
`)))
}
