package patterns

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A constructor derives a live flag from a client parameter being non-nil,
// and the handlers branch on the flag into mock quotes: a deployment that
// forgot the client's credentials serves made-up quotes with no error. A
// flag gated by configuration is left alone.
func TestSilentlyOptionalDependency_NilClientSwitchesToMock(t *testing.T) {
	project := decisionProject(t, map[string]string{
		"admin/admin.go": `package admin

import "errors"

type Client struct{}

type Admin struct {
	client *Client
	live   bool
	strict bool
}

func New(client *Client, cfg Config) *Admin {
	return &Admin{
		client: client,
		live:   client != nil,
		strict: cfg.Strict,
	}
}

type Config struct{ Strict, AllowMock bool }

type Guarded struct{ live bool }

func NewGuarded(client *Client, cfg Config) (*Guarded, error) {
	if client == nil && !cfg.AllowMock {
		return nil, errors.New("client is required unless mock mode is allowed")
	}
	return &Guarded{live: client != nil}, nil
}

func (g *Guarded) quote() string {
	if g.live {
		return "live"
	}
	return createMockGuarded()
}

func createMockGuarded() string { return "mock" }
`,
		"admin/quote.go": `package admin

func (a *Admin) quote() string {
	if a.live {
		return "live"
	}
	return a.createMockQuote()
}

func (a *Admin) createMockQuote() string { return "mock" }

func (a *Admin) check() string {
	if a.strict {
		return a.createMockQuote()
	}
	return ""
}
`,
	})
	violations, err := NewSilentlyOptionalDependencyRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	var got []string
	for _, v := range violations {
		got = append(got, v.File+":"+strconv.Itoa(v.Line))
	}
	assert.Equal(t, []string{"admin/admin.go:16"}, got)
}
