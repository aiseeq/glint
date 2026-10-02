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

func ownWaitOutageFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewOwnWaitReportedAsOutageRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

const ownWaitClientSource = `package enrich

import (
	"context"
	"fmt"
	"time"
)

type Client struct {
	gate     chan struct{}
	lastCall time.Time
}

// Search waits for its own rate limiter before asking the provider.
func (c *Client) Search(ctx context.Context, wallet string) ([]string, error) {
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("acquire rate limit: %w", ctx.Err())
	}
	defer func() { <-c.gate }()
	if wait := 6*time.Second - time.Since(c.lastCall); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for rate limit: %w", ctx.Err())
		case <-timer.C:
		}
	}
	return []string{wallet}, nil
}

// Lookup asks the provider right away.
func (c *Client) Lookup(ctx context.Context, wallet string) ([]string, error) {
	if wallet == "" {
		return nil, fmt.Errorf("wallet is required")
	}
	return []string{wallet}, nil
}
`

// A call that waits on the client's own limiter inside our time budget ends
// with our deadline; marking that as the provider's outage blames a service
// that was never asked.
func TestOwnWaitReportedAsOutage(t *testing.T) {
	assert.Equal(t, []string{"enrich/service.go:24"}, ownWaitOutageFindings(t, map[string]string{
		"enrich/client.go": ownWaitClientSource,
		"enrich/service.go": `package enrich

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

const (
	metadataUnavailable = "provider_unavailable"
	metadataStale       = "provider_stale"
)

type Service struct{ client *Client }

func mark(marks map[string]string, wallet, code string) { marks[wallet] = code }

func (s *Service) attach(ctx context.Context, wallets []string, marks map[string]string) {
	budget, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for _, wallet := range wallets {
		_, err := s.client.Search(budget, wallet)
		if err != nil {
			mark(marks, wallet, metadataUnavailable)
			continue
		}
	}
}

func (s *Service) attachChecked(ctx context.Context, wallets []string, marks map[string]string) {
	budget, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for _, wallet := range wallets {
		_, err := s.client.Search(budget, wallet)
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			mark(marks, wallet, metadataStale)
		case err != nil:
			mark(marks, wallet, metadataUnavailable)
		}
	}
}

func (s *Service) attachDirect(ctx context.Context, wallets []string, marks map[string]string) {
	budget, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for _, wallet := range wallets {
		if _, err := s.client.Lookup(budget, wallet); err != nil {
			mark(marks, wallet, metadataUnavailable)
		}
	}
}

func (s *Service) attachLogged(ctx context.Context, wallets []string, logger *slog.Logger) {
	budget, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for _, wallet := range wallets {
		if _, err := s.client.Search(budget, wallet); err != nil {
			logger.Warn("provider unavailable", "wallet", wallet)
		}
	}
}

func (s *Service) attachCallerContext(ctx context.Context, wallets []string, marks map[string]string) {
	for _, wallet := range wallets {
		if _, err := s.client.Search(ctx, wallet); err != nil {
			mark(marks, wallet, metadataUnavailable)
		}
	}
}
`,
	}))
}

func TestOwnWaitReportedAsOutageRule_Metadata(t *testing.T) {
	rule := NewOwnWaitReportedAsOutageRule()
	assert.Equal(t, "own-wait-reported-as-outage", rule.Name())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}
