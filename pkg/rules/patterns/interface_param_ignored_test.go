package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// The interface takes a period end; the implementation blanks it and always
// reports up to the latest snapshot, whatever range the caller asked for.
func TestInterfaceParamIgnored(t *testing.T) {
	violations, err := NewInterfaceParamIgnoredRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"profit/profit.go": `package profit

import (
	"context"
	"time"
)

type Calculator interface {
	PlatformProfit(ctx context.Context, strategy string, periodStart, periodEnd time.Time) (int, error)
	Label(code string, _ bool) string
	Window(from, to time.Time) int
	Send(to string, retries int) error
}

type Service struct{}

func (s *Service) PlatformProfit(_ context.Context, strategy string, periodStart, _ time.Time) (int, error) {
	return len(strategy) + periodStart.Day(), nil
}

func (s *Service) Label(code string, _ bool) string { return code }

func (s *Service) Other(_ string) {}

func (s *Service) Window(_, _ time.Time) int { return 0 }

func (s *Service) Send(to string, _ int) error { return nil }

var _ Calculator = (*Service)(nil)
`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"profit/profit.go:17"}, foundLines(violations))
}
