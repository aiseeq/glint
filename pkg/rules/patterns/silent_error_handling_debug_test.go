package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A failure recorded only at Debug level is off in production: the function
// goes on with partial data as if nothing failed.
func TestSilentErrorHandling_DebugLogIsNotHandling(t *testing.T) {
	const source = `package svc

func (s *Service) positions(ctx context.Context, address string) ([]Position, []Position, error) {
	wallet, err := s.client.Wallet(ctx, address)
	if err != nil {
		return nil, nil, err
	}
	defi, defiErr := s.client.DeFi(ctx, address)
	if defiErr != nil {
		s.logger.Debug("defi positions failed, using wallet only", "error", defiErr)
	}
	extra, extraErr := s.client.Extra(ctx, address)
	if extraErr != nil {
		s.logger.Warn("extra positions failed", "error", extraErr)
	}
	return wallet, append(defi, extra...), nil
}
`
	violations := NewSilentErrorHandlingRule().AnalyzeFile(rulestest.GoFile(t, "svc/positions.go", source))
	assert.Equal(t, []int{9}, violationLines(violations))
}

// A failed Close or drain produces no data to lose: a Debug line there is the
// handling.
func TestSilentErrorHandling_DebugLogOnCloseIsHandling(t *testing.T) {
	const source = `package svc

func drainAndClose(body io.ReadCloser) {
	if _, err := io.Copy(io.Discard, body); err != nil {
		slog.Debug("drain response body", "error", err)
	}
	if err := body.Close(); err != nil {
		slog.Debug("close response body", "error", err)
	}
}
`
	assert.Empty(t, violationLines(NewSilentErrorHandlingRule().AnalyzeFile(rulestest.GoFile(t, "svc/drain.go", source))))
}
