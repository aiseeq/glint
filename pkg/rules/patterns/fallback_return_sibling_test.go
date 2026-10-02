package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A failed source answered by a sibling source with the same arguments: the
// caller gets the second source's answer as if it were the first, and the
// failure that made the switch is only in the log.
func TestFallbackReturn_SiblingSourceAfterFailure(t *testing.T) {
	const source = `package svc

func (s *Service) fetchBalance(ctx context.Context, address string, out *Balance) error {
	if err := s.fetchPrimary(ctx, address, out); err != nil {
		s.logger.Warn("primary failed, falling back", "error", err)
		out.Tokens = nil
		return s.fetchSecondary(ctx, address, out)
	}
	return nil
}

func (s *Service) fetchMarked(ctx context.Context, address string, out *Balance) error {
	if err := s.fetchPrimary(ctx, address, out); err != nil {
		out.Warning = "primary unavailable: " + err.Error()
		return s.fetchSecondary(ctx, address, out)
	}
	return nil
}

func (s *Service) fetchJoined(ctx context.Context, address string, out *Balance) error {
	if err := s.fetchPrimary(ctx, address, out); err != nil {
		return errors.Join(err, s.fetchSecondary(ctx, address, out))
	}
	return nil
}

func (s *Service) retry(ctx context.Context, address string, out *Balance) error {
	if err := s.fetchPrimary(ctx, address, out); err != nil {
		return s.fetchPrimary(ctx, address, out)
	}
	return nil
}
`
	violations := NewFallbackReturnRule().AnalyzeFile(rulestest.GoFile(t, "svc/balance.go", source))
	assert.Equal(t, []int{7}, violationLines(violations))
}

// An identifier mapper answers a key it does not know with the key itself:
// the caller sends a ticker where an id is expected, and the lookup it feeds
// misses silently. A label mapper doing the same shows the raw key, which is
// visible, and is left alone.
func TestFallbackReturn_IdentifierMapperReturnsInput(t *testing.T) {
	const source = `package prices

import "strings"

var coinIDs = map[string]string{"btc": "bitcoin"}

func tickerToCoinID(ticker string) string {
	lower := strings.ToLower(ticker)
	if id, ok := coinIDs[lower]; ok {
		return id
	}
	return lower
}

func tickerLabel(ticker string) string {
	if label, ok := coinIDs[ticker]; ok {
		return label
	}
	return ticker
}

func tickerToCoinIDChecked(ticker string) (string, error) {
	if id, ok := coinIDs[ticker]; ok {
		return id, nil
	}
	return "", fmt.Errorf("unknown ticker %s", ticker)
}
`
	violations := NewFallbackReturnRule().AnalyzeFile(rulestest.GoFile(t, "prices/ids.go", source))
	assert.Equal(t, []int{12}, violationLines(violations))
}
