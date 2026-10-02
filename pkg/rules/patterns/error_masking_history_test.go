package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// Variants of error masking found in the history of a consumer project:
// a zero struct in an error branch, a switch default that answers an unknown
// value with a valid member, a parse helper whose default stands in for an
// unparsable request parameter, and a price left at zero when its fetch
// fails with only a Debug line.
func TestErrorMaskingRule_HistoryVariants(t *testing.T) {
	rule := NewErrorMaskingRule()
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "zero time returned from a parse error branch",
			code: `package report

import "time"

func endOfDay(day string) time.Time {
	parsed, err := time.Parse("2006-01-02", day)
	if err != nil {
		return time.Time{}
	}
	return parsed.Add(24*time.Hour - time.Nanosecond)
}
`,
			want: 1,
		},
		{
			name: "empty slice literal in an error branch stays with nil",
			code: `package report

func names(raw string) []string {
	parts, err := split(raw)
	if err != nil {
		return []string{}
	}
	return parts
}
`,
			want: 0,
		},
		{
			name: "switch default answers an unknown basis with a valid member",
			code: `package fees

func feeBasis(basis string, gross, committed Amount) Amount {
	switch basis {
	case BasisGross:
		return gross
	case BasisCommitted:
		return committed
	default:
		return gross
	}
}
`,
			want: 1,
		},
		{
			name: "switch default answers an unknown frequency with a case's literal",
			code: `package fees

func periodsPerYear(frequency string) int64 {
	switch frequency {
	case FrequencyMonthly:
		return 12
	case FrequencyQuarterly:
		return 4
	case FrequencyAnnually:
		return 1
	default:
		return 1
	}
}
`,
			want: 1,
		},
		{
			name: "switch default with its own value is a deliberate fallback",
			code: `package fees

func label(kind string) string {
	switch kind {
	case KindA:
		return "A"
	case KindB:
		return "B"
	default:
		return "unknown"
	}
}
`,
			want: 0,
		},
		{
			name: "switch with an error result reports the unknown value",
			code: `package fees

func periodsPerYear(frequency string) (int64, error) {
	switch frequency {
	case FrequencyMonthly:
		return 12, nil
	default:
		return 12, nil
	}
}
`,
			want: 0,
		},
		{
			name: "parse helper's default stands in for an unparsable query parameter",
			code: `package routing

import (
	"net/http"
	"strconv"
)

func parseInt(s string, defaultValue int) int {
	if val, err := strconv.Atoi(s); err == nil {
		return val
	}
	return defaultValue
}

func listQuery(req *http.Request) (int, int) {
	limit := parseInt(req.URL.Query().Get("limit"), 50)
	offset := parseInt(req.URL.Query().Get("offset"), 0)
	return limit, offset
}
`,
			want: 1,
		},
		{
			name: "parse helper used only on configuration is left alone",
			code: `package routing

import "strconv"

func parseInt(s string, defaultValue int) int {
	if val, err := strconv.Atoi(s); err == nil {
		return val
	}
	return defaultValue
}

func workers(cfg map[string]string) int {
	return parseInt(cfg["workers"], 4)
}
`,
			want: 0,
		},
		{
			name: "price left at zero when the fetch fails with a debug line",
			code: `package balance

import "github.com/shopspring/decimal"

func (s *Service) tokens(ctx context.Context, amounts []decimal.Decimal) []decimal.Decimal {
	nativeUSD := decimal.Zero
	if s.prices != nil {
		if p, perr := s.prices.GetPrice(ctx, "native"); perr == nil {
			nativeUSD = p
		} else {
			s.logger.Debug("native price fetch failed", "error", perr)
		}
	}
	out := make([]decimal.Decimal, 0, len(amounts))
	for _, a := range amounts {
		out = append(out, a.Mul(nativeUSD))
	}
	return out
}
`,
			want: 1,
		},
		{
			name: "warned failure in the else branch is handled",
			code: `package balance

import "github.com/shopspring/decimal"

func (s *Service) price(ctx context.Context) decimal.Decimal {
	var usd decimal.Decimal
	if p, perr := s.prices.GetPrice(ctx, "native"); perr == nil {
		usd = p
	} else {
		s.logger.Warn("native price fetch failed", "error", perr)
	}
	return usd
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := rule.AnalyzeFile(rulestest.GoFile(t, "service.go", tt.code))
			if len(violations) != tt.want {
				t.Errorf("got %d violations, want %d: %v", len(violations), tt.want, violations)
			}
		})
	}
}

// A zero value next to a custom error type in the last slot hands the
// failure over; a map filled under a success guard is a container, not a
// zero left behind.
func TestErrorMaskingRule_HistoryVariantsNotFlagged(t *testing.T) {
	rule := NewErrorMaskingRule()
	for name, code := range map[string]string{
		"custom error type next to a zero struct": `package q

type Query struct{ Date string }

type QueryError struct{ Message string }

func (e *QueryError) Error() string { return e.Message }

func parse(raw string) (Query, *QueryError) {
	if _, err := time.Parse("2006-01-02", raw); err != nil {
		return Query{}, &QueryError{Message: "date: expected YYYY-MM-DD"}
	}
	return Query{Date: raw}, nil
}
`,
		"named enum type maps its unknown members to a fail-safe": `package q

func convert(status upstream.Status) Status {
	switch status {
	case upstream.Healthy:
		return Healthy
	case upstream.Unhealthy:
		return Unhealthy
	default:
		return Unhealthy
	}
}
`,
		"fail collects the problem before the zero struct": `package q

func money(v string, fail func(string)) decimal.Decimal {
	d, err := decimal.NewFromString(v)
	if err != nil {
		fail("not a number")
		return decimal.Decimal{}
	}
	return d
}
`,
		"set filled under a success guard": `package q

func stale(ids []string) map[string]bool {
	out := map[string]bool{}
	for _, id := range ids {
		if pair, err := classify(id); err == nil && pair != nil {
			out[pair.Source] = true
		}
	}
	return out
}
`,
	} {
		t.Run(name, func(t *testing.T) {
			violations := rule.AnalyzeFile(rulestest.GoFile(t, "service.go", code))
			if len(violations) != 0 {
				t.Errorf("got %v", violations)
			}
		})
	}
}
