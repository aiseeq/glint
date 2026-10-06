package patterns

import "testing"

// A query value mapped by a switch whose default returns a preset: a typo or
// an unsupported value is answered as if the client asked for the preset
// ("all time") instead of being refused. A parser that can return an error,
// or a switch fed by something other than the request, is fine.
func TestQueryValueFallsBackToDefault(t *testing.T) {
	assertWanted(t, NewQueryValueFallsBackToDefaultRule(), `package routing

import (
	"fmt"
	"net/http"
	"time"
)

func ParsePeriod(period string) (time.Time, string) {
	now := time.Now()
	switch period {
	case "7d":
		return now.Add(-7 * 24 * time.Hour), period
	case "30d":
		return now.Add(-30 * 24 * time.Hour), period
	default:
		return time.Time{}, "all" // want
	}
}

func ResolveWindow(periodParam string, previous bool) (time.Time, string) {
	since, period := ParsePeriod(periodParam)
	return since, period
}

func ParsePeriodStrict(period string) (time.Time, error) {
	switch period {
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour), nil
	case "", "all":
		return time.Time{}, nil
	default:
		return time.Time{}, fmt.Errorf("invalid period %q", period)
	}
}

func colorOf(level string) string {
	switch level {
	case "warn":
		return "yellow"
	case "error":
		return "red"
	default:
		return "gray"
	}
}

func handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	_, _ = ResolveWindow(q.Get("period"), false)
	_, _ = ParsePeriodStrict(r.URL.Query().Get("period"))
	_ = colorOf("warn")
}
`)
}
