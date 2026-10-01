package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A threshold configured as 0 means "off" — the webhook check knows it, the
// inactivity check compares against 0 and warns after every success.
func TestZeroThresholdNotHonored(t *testing.T) {
	violations, err := NewZeroThresholdNotHonoredRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"health/monitor.go": `package health

import "time"

type Thresholds struct {
	Inactivity        time.Duration
	WebhookInactivity time.Duration
	Timeout           time.Duration
	Failures          int
	Retries           int
}

var defaults = map[string]Thresholds{
	"api":  {Inactivity: time.Hour, WebhookInactivity: 12 * time.Hour, Timeout: time.Second, Failures: 3, Retries: 2},
	"mail": {Inactivity: 0, WebhookInactivity: 0, Timeout: time.Second, Failures: 0, Retries: 0},
}

type Status struct {
	LastSuccess, LastWebhook time.Time
	Failures, Attempts       int
	Warning                  bool
}

func checkInactivity(s *Status, t Thresholds, now time.Time) {
	if now.Sub(s.LastSuccess) <= t.Inactivity {
		return
	}
	s.Warning = true
}

func checkWebhook(s *Status, t Thresholds, now time.Time) {
	if t.WebhookInactivity <= 0 {
		return
	}
	if now.Sub(s.LastWebhook) <= t.WebhookInactivity {
		return
	}
	s.Warning = true
}

func checkFailures(s *Status, t Thresholds) {
	if s.Failures >= t.Failures {
		s.Warning = true
	}
}

func slow(elapsed time.Duration, t Thresholds) bool {
	return elapsed > t.Timeout
}

func byFailures(ts []Thresholds) func(i, j int) bool {
	return func(i, j int) bool { return ts[i].Failures < ts[j].Failures }
}

func retry(s *Status, t Thresholds) bool {
	if t.Retries == 0 {
		return false
	}
	return s.Attempts < t.Retries
}
`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"health/monitor.go:25", "health/monitor.go:42"}, foundLines(violations))
}
