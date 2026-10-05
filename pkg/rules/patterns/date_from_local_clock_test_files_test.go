package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A test seeds today's rates with the host's clock while production reads
// them by the project's own business-day helper: around midnight in the
// business zone the test writes one day and the code reads another.
func TestDateFromLocalClock_TestSeedsTodayWithHostClock(t *testing.T) {
	helper := `package domain

import "time"

var BusinessZone = time.UTC

func TodayRateDate() time.Time {
	now := time.Now().In(BusinessZone)
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}
`
	test := `package domain

import (
	"testing"
	"time"
)

type repo struct{}

func (repo) Upsert(pair string, day time.Time) error { return nil }

func createSession(created time.Time) error { return nil }

func TestQuote(t *testing.T) {
	today := time.Now()
	if err := upsertRates(t); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_ = time.Since(started)
	_ = createSession(time.Now())
	_ = today
}

func upsertRates(t *testing.T) error {
	return (repo{}).Upsert("AAA/BBB", time.Now())
}
`
	violations, err := NewDateFromLocalClockRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"domain/date.go": helper, "domain/date_test.go": test,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"domain/date_test.go:15", "domain/date_test.go:26"}, foundLines(violations))

	violations, err = NewDateFromLocalClockRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"domain/date_test.go": test,
	}))
	require.NoError(t, err)
	assert.Empty(t, violations, "without a business-day helper there is nothing the test should use")
}
