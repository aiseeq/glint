package output

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestSummaryOutputCountsBySeverity(t *testing.T) {
	violations := core.ViolationList{
		core.NewViolation("r-crit", "security", "a.go", 1, core.SeverityCritical, "m"),
		core.NewViolation("r-high", "patterns", "a.go", 2, core.SeverityHigh, "m"),
		core.NewViolation("r-high", "patterns", "b.go", 3, core.SeverityHigh, "m"),
		core.NewViolation("r-low", "naming", "b.go", 4, core.SeverityLow, "m"),
	}

	var buf bytes.Buffer
	err := NewSummaryOutput().WithWriter(&buf).Write(violations, Stats{FilesAnalyzed: 9, Duration: 0.5})
	require.NoError(t, err)
	got := buf.String()

	assert.Contains(t, got, "GLINT ANALYSIS SUMMARY")
	assert.Contains(t, got, "Critical: 1 | High: 2 | Medium: 0 | Low: 1")
	assert.Contains(t, got, "TOP ISSUES:")
	assert.Contains(t, got, "Files analyzed: 9 | Duration: 0.50s")

	// Top issues ordered by severity, rule with 2 hits shows its count.
	assert.Contains(t, got, "1. [CRITICAL] r-crit: 1 violations")
	assert.Contains(t, got, "2. [HIGH] r-high: 2 violations")
	assert.Contains(t, got, "3. [LOW] r-low: 1 violations")
}

func TestSummaryOutputEmptyList(t *testing.T) {
	var buf bytes.Buffer
	err := NewSummaryOutput().WithWriter(&buf).Write(nil, Stats{FilesAnalyzed: 4, Duration: 1.0})
	require.NoError(t, err)
	got := buf.String()

	assert.Contains(t, got, "Critical: 0 | High: 0 | Medium: 0 | Low: 0")
	assert.NotContains(t, got, "TOP ISSUES", "empty run must not print a top-issues section")
	assert.Contains(t, got, "Files analyzed: 4 | Duration: 1.00s")
}

func TestSummaryOutputTopIssuesLimitedToFive(t *testing.T) {
	var violations core.ViolationList
	for i := 0; i < 7; i++ {
		rule := fmt.Sprintf("rule-%d", i)
		violations = append(violations, core.NewViolation(rule, "patterns", "a.go", i+1, core.SeverityMedium, "m"))
	}

	var buf bytes.Buffer
	require.NoError(t, NewSummaryOutput().WithWriter(&buf).Write(violations, Stats{}))
	got := buf.String()

	assert.Contains(t, got, "5. [MEDIUM]")
	assert.NotContains(t, got, "6. [MEDIUM]", "top issues must be capped at 5")
	// Equal severity and count: ties broken by rule name for stable output.
	assert.Contains(t, got, "1. [MEDIUM] rule-0: 1 violations")
	assert.Contains(t, got, "5. [MEDIUM] rule-4: 1 violations")
}

func TestSummaryOutputOrdersByCountWithinSeverity(t *testing.T) {
	violations := core.ViolationList{
		core.NewViolation("rare", "patterns", "a.go", 1, core.SeverityMedium, "m"),
		core.NewViolation("frequent", "patterns", "a.go", 2, core.SeverityMedium, "m"),
		core.NewViolation("frequent", "patterns", "a.go", 3, core.SeverityMedium, "m"),
	}

	var buf bytes.Buffer
	require.NoError(t, NewSummaryOutput().WithWriter(&buf).Write(violations, Stats{}))
	got := buf.String()

	frequent := strings.Index(got, "frequent: 2 violations")
	rare := strings.Index(got, "rare: 1 violations")
	require.GreaterOrEqual(t, frequent, 0)
	require.GreaterOrEqual(t, rare, 0)
	assert.Less(t, frequent, rare, "higher count must rank first within one severity")
}

func TestSummaryOutputPropagatesWriteError(t *testing.T) {
	violations := core.ViolationList{
		core.NewViolation("r", "patterns", "a.go", 1, core.SeverityLow, "m"),
	}
	err := NewSummaryOutput().WithWriter(&failingWriter{failAfter: 1}).Write(violations, Stats{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
}
