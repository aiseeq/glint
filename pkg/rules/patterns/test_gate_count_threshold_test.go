package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A security gate lets up to seven high vulnerabilities through "for
// advisory drift": a new, fixable one enters unnoticed while the count stays
// under the slack. Zero with a named list of accepted findings is the gate;
// a bound on something that is not a count of problems is not this rule's.
func TestTestGateCountThreshold(t *testing.T) {
	ctx := rulestest.TextFile(t, "src/__tests__/security/scan.test.ts", `describe('security', () => {
  it('has no high vulnerabilities', () => {
    const highIssues = results.filter(i => i.severity === 'HIGH').length
    expect(highIssues).toBeLessThanOrEqual(7)
    expect(vulnerabilities.length).toBeLessThan(3)
    expect(criticalIssues).toBe(0)
    expect(lintWarnings).toBeLessThanOrEqual(0)
    expect(status).toBeLessThan(400)
    expect(retries).toBeLessThanOrEqual(3)
    expect(errorCount).toBeLessThan(1)
  })
})
`)
	assert.Equal(t, []int{4, 5}, violationLines(NewTestGateCountThresholdRule().AnalyzeFile(ctx)))

	production := rulestest.TextFile(t, "src/report.ts", "expect(highIssues).toBeLessThanOrEqual(7)\n")
	assert.Empty(t, NewTestGateCountThresholdRule().AnalyzeFile(production))
}
