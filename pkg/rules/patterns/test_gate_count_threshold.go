package patterns

import (
	"regexp"
	"slices"
	"strconv"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewTestGateCountThresholdRule())
}

// TestGateCountThresholdRule detects a test gate that lets a number of
// problems through:
//
//	expect(highIssues).toBeLessThanOrEqual(7) // headroom for advisory drift
//
// The slack is spent on whatever comes: a new, fixable vulnerability enters
// unnoticed while the count stays under the bound. The gate holds when it
// asserts zero and names the accepted findings in an explicit list.
type TestGateCountThresholdRule struct {
	*rules.BaseRule
}

// NewTestGateCountThresholdRule creates the rule
func NewTestGateCountThresholdRule() *TestGateCountThresholdRule {
	return &TestGateCountThresholdRule{BaseRule: rules.NewBaseRule(
		"test-gate-count-threshold-instead-of-allowlist",
		"patterns",
		"Detects a test asserting a count of issues, vulnerabilities or errors stays under a bound above zero — new problems pass while the count fits the slack; assert zero with an explicit list of accepted findings",
		core.SeverityMedium,
	)}
}

var (
	countUnderBound = regexp.MustCompile(`expect\s*\(\s*([A-Za-z_$][\w$]*)(?:\.length)?\s*\)\s*\.\s*(toBeLessThanOrEqual|toBeLessThan)\s*\(\s*(\d+)\s*\)`)
	// problemWords name a count of problems.
	problemWords = []string{"issue", "issues", "vulnerability", "vulnerabilities", "vuln", "vulns", "finding", "findings",
		"violation", "violations", "error", "errors", "warning", "warnings", "problem", "problems", "failure", "failures"}
)

// AnalyzeFile reports the gates of a test file that let problems through.
func (r *TestGateCountThresholdRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !jsTestFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range newJSSource(ctx).code {
		m := countUnderBound.FindStringSubmatch(line)
		if m == nil || !slices.ContainsFunc(helpers.IdentifierWords(m[1]), func(w string) bool { return slices.Contains(problemWords, w) }) {
			continue
		}
		bound, err := strconv.Atoi(m[3])
		if err != nil || (m[2] == "toBeLessThanOrEqual" && bound < 1) || (m[2] == "toBeLessThan" && bound < 2) {
			continue
		}
		if ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		violations = append(violations, testReport(r.BaseRule, ctx, i+1,
			"The gate lets up to "+strconv.Itoa(boundAllowed(m[2], bound))+" "+m[1]+" through — a new problem passes while the count fits the slack",
			"Assert zero and list the accepted findings by name (advisory id, rule, file) next to the gate"))
	}
	return violations
}

// boundAllowed is the largest count the assertion accepts.
func boundAllowed(matcher string, bound int) int {
	if matcher == "toBeLessThan" {
		return bound - 1
	}
	return bound
}
