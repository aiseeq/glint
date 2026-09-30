package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const silentRatesSource = `package rates

import "strconv"

type Rate struct{ V int }

func LatestA(s string) *Rate {
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &Rate{V: v}
}
`

// Only test files are skipped: latest_rates.go contains "test_" and a
// testimonials directory starts with "/test", yet both are production code.
func TestSilentErrorHandling_ProductionFilesWithTestLikeNames(t *testing.T) {
	for _, path := range []string{"rates/latest_rates.go", "web/testimonials/rates.go", "rates/test.go"} {
		t.Run(path, func(t *testing.T) {
			ctx := rulestest.GoFile(t, path, silentRatesSource)
			assert.Equal(t, []int{9}, violationLines(NewSilentErrorHandlingRule().AnalyzeFile(ctx)))
		})
	}
}

// A declared function answering with one bool leaves its error branches that
// return true/false to error-masked-as-false-bool and error-masking; the same
// branch is not reported by two rules.
func TestSilentErrorHandling_BoolFunctionBranchBelongsToBoolRules(t *testing.T) {
	const source = `package p

import "strconv"

func Publish(s string) bool {
	_, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return true
}

func Process(s string) bool {
	_, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return true
}
`
	ctx := rulestest.GoFile(t, "p/p.go", source)
	assert.Empty(t, NewSilentErrorHandlingRule().AnalyzeFile(ctx))
}
