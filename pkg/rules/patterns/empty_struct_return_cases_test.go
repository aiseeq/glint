package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func emptyStructReturnLines(t *testing.T, path, source string) []int {
	t.Helper()
	ctx := rulestest.GoFile(t, path, source)
	return violationLines(NewEmptyStructReturnRule().AnalyzeFile(ctx))
}

// Only test files are skipped: latest_rates.go contains "test_" and a
// testimonials directory starts with "/test", yet both are production code.
func TestEmptyStructReturn_ProductionFilesWithTestLikeNames(t *testing.T) {
	const source = `package rates

import "strconv"

type Rate struct{ V int }

func Latest(s string) (Rate, error) {
	v, err := strconv.Atoi(s)
	if err != nil {
		return Rate{}, nil
	}
	return Rate{V: v}, nil
}
`
	for _, path := range []string{"rates/latest_rates.go", "web/testimonials/rates.go", "rates/testing.go"} {
		t.Run(path, func(t *testing.T) {
			assert.Equal(t, []int{10}, emptyStructReturnLines(t, path, source))
		})
	}
}

// The error branch can sit in a loop, a switch case or a select case.
func TestEmptyStructReturn_ErrorBranchInLoopAndCase(t *testing.T) {
	const source = `package p

import "strconv"

type Rate struct{ V int }

func First(ss []string) (Rate, error) {
	for _, s := range ss {
		v, err := strconv.Atoi(s)
		if err != nil {
			return Rate{}, nil
		}
		return Rate{V: v}, nil
	}
	return Rate{V: 1}, nil
}

func Pick(s string) (Rate, error) {
	switch s {
	case "a":
		v, err := strconv.Atoi(s)
		if err != nil {
			return Rate{}, nil
		}
		return Rate{V: v}, nil
	}
	return Rate{V: 2}, nil
}

func Wait(ch chan string) (Rate, error) {
	select {
	case s := <-ch:
		v, err := strconv.Atoi(s)
		if err != nil {
			return Rate{}, nil
		}
		return Rate{V: v}, nil
	}
}
`
	assert.Equal(t, []int{11, 23, 35}, emptyStructReturnLines(t, "p/p.go", source))
}
