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

// A chain of matchers answers "not a candidate" with the empty match. When the
// file's functions return that empty value as a regular answer, a matcher that
// says it only under a nil guard ("the operation has no loan") gives the same
// answer, not a hidden failure. A nil guard over a type the file never answers
// empty with, and an error check, stay reported.
func TestEmptyStructReturn_EmptyAnswerOfSiblingFunctions(t *testing.T) {
	const source = `package link

import "errors"

type match struct{ id string }

type activity struct{ id string }

type outcome struct{ id string }

func activityOf(s string) (*activity, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	return nil, nil
}

func byPair(pairs []string) (match, error) {
	if len(pairs) == 0 {
		return match{}, nil
	}
	return match{id: pairs[0]}, nil
}

func byLoan(s string) (match, error) {
	a, err := activityOf(s)
	if err != nil {
		return match{}, err
	}
	if a == nil {
		return match{}, nil
	}
	return match{id: a.id}, nil
}

func byLoanStrict(s string) (match, error) {
	a, err := activityOf(s)
	if err != nil {
		return match{}, nil
	}
	return match{id: a.id}, nil
}

func settle(s string) (outcome, error) {
	a, err := activityOf(s)
	if err != nil {
		return outcome{}, err
	}
	if a == nil {
		return outcome{}, nil
	}
	return outcome{id: a.id}, nil
}
`
	assert.Equal(t, []int{39, 50}, emptyStructReturnLines(t, "link/match.go", source))
}
