package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// An empty-message check picks a fallback text for a message that never
// came; it compares nothing against an error's wording.
func TestErrorStringCompare_EmptyMessageCheckIsNotAComparison(t *testing.T) {
	const source = `package cmp

func Describe(errMsg string) string {
	if errMsg == "" {
		errMsg = "unknown failure"
	}
	return errMsg
}

func Known(errMsg string) bool {
	return errMsg == "timeout"
}
`
	ctx := rulestest.GoFile(t, "cmp/c.go", source)
	assert.Equal(t, []int{11}, violationLines(NewErrorStringCompareRule().AnalyzeFile(ctx)))
}

// The receiver of .Error() is an error by its type, whatever it is called: a
// failure variable is one, an Entry with an Error(code) method is not.
func TestErrorStringCompare_ReceiverJudgedByType(t *testing.T) {
	const source = `package cmp

import "errors"

type Entry struct{ Msg string }

func (e Entry) Error(code int) string { return e.Msg }

func load() error { return errors.New("boom") }

func Failed() bool {
	failure := load()
	return failure.Error() == "boom"
}

func Labeled(e Entry) bool {
	return e.Error(1) == "boom"
}
`
	violations := runRuleOnFiles(t, NewErrorStringCompareRule(), map[string]string{"cmp/c.go": source})
	assert.Equal(t, []int{13}, violationLines(violations))
}
