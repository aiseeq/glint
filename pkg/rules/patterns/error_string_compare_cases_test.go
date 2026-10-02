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

// The text of an error kept in a variable, or lowered first, is matched the
// same way: the wording decides the branch whatever the variable is called.
func TestErrorStringCompare_TextThroughVariable(t *testing.T) {
	const source = `package cmp

import (
	"errors"
	"strings"
)

func approve() error { return errors.New("already processed") }

func Status() int {
	err := approve()
	if err == nil {
		return 200
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "already processed") {
		return 409
	}
	text := strings.ToLower(err.Error())
	if strings.HasPrefix(text, "invalid") {
		return 400
	}
	if strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return 504
	}
	return 500
}

func Logged() string {
	err := approve()
	errStr := err.Error()
	if strings.Contains("prefix", "p") {
		return errStr
	}
	return strings.TrimSpace(errStr)
}
`
	violations := runRuleOnFiles(t, NewErrorStringCompareRule(), map[string]string{"cmp/c.go": source})
	assert.Equal(t, []int{16, 20, 23}, violationLines(violations))
}

// Without type information an error the file never types — the result of a
// call — is known by its name.
func TestErrorStringCompare_UntypedErrorByName(t *testing.T) {
	const source = `package cmp

import "strings"

type Svc struct{ approve func() (int, error) }

func (s *Svc) Status() int {
	_, err := s.approve()
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "already processed") {
			return 409
		}
	}
	return 200
}
`
	ctx := rulestest.GoFile(t, "cmp/c.go", source)
	assert.Equal(t, []int{11}, violationLines(NewErrorStringCompareRule().AnalyzeFile(ctx)))
}

// An error message kept as data - a status row's Error column, the message
// parameter of an is...Error predicate - is still the wording of a failure:
// matching it by substrings classifies failures by their text.
func TestErrorStringCompare_StoredErrorMessage(t *testing.T) {
	const source = `package cmp

import "strings"

type SyncStatus struct {
	Error   *string
	Message string
}

func isTransientSyncError(message *string) bool {
	if message == nil {
		return false
	}
	lower := strings.ToLower(*message)
	return strings.Contains(lower, "429") || strings.Contains(lower, "rate limit")
}

func Classify(rec SyncStatus) string {
	if rec.Error != nil && strings.Contains(strings.ToLower(*rec.Error), "degraded") {
		return "warning"
	}
	if strings.Contains(rec.Message, "done") {
		return "ok"
	}
	return "error"
}

func hasPrefixWord(message string) bool {
	return strings.HasPrefix(message, "warn")
}
`
	for name, run := range map[string]func() []int{
		"typed": func() []int {
			return violationLines(runRuleOnFiles(t, NewErrorStringCompareRule(), map[string]string{"cmp/c.go": source}))
		},
		"untyped": func() []int {
			return violationLines(NewErrorStringCompareRule().AnalyzeFile(rulestest.GoFile(t, "cmp/c.go", source)))
		},
	} {
		assert.Equal(t, []int{15, 15, 19}, run(), name)
	}
}

// A stored message tested against a marker the program writes itself reads
// the program's own encoding.
func TestErrorStringCompare_StoredMessageOwnMarker(t *testing.T) {
	const source = `package cmp

import "strings"

const warningPrefix = "warning: "

type Record struct{ Error *string }

func Split(rec *Record) (string, string) {
	if rec == nil || rec.Error == nil {
		return "", ""
	}
	if strings.HasPrefix(*rec.Error, warningPrefix) {
		return "", strings.TrimPrefix(*rec.Error, warningPrefix)
	}
	return *rec.Error, ""
}
`
	assert.Empty(t, violationLines(runRuleOnFiles(t, NewErrorStringCompareRule(), map[string]string{"cmp/c.go": source})))
}

// A predicate about an error's name, not an error's text.
func TestErrorStringCompare_PredicateAboutAName(t *testing.T) {
	const source = `package cmp

import "strings"

func isErrorVarName(name string) bool {
	return name == "err" || strings.HasSuffix(name, "Err")
}
`
	assert.Empty(t, violationLines(runRuleOnFiles(t, NewErrorStringCompareRule(), map[string]string{"cmp/c.go": source})))
}
