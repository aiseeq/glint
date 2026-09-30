package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func errorMaskingLines(t *testing.T, source string) []int {
	t.Helper()
	ctx := rulestest.GoFile(t, "svc/svc.go", source)
	return violationLines(NewErrorMaskingRule().AnalyzeFile(ctx))
}

// The error slot of the signature decides whether a return hands an error
// over: a sentinel, a wrap helper and any other non-nil value in that slot is
// propagation, whatever it is called.
func TestErrorMasking_ErrorSlotPropagatesAnyValue(t *testing.T) {
	const source = `package svc

import "errors"

var ErrNotFound = errors.New("not found")

func wrapErr(err error) error { return err }

func load(id string) (int, error) { return 0, nil }

func GetCount(id string) (int, error) {
	n, err := load(id)
	if err != nil {
		return 0, ErrNotFound
	}
	return n, nil
}

func LoadName(id string) (string, error) {
	_, err := load(id)
	if err != nil {
		return "", wrapErr(err)
	}
	return id, nil
}

func LoadLabel(id string) (string, error) {
	_, err := load(id)
	if err != nil {
		return "", nil
	}
	return id, nil
}

func Handler() func(string) (int, error) {
	return func(id string) (int, error) {
		n, err := load(id)
		if err != nil {
			return 0, ErrNotFound
		}
		return n, nil
	}
}
`
	assert.Equal(t, []int{29}, errorMaskingLines(t, source))
}

// In a function whose only result is error, nil in the default branch is
// success, not a masked failure.
func TestErrorMasking_SwitchDefaultNilInErrorOnlyFunction(t *testing.T) {
	const source = `package svc

import "fmt"

func ValidateKind(kind string) error {
	switch kind {
	case "bad":
		return fmt.Errorf("kind %q is not allowed", kind)
	default:
		return nil
	}
}
`
	assert.Empty(t, errorMaskingLines(t, source))
}

// Predicate names end at a word boundary: HashPassword is not Has+Password's
// predicate, CancelOrder is not Can+..., so their masked errors are reported;
// IsCached and isStale are predicates.
func TestErrorMasking_PredicateNameNeedsWordBoundary(t *testing.T) {
	const source = `package svc

import "strconv"

func HashPassword(s string) (string, error) {
	_, err := strconv.Atoi(s)
	if err != nil {
		return "", nil
	}
	return s, nil
}

func CancelOrder(s string) (string, error) {
	_, err := strconv.Atoi(s)
	if err != nil {
		return "", nil
	}
	return s, nil
}

func IsCached(s string) bool {
	_, err := strconv.Atoi(s)
	if err != nil {
		return true
	}
	return false
}

func isStale(s string) bool {
	_, err := strconv.Atoi(s)
	if err != nil {
		return true
	}
	return false
}
`
	assert.Equal(t, []int{7, 15}, errorMaskingLines(t, source))
}

// A function implemented elsewhere has no body to inspect.
func TestErrorMasking_FunctionWithoutBody(t *testing.T) {
	assert.Empty(t, errorMaskingLines(t, "package svc\n\nfunc ReadCounter() (int, error)\n"))
}

// A function whose last result is a typed error of its own (*RequestError)
// hands the failure over when that slot carries an error built from the cause,
// just as a plain error slot would. A bool that answers "keep going" after the
// cause was logged at error level is a decision, not a masked failure; the same
// return without the log, or with a log that does not carry the cause, still is
// one.
func TestErrorMasking_TypedErrorSlotAndLoggedDecision(t *testing.T) {
	const source = `package svc

import (
	"log/slog"
	"strconv"
)

type RequestError struct{ Message string }

func (e *RequestError) Error() string { return e.Message }

func newRequestError(msg string, cause error) *RequestError { return &RequestError{Message: msg} }

func parseLimit(s string) (int, int, *RequestError) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, newRequestError(err.Error(), err)
	}
	return n, n, nil
}

type streamer struct{ logger *slog.Logger }

func (s *streamer) sendEvent(raw string) bool {
	_, formatErr := strconv.Atoi(raw)
	if formatErr != nil {
		s.logger.Error("skipping event", "error", formatErr)
		return true
	}
	return true
}

func (s *streamer) sendQuiet(raw string) bool {
	_, formatErr := strconv.Atoi(raw)
	if formatErr != nil {
		return true
	}
	return true
}

func (s *streamer) sendNoted(raw string) bool {
	_, formatErr := strconv.Atoi(raw)
	if formatErr != nil {
		s.logger.Info("event", "error", formatErr)
		return true
	}
	return true
}

func (s *streamer) readCount(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil {
		s.logger.Error("bad count", "error", err)
		return 0
	}
	return n
}
`
	assert.Equal(t, []int{35, 43, 52}, errorMaskingLines(t, source))
}
