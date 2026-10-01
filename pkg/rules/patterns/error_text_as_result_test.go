package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// The error is turned into text inside a value: a template gets
// "null /* JSON error */" in place of JSON, a caller gets a result marked
// unsuccessful with a nil error and goes on as if the call had worked.
func TestErrorTextAsResult(t *testing.T) {
	ctx := rulestest.GoFile(t, "gen/gen.go", `package gen

import (
	"encoding/json"
	"fmt"
	"log"
	"text/template"
)

type SimResult struct {
	Success bool
	Message string
}

func funcs() template.FuncMap {
	return template.FuncMap{
		"toJSON": func(v any) string {
			data, err := json.Marshal(v)
			if err != nil {
				log.Printf("marshal failed: %v", err)
				return fmt.Sprintf("null /* JSON error: %v */", err)
			}
			return string(data)
		},
	}
}

func Simulate(rate func() (float64, error)) (*SimResult, error) {
	r, err := rate()
	if err != nil {
		return &SimResult{Success: false, Message: fmt.Sprintf("rate failed: %v", err)}, nil
	}
	return &SimResult{Success: r > 0}, nil
}

// A function without an error result returns a description meant for a
// message, or a result type built to carry the failure: the value is the
// report, not data taken for success.
func Describe(load func() (string, error)) string {
	text, err := load()
	if err != nil {
		return "unavailable: " + err.Error()
	}
	return text
}

type Validation struct {
	Valid   bool
	Message string
}

func Validate(check func() error) *Validation {
	if err := check(); err != nil {
		return &Validation{Message: "invalid: " + err.Error()}
	}
	return &Validation{Valid: true}
}

// A check's finding and a skip reason are the function's answer: the error
// result is for the check failing to run, not for what it found.
type Finding struct{ Path, Reason string }

func checkFile(parse func() error) ([]Finding, error) {
	if err := parse(); err != nil {
		return []Finding{{Path: "flags", Reason: err.Error()}}, nil
	}
	return nil, nil
}

func applyRow(symbol func() (string, error)) (skipped string, err error) {
	if _, err := symbol(); err != nil {
		return fmt.Sprintf("row excluded: %v", err), nil
	}
	return "", nil
}

type queryError struct{ details string }

func parseQuery(parse func() error) (string, *queryError) {
	if err := parse(); err != nil {
		return "", &queryError{details: err.Error()}
	}
	return "ok", nil
}

func Wrapped(rate func() (float64, error)) (*SimResult, error) {
	_, err := rate()
	if err != nil {
		return nil, fmt.Errorf("rate: %w", err)
	}
	return &SimResult{Success: true}, nil
}

func Classified(load func() error) (bool, error) {
	if err := load(); err != nil {
		return isRetryable(err), nil
	}
	return false, nil
}

func isRetryable(err error) bool { return err != nil }

type Status struct{ err error }

func (s Status) String() string {
	if s.err != nil {
		return "failed: " + s.err.Error()
	}
	return "ok"
}
`)
	assert.Equal(t, []int{21, 31}, violationLines(NewErrorTextAsResultRule().AnalyzeFile(ctx)))
}
