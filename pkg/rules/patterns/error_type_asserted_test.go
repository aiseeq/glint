package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// An error tested by a type assertion or a type switch to its concrete type:
// once a caller wraps it with %w the assertion fails, and the rate-limit
// branch never runs.
func TestErrorTypeAsserted(t *testing.T) {
	files := map[string]string{
		"rates/client.go": `package rates

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string { return fmt.Sprintf("status %d: %s", e.StatusCode, e.Body) }

type marker interface{ Temporary() bool }

func IsRateLimit(err error) bool {
	apiErr, ok := err.(*APIError) // want error-type-asserted
	if !ok {
		return false
	}
	return apiErr.StatusCode == 429 || strings.Contains(apiErr.Body, "rate limit")
}

func Timeout(err error) bool {
	if ne, ok := err.(net.Error); ok { // want error-type-asserted
		return ne.Timeout()
	}
	return false
}

func Kind(err error) string {
	switch e := err.(type) { // want error-type-asserted
	case *APIError:
		return fmt.Sprint(e.StatusCode)
	case nil:
		return ""
	}
	return "other"
}

func IsRateLimitWrapped(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 429
}

// Temporary asks for a behaviour no error type has to implement.
func Temporary(err error) bool {
	m, ok := err.(marker)
	return ok && m.Temporary()
}

func Describe(v any) string {
	if e, ok := v.(*APIError); ok {
		return e.Body
	}
	return ""
}

func NilOnly(err error) bool {
	switch err.(type) {
	case nil:
		return true
	}
	return false
}

// Is is the error's own comparison: errors.Is calls it on every link of the
// chain, so the assertion sees one link at a time.
func (e *APIError) Is(target error) bool {
	t, ok := target.(*APIError)
	return ok && t.StatusCode == e.StatusCode
}
`,
	}
	violations, err := NewErrorTypeAssertedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "error-type-asserted"), foundLines(violations))
}
