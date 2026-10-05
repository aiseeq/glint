package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A classifier takes every 4xx of the provider for its verdict on the payment
// and excludes the codes that say nothing about it - but not 401 and 403: an
// expired token turns a valid payment into a terminal rejection.
func TestAuthFailureClassifiedAsRejection(t *testing.T) {
	files := map[string]string{
		"payprov/refusal.go": `package payprov

import (
	"errors"
	"net/http"
)

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string { return e.Message }

func SendRefusal(err error) (string, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return "", false
	}
	switch apiErr.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return "", false
	}
	if apiErr.StatusCode < 400 || apiErr.StatusCode >= 500 { // want auth-failure-classified-as-rejection
		return "", false
	}
	return apiErr.Message, true
}

func IsPermanent(status int) bool {
	if status == http.StatusTooManyRequests {
		return false
	}
	return status >= 400 && status < 500 // want auth-failure-classified-as-rejection
}

func CorridorRefusal(err error) (string, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return "", false
	}
	switch apiErr.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden,
		http.StatusRequestTimeout, http.StatusTooManyRequests:
		return "", false
	}
	if apiErr.StatusCode < 400 || apiErr.StatusCode >= 500 {
		return "", false
	}
	return apiErr.Message, true
}

// isPermanentRejection decides about 401 and 403 on purpose: a revoked
// credential of the recipient will not change on a resend.
func isPermanentRejection(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return status >= 400 && status < 500
}

// ShouldRetry answers the other question: a 4xx is not worth repeating, and
// 401 is not either.
func ShouldRetry(status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	if status >= 400 && status < 500 {
		return false
	}
	return true
}

// IsClientError has no exclusions: a plain range test, no verdict on an
// operation.
func IsClientError(status int) bool {
	return status >= 400 && status < 500
}
`,
	}
	violations, err := NewAuthFailureClassifiedAsRejectionRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "auth-failure-classified-as-rejection"), foundLines(violations))
}
