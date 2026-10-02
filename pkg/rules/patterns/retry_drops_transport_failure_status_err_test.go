package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// statusErrorPrelude declares a client whose failed answer is a StatusError
// carrying the code, and helpers that read only that code from an error.
const statusErrorPrelude = `package client

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type StatusError struct{ StatusCode int }

func (e *StatusError) Error() string { return http.StatusText(e.StatusCode) }

func doGet(ctx context.Context, url string) ([]byte, error) { return nil, nil }

func isServerError(err error) bool {
	var statusErr *StatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode >= 500
}

func isTooManyRequests(err error) bool {
	var statusErr *StatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusTooManyRequests
}

func isTransient(err error) bool { return errors.Is(err, context.DeadlineExceeded) }

func pause(ctx context.Context, d time.Duration) error { return nil }
`

// The retry decision asks the error, but only for the status it carries: a
// reset connection has none, falls to the default and ends the loop.
func TestRetryDropsTransportFailure_PredicatesReadOnlyTheStatus(t *testing.T) {
	const code = `package client

import (
	"context"
	"fmt"
	"time"
)

func get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		body, err := doGet(ctx, url)
		if err == nil {
			return body, nil
		}
		switch {
		case isTooManyRequests(err):
		case isServerError(err):
		default:
			return nil, err
		}
		lastErr = err
		if err := pause(ctx, time.Second<<attempt); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("still failing: %w", lastErr)
}

func getTransient(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		body, err := doGet(ctx, url)
		if err == nil {
			return body, nil
		}
		switch {
		case isServerError(err):
		case isTransient(err):
		default:
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}
`
	violations := runRuleOnFiles(t, NewRetryDropsTransportFailureRule(), map[string]string{
		"client/prelude.go": statusErrorPrelude,
		"client/client.go":  code,
	})
	assert.Equal(t, []int{16}, violationLines(violations))
}
