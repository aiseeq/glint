package httprules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// An outbound client's failure observer counts a request without a status
// (status 0: no response) as a provider failure, and the caller's own
// cancellation has no status either: a shutdown or a client that walked away
// raises a provider outage.
func TestServerErrorHidesClientCancel_OutboundObserverCountsOwnCancel(t *testing.T) {
	const code = `package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
)

func notifyRemoteFailure(host string, status int, detail string) {}

func remoteFailure(method, rawURL string, status int, detail string, err error) error {
	parsed, parseErr := url.Parse(rawURL)
	if parseErr != nil {
		return fmt.Errorf("%s request: %w", method, err)
	}
	if status == 0 || status >= 500 {
		notifyRemoteFailure(parsed.Host, status, detail)
	}
	return fmt.Errorf("%s %s: %w", method, parsed.Host, err)
}

func remoteFailureAware(method, rawURL string, status int, detail string, err error) error {
	parsed, _ := url.Parse(rawURL)
	if (status == 0 || status >= 500) && !errors.Is(err, context.Canceled) {
		notifyRemoteFailure(parsed.Host, status, detail)
	}
	return fmt.Errorf("%s %s: %w", method, parsed.Host, err)
}
`
	violations := rulestest.RunRuleOnFiles(t, NewServerErrorHidesClientCancelRule(), map[string]string{"client/client.go": code})
	assert.Equal(t, []int{18}, rulestest.ViolationLines(violations))
}
