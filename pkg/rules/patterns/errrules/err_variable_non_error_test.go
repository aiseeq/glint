package errrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// errVariableFindings runs the rule over a module the way the check flow
// does: every file first, then each one.

// The helper's second result became a login response; the caller still names
// it err, and the nil check holds on every success.
func TestErrVariableHoldsNonError(t *testing.T) {
	assert.Equal(t, []string{"integration/search_test.go:5"}, rulestest.ProjectFilesRulePlaces(t, NewErrVariableHoldsNonErrorRule(), map[string]string{
		"integration/helpers.go": `package integration

type Client struct{}

func setupAdmin(t *testing.T) (*Client, *auth.LoginResponse) {
	return &Client{}, nil
}

func newClient() (*Client, error) { return &Client{}, nil }

type statusError struct{}

func (statusError) Error() string { return "status" }

func probe() (*Client, *statusError) { return nil, nil }

type Outcome interface{ Done() bool }

func run() (*Client, Outcome) { return nil, nil }
`,
		"integration/search_test.go": `package integration

func TestSearch(t *testing.T) {
	client, err := setupAdmin(t)
	if err != nil || client == nil {
		t.Skipf("no admin: %v", err)
	}
	other, err2 := newClient()
	if err2 != nil {
		t.Fatal(err2)
	}
	c, probeErr := probe()
	if probeErr != nil {
		t.Fatal(probeErr)
	}
	d, err := run()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _ = client, other, c, d
}
`,
	}))
}

// A variable of the same name declared in an inner scope is another one.
func TestErrVariableHoldsNonErrorShadowed(t *testing.T) {
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewErrVariableHoldsNonErrorRule(), map[string]string{
		"svc/svc.go": `package svc

type Row struct{}

func load() (*Row, *Row) { return nil, nil }

func save() error { return nil }

func run() error {
	row, err := load()
	_ = err
	if row != nil {
		if err := save(); err != nil {
			return err
		}
	}
	return nil
}
`,
	}))
}
