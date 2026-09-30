package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With types the name of the variable is no evidence of nil semantics:
// a slice parameter called userIDs compared with nil is reported like any
// other.
func TestNilSliceTypedIDsNameIsNoExemption(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilSliceRule(), map[string]string{
		"svc/svc.go": `package svc

func unset(userIDs []string) bool {
	return userIDs == nil
}
`,
	})
	require.Len(t, violations, 1)
	assert.Equal(t, "userIDs", violations[0].Context["variable"])
}

// Code that tests both nil and empty on the same slice tells them apart on
// purpose: nil means "no filter", empty means "match nothing".
func TestNilSliceTypedNilAndEmptyDistinguished(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilSliceRule(), map[string]string{
		"svc/svc.go": `package svc

func matches(filter []string, id string) bool {
	if filter == nil {
		return true
	}
	if len(filter) == 0 {
		return false
	}
	for _, f := range filter {
		if f == id {
			return true
		}
	}
	return false
}
`,
	})
	assert.Empty(t, violations)
}

// A variable left nil and set only on one branch - to a part of another slice,
// or a call result - is compared with nil to ask whether that branch ran: the
// part it got may be empty. A variable grown by append is nil exactly when it
// is empty, and its nil check is still reported.
func TestNilSliceTypedNilMeansNotAssigned(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilSliceRule(), map[string]string{
		"cli/cli.go": `package cli

import "slices"

func split(args []string) (bool, []string) {
	var tail []string
	if i := slices.Index(args, "--"); i >= 0 {
		args, tail = args[:i], args[i+1:]
	}
	return tail != nil, args
}

func collect(names []string) bool {
	var picked []string
	for _, name := range names {
		if name != "" {
			picked = append(picked, name)
		}
	}
	return picked == nil
}
`,
	})
	require.Len(t, violations, 1)
	assert.Equal(t, "picked", violations[0].Context["variable"])
}

// A parameter its callers set to a literal nil takes nil as "none given": an
// optional request body, a filter that is not there. Checking it with nil is
// the function's contract, not a mix-up of nil and empty.
func TestNilSliceTypedParameterCallersPassNil(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilSliceRule(), map[string]string{
		"client/client.go": `package client

type Client struct{ contentType string }

func (c *Client) send(method string, body []byte) string {
	if body != nil {
		return method + " " + c.contentType
	}
	return method
}

func (c *Client) request(method string, body []byte) string { return c.send(method, body) }

func (c *Client) Get() string { return c.request("GET", nil) }

func (c *Client) Post(payload []byte) string { return c.request("POST", payload) }

func count(items []int) int {
	if items == nil {
		return 0
	}
	return len(items)
}

func Count() int { return count([]int{1}) }
`,
	})
	require.Len(t, violations, 1)
	assert.Equal(t, "items", violations[0].Context["variable"])
}

// Variadic options are not a declared slice; the typed path leaves them alone
// without looking at the name.
func TestNilSliceTypedVariadicOptions(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilSliceRule(), map[string]string{
		"svc/svc.go": `package svc

func configured(options ...string) bool {
	return options != nil
}
`,
	})
	assert.Empty(t, violations)
}
