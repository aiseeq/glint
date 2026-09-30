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
