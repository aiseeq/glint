package typesafety

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A bare any field of an exported struct is as schema-less as a map of any;
// a method of an unexported type is no part of the public contract.
func TestAnyInPublicContractFieldsAndReceivers(t *testing.T) {
	ctx := rulestest.GoFile(t, "p/p.go", `package p

type impl struct{}

// Load is on an unexported type.
func (impl) Load() any { return nil }

// Load is on an exported type.
func (*Store) Load() any { return nil }

type Store struct{}

// Req is a request.
type Req struct {
	// Data is untyped.
	Data any
	Raw  interface{}
	Tags []string
	note any
}
`)
	violations := NewAnyInPublicContractRule().AnalyzeFile(ctx)

	var lines []int
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{9, 16, 17}, lines)
	require.Len(t, violations, 3)
	assert.Contains(t, violations[1].Message, "Data")
}
