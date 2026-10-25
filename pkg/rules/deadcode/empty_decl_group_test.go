package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Repro from a real project: the last constant of a group was deleted and
// `const ()` stayed between the variables around it.
func TestEmptyDeclGroupReportsBareGroup(t *testing.T) {
	ctx := parseGoContext(t, "emulator.go", `package production

// Queue picks the end of the queue.
var Queue = false

const ()

// Cancel returns the builder.
var Cancel = true
`)
	violations := NewEmptyDeclGroupRule().AnalyzeFile(ctx)

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[0].Message, "const")
}

// The constants were moved to another package and only their docs stayed in
// the groups; an import group, a var group and a type group are the same.
func TestEmptyDeclGroupReportsGroupOfCommentsOnly(t *testing.T) {
	ctx := parseGoContext(t, "ids.go", `package economy

import ()

const (

// CarryGas
)

const (
// TypeWorker — id of the worker.

// TypeHall — id of the hall.
)

var (
)

type (
	// Pair of ids.
)
`)
	var lines []int
	for _, v := range NewEmptyDeclGroupRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}

	assert.Equal(t, []int{3, 5, 10, 16, 19}, lines)
}

// A group with a declaration, and a declaration without parentheses, hold code.
func TestEmptyDeclGroupAcceptsGroupsWithDeclarations(t *testing.T) {
	ctx := parseGoContext(t, "ids.go", `package economy

import (
	"fmt"
)

const (
	// TypeWorker — id of the worker.
	TypeWorker = 45
)

var single = fmt.Sprint(TypeWorker)

type (
	pair struct{ a, b int }
)
`)

	assert.Empty(t, NewEmptyDeclGroupRule().AnalyzeFile(ctx))
}

// A suppressed line is not reported.
func TestEmptyDeclGroupSuppressed(t *testing.T) {
	ctx := parseGoContext(t, "ids.go", `package economy

const () //nolint:empty-decl-group
`)

	assert.Empty(t, NewEmptyDeclGroupRule().AnalyzeFile(ctx))
}
