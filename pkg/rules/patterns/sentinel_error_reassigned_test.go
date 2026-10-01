package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A setup that swaps a sentinel for a configured one leaves every error made
// before it unrecognized, and a sentinel declared empty is nil until then.
func TestSentinelErrorReassigned(t *testing.T) {
	violations, err := NewSentinelErrorReassignedRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"store/errors.go": `package store

import (
	"errors"
	"fmt"
	"sync"
)

var ErrNotFound = errors.New("not found")

var ErrConflict error

var ErrUnsupported = errors.New("unsupported")

var ErrFrozen = errors.New("frozen")

var lastFailure error

var errSetup error

var once sync.Once

type Messages interface {
	NotFound() string
}

func InitErrors(m Messages) {
	once.Do(func() {
		ErrNotFound = errors.New(m.NotFound())
		ErrConflict = fmt.Errorf("conflict")
		ErrUnsupported = ErrNotFound
	})
}

func init() {
	ErrFrozen = fmt.Errorf("frozen: %w", ErrNotFound)
}

func connect() error { return nil }

func Setup() {
	lastFailure = connect()
	errSetup = connect()
}
`,
		"store/errors_test.go": `package store

import "testing"

func TestSwap(t *testing.T) {
	ErrNotFound = ErrConflict
}
`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"store/errors.go:29", "store/errors.go:30", "store/errors.go:31"}, foundLines(violations))
}
