package duplication

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The library has two short functions: each reads its argument once
// through a call into a new local and builds the result from that local.
const libraryShortSource = `package lib

import (
	"strings"
	"time"
)

func StartOfDayUTC(t time.Time) time.Time {
	utc := t.UTC()
	return time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
}

func TrimmedLower(s string) string {
	clean := strings.TrimSpace(s)
	return strings.ToLower(clean)
}
`

// A copy of a short library function that puts the converted value back
// into the parameter instead of a new local is the same function.
func TestDuplicateFuncOfLibraryShortBodyReassignedParameter(t *testing.T) {
	violations := nearLibraryFindings(t, libraryShortSource, `package app

import (
	"strings"
	"time"
)

func payprovDay(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
}

func payprovKey(raw string) string {
	raw = strings.TrimSpace(raw)
	return strings.ToLower(raw)
}
`)
	require.Len(t, violations, 2)
	assert.Equal(t, 8, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Function payprovDay duplicates function StartOfDayUTC")
	assert.Equal(t, 13, violations[1].Line)
	assert.Contains(t, violations[1].Message, "Function payprovKey duplicates function TrimmedLower")
}

// Short functions that differ from the library in a constant, in a field
// read, or that read the parameter before putting the converted value back
// are other functions.
func TestDuplicateFuncOfLibraryShortBodyNeighbours(t *testing.T) {
	violations := nearLibraryFindings(t, libraryShortSource, `package app

import (
	"strings"
	"time"
)

func payprovNoon(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), at.Day(), 12, 0, 0, 0, time.UTC)
}

func payprovMonth(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func payprovLocalDay(at time.Time) time.Time {
	day := at.Day()
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), day, 0, 0, 0, 0, time.UTC)
}

func payprovUpper(raw string) string {
	raw = strings.TrimSpace(raw)
	return strings.ToUpper(raw)
}

func payprovKeyOf(raw, fallback string) string {
	raw = strings.TrimSpace(fallback)
	return strings.ToLower(raw)
}
`)
	assert.Empty(t, violations)
}
