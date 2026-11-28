package duplication

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The library tidies an amount in six statements before it returns it.
const libraryInlineRunSource = `package lib

import "strings"

func NormalizeAmount(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, ",", "")
	value = strings.ReplaceAll(value, " ", "")
	if value == "" {
		return "0"
	}
	if strings.HasPrefix(value, ".") {
		value = "0" + value
	}
	if strings.HasSuffix(value, ".") {
		value = value + "0"
	}
	return value
}
`

// A function that starts with the whole body of a library function but its
// return, under other names, and goes on with the value repeats the
// library function: it should call it.
func TestDuplicateFuncOfLibraryInlineStatementRun(t *testing.T) {
	violations := nearLibraryFindings(t, libraryInlineRunSource, `package app

import (
	"fmt"
	"strings"
)

func payprovLabel(amount, currency string) string {
	v := strings.TrimSpace(amount)
	v = strings.ReplaceAll(v, ",", "")
	v = strings.ReplaceAll(v, " ", "")
	if v == "" {
		return "0"
	}
	if strings.HasPrefix(v, ".") {
		v = "0" + v
	}
	if strings.HasSuffix(v, ".") {
		v = v + "0"
	}
	return fmt.Sprintf("%s %s", v, strings.ToUpper(currency))
}
`)
	require.Len(t, violations, 1)
	assert.GreaterOrEqual(t, violations[0].Line, 8)
	assert.LessOrEqual(t, violations[0].Line, 9)
	assert.Contains(t, violations[0].Message, "NormalizeAmount")
}

// A function that shares only the first statements of the library body,
// changes one argument of it, or writes the value in between is no copy.
func TestDuplicateFuncOfLibraryInlineStatementRunNeighbours(t *testing.T) {
	violations := nearLibraryFindings(t, libraryInlineRunSource, `package app

import (
	"fmt"
	"strings"
)

func payprovShort(amount, currency string) string {
	v := strings.TrimSpace(amount)
	v = strings.ReplaceAll(v, ",", "")
	return fmt.Sprintf("%s %s", v, currency)
}

func payprovDots(amount, currency string) string {
	v := strings.TrimSpace(amount)
	v = strings.ReplaceAll(v, ".", "")
	v = strings.ReplaceAll(v, " ", "")
	if v == "" {
		return "0"
	}
	if strings.HasPrefix(v, ".") {
		v = "0" + v
	}
	if strings.HasSuffix(v, ".") {
		v = v + "0"
	}
	return fmt.Sprintf("%s %s", v, currency)
}

func payprovMixed(amount, currency string) string {
	v := strings.TrimSpace(amount)
	v = strings.ReplaceAll(v, ",", "")
	v = strings.ToLower(v)
	v = strings.ReplaceAll(v, " ", "")
	if v == "" {
		return "0"
	}
	if strings.HasPrefix(v, ".") {
		v = "0" + v
	}
	if strings.HasSuffix(v, ".") {
		v = v + "0"
	}
	return fmt.Sprintf("%s %s", v, currency)
}
`)
	assert.Empty(t, violations)
}
