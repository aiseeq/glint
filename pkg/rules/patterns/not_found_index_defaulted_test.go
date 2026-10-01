package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A lookup that says "not found" with -1 is answered with index 0: the code
// goes on with the first account, which belongs to someone else.
func TestNotFoundIndexDefaulted(t *testing.T) {
	ctx := rulestest.GoFile(t, "accounts/sign.go", `package accounts

import "strings"

type Store struct{}

func (Store) IndexOf(address string) int { return -1 }

func FindAccountIndex(address string) int { return -1 }

func KeyFor(address string, s Store) int {
	index := FindAccountIndex(address)
	if index == -1 {
		// fall back to the first account
		index = 0
	}
	slot := s.IndexOf(address)
	if slot < 0 {
		slot = 0
	}
	return index + slot
}

func Checked(address string) (int, bool) {
	index := FindAccountIndex(address)
	if index == -1 {
		return 0, false
	}
	return index, true
}

func Prefix(s string) string {
	end := strings.Index(s, ":")
	if end == -1 {
		end = len(s)
	}
	return s[:end]
}
`)
	assert.Equal(t, []int{15, 19}, violationLines(NewNotFoundIndexDefaultedRule().AnalyzeFile(ctx)))
}
