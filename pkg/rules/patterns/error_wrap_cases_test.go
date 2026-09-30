package patterns

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Every file is checked — internal/ and cmd/ included — and an error branch
// counts wherever it sits in the body: inside a loop as well as at the top.
func TestErrorWrap_AllDirectoriesAndNestedBranches(t *testing.T) {
	const source = `package store

import "os"

func ReadTop(p string) ([]byte, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func ReadAll(ps []string) ([][]byte, error) {
	var out [][]byte
	for _, p := range ps {
		b, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil, readErr
		}
		out = append(out, b)
	}
	return out, nil
}
`
	violations := runRuleOnFiles(t, NewErrorWrapRule(), map[string]string{
		"store/s.go":          source,
		"internal/store/s.go": source,
		"cmd/tool/store.go":   "package main\n\n" + source[len("package store\n\n"):] + "\nfunc main() {}\n",
	})
	var got []string
	for _, v := range violations {
		got = append(got, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	assert.Equal(t, []string{
		"cmd/tool/store.go:8", "cmd/tool/store.go:18",
		"internal/store/s.go:8", "internal/store/s.go:18",
		"store/s.go:8", "store/s.go:18",
	}, got)
}
