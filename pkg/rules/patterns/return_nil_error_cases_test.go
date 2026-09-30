package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// nil is the empty value of a slice, a map, a channel and a function: a
// (nil, nil) return from such a function reports "nothing", not a missing
// error. A pointer first result still is suspicious.
const nilCollectionSource = `package svc

type Item struct{ ID int }

type Items []Item

type Report struct{}

func Collect(ids []int) ([]Item, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return []Item{{ID: ids[0]}}, nil
}

func Index(ids []int) (map[int]Item, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return map[int]Item{}, nil
}

func Named(ids []int) (Items, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return Items{}, nil
}

func Stream(ids []int) (<-chan Item, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return make(chan Item), nil
}

func Hook(ids []int) (func() error, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return func() error { return nil }, nil
}

func Build(ids []int) (*Report, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return &Report{}, nil
}
`

func violationLines(violations []*core.Violation) []int {
	lines := make([]int, 0, len(violations))
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	return lines
}

func TestReturnNilErrorRule_NilCollectionIsEmptyValueTyped(t *testing.T) {
	violations := runRuleOnFiles(t, NewReturnNilErrorRule(), map[string]string{"svc/svc.go": nilCollectionSource})
	require.Len(t, violations, 1)
	assert.Equal(t, 46, violations[0].Line, "only the pointer result is reported")
}

func TestReturnNilErrorRule_NilCollectionIsEmptyValueUntyped(t *testing.T) {
	ctx := rulestest.GoFile(t, "svc/svc.go", nilCollectionSource)
	// Without types the named slice type is unknown and stays reported.
	assert.Equal(t, []int{25, 46}, violationLines(NewReturnNilErrorRule().AnalyzeFile(ctx)))
}
