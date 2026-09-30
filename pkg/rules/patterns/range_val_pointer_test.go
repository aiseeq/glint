package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rangeGoMod121 = "module example.com/projecta\n\ngo 1.21\n"
	rangeGoMod123 = "module example.com/projecta\n\ngo 1.23\n"
)

func TestRangeValPointerRule_Metadata(t *testing.T) {
	rule := NewRangeValPointerRule()

	assert.Equal(t, "range-val-pointer", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

// TestRangeValPointerRule_Detection runs on a go 1.21 module: before Go 1.22
// one variable serves every iteration, so a pointer to it that outlives the
// iteration sees only the last element.
func TestRangeValPointerRule_Detection(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "pointer to range value appended",
			code: `package main

type Item struct{}

func example(items []Item) []*Item {
	var ptrs []*Item
	for _, item := range items {
		ptrs = append(ptrs, &item)
	}
	return ptrs
}
`,
			expectMatch: true,
		},
		{
			name: "pointer to range key appended",
			code: `package main

func example(items []int) []*int {
	var ptrs []*int
	for i := range items {
		ptrs = append(ptrs, &i)
	}
	return ptrs
}
`,
			expectMatch: true,
		},
		{
			name: "pointer inside a composite literal appended",
			code: `package main

type Item struct{}
type Wrapper struct{ Item *Item }

func example(items []Item) []Wrapper {
	var out []Wrapper
	for _, item := range items {
		out = append(out, Wrapper{Item: &item})
	}
	return out
}
`,
			expectMatch: true,
		},
		{
			name: "pointer stored in an outer map",
			code: `package main

type Item struct{ ID string }

func example(items []Item) map[string]*Item {
	byID := map[string]*Item{}
	for _, item := range items {
		byID[item.ID] = &item
	}
	return byID
}
`,
			expectMatch: true,
		},
		{
			name: "pointer returned from the loop",
			code: `package main

type Item struct{ ID string }

func find(items []Item, id string) *Item {
	for _, item := range items {
		if item.ID == id {
			return &item
		}
	}
	return nil
}
`,
			expectMatch: true,
		},
		{
			name: "range variable captured by a goroutine",
			code: `package main

func process(int) {}

func example(items []int) {
	for _, item := range items {
		go func() {
			process(item)
		}()
	}
}
`,
			expectMatch: true,
		},
		{
			name: "pointer passed to a call that does not keep it",
			code: `package main

import "encoding/json"

type Item struct{ ID string }

func example(blobs [][]byte) error {
	for _, item := range []Item{{}, {}} {
		if err := json.Unmarshal(blobs[0], &item); err != nil {
			return err
		}
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			name: "pointer kept in a loop-local variable",
			code: `package main

type Item struct{ ID string }

func use(*Item) {}

func example(items []Item) {
	for _, item := range items {
		p := &item
		use(p)
	}
}
`,
			expectMatch: false,
		},
		{
			name: "pointer to local copy",
			code: `package main

type Item struct{}

func example(items []Item) []*Item {
	var ptrs []*Item
	for _, item := range items {
		copy := item
		ptrs = append(ptrs, &copy)
	}
	return ptrs
}
`,
			expectMatch: false,
		},
		{
			name: "pointer to slice element",
			code: `package main

type Item struct{}

func example(items []Item) []*Item {
	var ptrs []*Item
	for i := range items {
		ptrs = append(ptrs, &items[i])
	}
	return ptrs
}
`,
			expectMatch: false,
		},
		{
			name: "no pointer usage",
			code: `package main

func example(items []int) int {
	sum := 0
	for _, item := range items {
		sum += item
	}
	return sum
}
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := runRuleOnFiles(t, NewRangeValPointerRule(), map[string]string{
				"go.mod":     rangeGoMod121,
				"service.go": tt.code,
			})

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "range_val_pointer", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

const rangeAppendSource = `package main

type Item struct{ ID int }

func Ptrs(items []Item) []*Item {
	var out []*Item
	for _, it := range items {
		out = append(out, &it)
	}
	return out
}
`

// TestRangeValPointerRule_Go122LoopVariables: since Go 1.22 every iteration
// has its own variable, so the same code is correct in a newer module.
func TestRangeValPointerRule_Go122LoopVariables(t *testing.T) {
	violations := runRuleOnFiles(t, NewRangeValPointerRule(), map[string]string{
		"go.mod":     rangeGoMod123,
		"service.go": rangeAppendSource,
	})
	assert.Empty(t, violations)
}

// TestRangeValPointerRule_FileBuildVersion: a //go:build go1.22 constraint
// raises the language version of that one file in an older module.
func TestRangeValPointerRule_FileBuildVersion(t *testing.T) {
	violations := runRuleOnFiles(t, NewRangeValPointerRule(), map[string]string{
		"go.mod":     rangeGoMod121,
		"service.go": "//go:build go1.22\n\n" + rangeAppendSource,
	})
	assert.Empty(t, violations)
}

// TestRangeValPointerRule_UnknownVersion: without type information the
// language version of the file is unknown, and unknown is not old.
func TestRangeValPointerRule_UnknownVersion(t *testing.T) {
	ctx := rulestest.GoFile(t, "service.go", rangeAppendSource)
	assert.Empty(t, NewRangeValPointerRule().AnalyzeFile(ctx))
}

func TestRangeValPointerRule_OldModuleReportsLine(t *testing.T) {
	violations := runRuleOnFiles(t, NewRangeValPointerRule(), map[string]string{
		"go.mod":     rangeGoMod121,
		"service.go": rangeAppendSource,
	})
	require.Len(t, violations, 1)
	assert.Equal(t, 8, violations[0].Line)
	assert.Equal(t, "service.go", violations[0].File)
}
