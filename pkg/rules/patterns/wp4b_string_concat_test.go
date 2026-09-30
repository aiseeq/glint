package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With types the accumulator is judged by its type, not by the spelling of
// the right-hand side.
func TestStringConcatTyped(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "float accumulator is arithmetic",
			code: `package main

func sum(prices []float64) float64 {
	total := 0.0
	for _, p := range prices {
		total = total + p
	}
	return total
}
`,
			expectMatch: false,
		},
		{
			name: "int accumulator with += is arithmetic",
			code: `package main

func sum(xs []int) int {
	total := 0
	for _, x := range xs {
		total += x
	}
	return total
}
`,
			expectMatch: false,
		},
		{
			name: "string += of a variable",
			code: `package main

func join(names []string) string {
	out := ""
	for _, name := range names {
		out += name
	}
	return out
}
`,
			expectMatch: true,
		},
		{
			name: "string = string + variable",
			code: `package main

func join(names []string) string {
	out := ""
	for _, name := range names {
		out = out + name
	}
	return out
}
`,
			expectMatch: true,
		},
		{
			name: "named string type",
			code: `package main

type Label string

func join(names []Label) Label {
	var out Label
	for _, name := range names {
		out += name
	}
	return out
}
`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := runRuleOnFiles(t, NewStringConcatRule(), map[string]string{"service.go": tt.code})
			if tt.expectMatch {
				require.Len(t, violations, 1)
				assert.Equal(t, "string_concat_loop", violations[0].Context["pattern"])
				assert.Equal(t, "service.go", violations[0].File)
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}

// Without types `total = total + p` has unknown operands: silence, not a
// guess that anything that is not a literal is a string.
func TestStringConcatUntypedUnknownOperand(t *testing.T) {
	ctx := createConcatContext(t, "service.go", `package main

func sum(prices []float64) float64 {
	total := 0.0
	for _, p := range prices {
		total = total + p
	}
	return total
}
`)
	assert.Empty(t, NewStringConcatRule().AnalyzeFile(ctx))
}
