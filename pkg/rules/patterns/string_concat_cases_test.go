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

// A loop over a handful of entries fixed in the source - a package table of
// filters, an array, a literal - concatenates a known small number of times;
// the quadratic copying strings.Builder avoids does not exist there. A table
// the package reassigns or appends to has no fixed size, and a loop over the
// characters of its input still grows with the input.
func TestStringConcatFixedSmallLoops(t *testing.T) {
	violations := runRuleOnFiles(t, NewStringConcatRule(), map[string]string{"service.go": `package main

import "fmt"

type filterSpec struct {
	key    string
	column string
}

var filterSpecs = []filterSpec{
	{"region", "t.region"},
	{"status", "t.status"},
	{"owner", "t.owner"},
}

var growingSpecs = []filterSpec{
	{"region", "t.region"},
}

func register(spec filterSpec) {
	growingSpecs = append(growingSpecs, spec)
}

func applyFilters(query string, values map[string]string, args []any) (string, []any) {
	for _, f := range filterSpecs {
		value, ok := values[f.key]
		if !ok {
			continue
		}
		args = append(args, value)
		query += fmt.Sprintf(" AND %s = $%d", f.column, len(args))
	}
	return query, args
}

func columns() string {
	out := ""
	for _, name := range [3]string{"a", "b", "c"} {
		out += name
	}
	for _, name := range []string{"d", "e"} {
		out += name
	}
	return out
}

func applyGrowing(query string) string {
	for _, f := range growingSpecs {
		query += " AND " + f.column
	}
	return query
}

func replacePlaceholders(query string) string {
	result := ""
	for _, c := range query {
		result += string(c)
	}
	return result
}
`})

	require.Len(t, violations, 2)
	assert.Equal(t, 49, violations[0].Line)
	assert.Equal(t, 57, violations[1].Line)
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
