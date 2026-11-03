package gorules

import (
	"github.com/aiseeq/glint/pkg/rules/rulestest"
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
			violations := rulestest.RunRuleOnFiles(t, NewStringConcatRule(), map[string]string{"service.go": tt.code})
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
	violations := rulestest.RunRuleOnFiles(t, NewStringConcatRule(), map[string]string{"service.go": `package main

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

func applyOptions(query string, values map[string]string, args []any) (string, []any) {
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

// Without types a name does not tell the loop's variable from another of its
// name: the element of the counter is still an accumulation.
func TestStringConcatUntypedElementOfCounter(t *testing.T) {
	ctx := createConcatContext(t, "service.go", `package main

func annotate(names []string) {
	for i := 0; i < len(names); i++ {
		names[i] += "!"
	}
}
`)
	assert.Len(t, NewStringConcatRule().AnalyzeFile(ctx), 1)
}

// A += on the element the loop picks by its own variable writes a different
// string each iteration: nothing accumulates, as in out[i] = T{out[i].Message
// + extra}. The element of another loop's variable, of an expression of the
// variable, or of a variable the body moves still grows across iterations.
func TestStringConcatPerElement(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		expectMatch bool
	}{
		{"field of the range element", "for i := range out {\n\t\tout[i].Message += extra\n\t}", false},
		{"range element with key and value", "for i, n := range out {\n\t\tout[i].Message = out[i].Message + n.Kind\n\t}", false},
		{"string slice element", "for i := range names {\n\t\tnames[i] += extra\n\t}", false},
		{"map entry of the range key", "for k := range byKind {\n\t\tbyKind[k] += extra\n\t}", false},
		{"counter of a for loop", "for i := 0; i < len(out); i++ {\n\t\tout[i].Message += extra\n\t}", false},
		{"element of the outer loop in an inner loop", "for i := range out {\n\t\tfor _, p := range parts {\n\t\t\tout[i].Message += p\n\t\t}\n\t}", true},
		{"element of the outer loop in an inner loop with a key", "for i := range out {\n\t\tfor j := range parts {\n\t\t\tout[i].Message += parts[j]\n\t\t}\n\t}", true},
		{"element of an expression of the variable", "for i := range out {\n\t\tout[i/2].Message += extra\n\t}", true},
		{"key the body moves", "for i := range out {\n\t\ti = 0\n\t\tout[i].Message += extra\n\t}", true},
		{"blank key", "for range out {\n\t\tout[0].Message += extra\n\t}", true},
		{"key of an integer range", "for i := range len(out) {\n\t\tout[i].Message += extra\n\t}", false},
		{"key of a string range", "for i := range extra {\n\t\tnames[i] += extra\n\t}", false},
		{"key of an array pointer range", "for i := range fixed {\n\t\tfixed[i] += extra\n\t}", false},
		{"key of a channel", "for k := range kinds {\n\t\tbyKind[k] += extra\n\t}", true},
		{"key of an iterator", "for k := range words {\n\t\tbyKind[k] += extra\n\t}", true},
		{"key an inner range assigns", "for i := range out {\n\t\tfor i = range parts {\n\t\t}\n\t\tout[i].Message += extra\n\t}", true},
		{"key the body steps", "for i := range out {\n\t\tout[i].Message += extra\n\t\ti++\n\t}", true},
		{"key the body passes by address", "for i := range out {\n\t\tparse(extra, &i)\n\t\tout[i].Message += extra\n\t}", true},
		{"key a pointer method moves", "for i := range count {\n\t\ti.next()\n\t\tnames[i] += extra\n\t}", true},
		{"key the body shadows", "for i := range out {\n\t\tout[i].Kind = extra\n\t\tvar i int\n\t\tout[i].Message += extra\n\t}", true},
		{"key an inner loop shadows", "for i := range out {\n\t\tout[i].Kind = extra\n\t\tfor i := range parts {\n\t\t\tout[i].Message += parts[i]\n\t\t}\n\t}", true},
		{"counter of a step by a variable", "for i := 0; i < len(out); i += len(parts) {\n\t\tout[i].Message += extra\n\t}", false},
		{"counter of a zero step", "for i := 0; i < len(out); i += 0 {\n\t\tout[i].Message += extra\n\t\tif len(out[i].Message) < 8 {\n\t\t\tcontinue\n\t\t}\n\t\tbreak\n\t}", true},
		{"counter of a string step", "for s := \"\"; len(s) < 3; s += \"-\" {\n\t\tbyKind[s] += extra\n\t}", false},
		{"counter a product steps", "for i := 0; i < len(out); i *= 2 {\n\t\tout[i].Message += extra\n\t}", true},
		{"counter with no condition", "for i := uint8(0); ; i++ {\n\t\tnames[i] += extra\n\t}", true},
		{"counter an empty string steps", "for s := \"\"; len(s) < 3; s += \"\" {\n\t\tbyKind[s] += extra\n\t}", true},
		{"key an inner range moves by value", "for i := range out {\n\t\tfor _, i = range order {\n\t\t}\n\t\tout[i].Message += extra\n\t}", true},
		{"key the body moves a part of", "for k := range byPair {\n\t\tk.B = \"\"\n\t\tbyPair[k] += extra\n\t}", true},
		{"field behind a shared pointer", "for i := range children {\n\t\tchildren[i].Parent.Label += children[i].Label\n\t}", true},
		{"field of an embedded pointer", "for i := range children {\n\t\tchildren[i].Note += extra\n\t}", true},
		{"key of a long array pointer range", "for i := range long {\n\t\tlong[i] += extra\n\t}", false},
		{"key the body moves an element of", "for k := range byCell {\n\t\tk[1]++\n\t\tbyCell[k] += extra\n\t}", true},
		{"key the body passes a part of by address", "for k := range byPair {\n\t\tblank(&k.B)\n\t\tbyPair[k] += extra\n\t}", true},
		{"element a goto repeats", "for i := range out {\n\tagain:\n\t\tout[i].Message += extra\n\t\tif len(out[i].Message) < 8 {\n\t\t\tgoto again\n\t\t}\n\t}", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := "package main\n\ntype Notice struct {\n\tKind    string\n\tMessage string\n}\n\n" +
				"type Pos int\n\nfunc (p *Pos) next() { *p++ }\n\nfunc parse(s string, n *int) {}\n\n" +
				"type Pair struct{ A, B string }\n\nfunc blank(s *string) {}\n\ntype Remark struct{ Note string }\n\n" +
				"type Node struct {\n\t*Remark\n\tLabel  string\n\tParent *Node\n}\n\n" +
				"func annotate(out []Notice, names []string, byKind map[string]string, parts []string, extra string,\n" +
				"\tfixed *[4]string, kinds chan string, words func(func(string) bool), count Pos,\n" +
				"\torder []int, byPair map[Pair]string, children []Node, long *[20]string, byCell map[[2]int]string) {\n\t" +
				tt.body + "\n}\n"
			violations := rulestest.RunRuleOnFiles(t, NewStringConcatRule(), map[string]string{"service.go": code})
			if tt.expectMatch {
				require.Len(t, violations, 1)
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}
