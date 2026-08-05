package duplication

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeLineCollapsesWhitespace(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"\tresult := compute(a, b)", "result := compute(a, b)"},
		{"  a    b   c  ", "a b c"},
		{"a\t\tb", "a b"},
		{"already normalized", "already normalized"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, normalizeLine(tc.in), "normalizeLine(%q)", tc.in)
	}
}

// The old implementation looped `strings.ReplaceAll(s, "  ", " ")` until no
// double space remained, which is quadratic in the length of a whitespace run.
func TestNormalizeLineHandlesLongWhitespaceRuns(t *testing.T) {
	line := "x" + strings.Repeat(" ", 200000) + "y"
	done := make(chan string, 1)
	go func() { done <- normalizeLine(line) }()
	select {
	case got := <-done:
		assert.Equal(t, "x y", got)
	case <-time.After(5 * time.Second):
		t.Fatal("normalizeLine did not finish in 5s on a long whitespace run")
	}
}

// A file with many identical windows used to cost O(n^2) window hashes.
func TestDuplicateBlockScalesLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("performance guard skipped in short mode")
	}
	rule := NewDuplicateBlockRule()

	var b strings.Builder
	b.WriteString("package main\n")
	for i := 0; i < 400; i++ {
		b.WriteString("func settlementHandler(ctx context.Context, id int) (*Result, error) {\n")
		b.WriteString("\tconnection := database.GetConnectionFromPool(ctx)\n")
		b.WriteString("\tvalidator := NewIncomingPayloadValidator(connection)\n")
		b.WriteString("\tprocessor := NewRecordProcessor(validator, connection)\n")
		b.WriteString("\thandler := processor.CreateRequestHandler(id, connection)\n")
		b.WriteString("\tresults, err := handler.ExecuteWithRetries(ctx, id)\n")
		b.WriteString("\treport := generateSettlementReport(results, validator)\n")
		b.WriteString("\tif err := saveResults(ctx, results, report); err != nil {\n")
		b.WriteString("\t\treturn nil, fmt.Errorf(\"save settlement results: %w\", err)\n")
		b.WriteString("\t}\n")
		b.WriteString("\treturn results, nil\n")
		b.WriteString("}\n")
	}
	ctx := createTestContext(t, "backend/big.go", b.String())

	start := time.Now()
	violations := rule.AnalyzeFile(ctx)
	elapsed := time.Since(start)

	require.NotEmpty(t, violations, "identical handlers must be reported as duplicates")
	assert.Less(t, elapsed, 2*time.Second,
		"analysis of %d lines took %s — window hashing is not linear", len(ctx.Lines), elapsed)
}

func TestRawStringLineSet(t *testing.T) {
	lines := []string{
		`s := "` + "`" + `"`, // backtick inside a quoted string is not a delimiter
		"a := 1",
		"q := `",   // opens a raw string
		"raw line", // inside it
		"`",        // closes it
		"b := 2",
		`c := '` + "`" + `'`, // backtick as a rune literal is not a delimiter either
		"d := 3",
	}

	assert.Equal(t, map[int]bool{2: true, 3: true, 4: true}, rawStringLineSet(lines))
}

// Findings must not depend on Go's randomized map iteration order.
func TestCrossFileDuplicateOrderIsDeterministic(t *testing.T) {
	block := func(seed string) []string {
		return []string{
			"func process" + seed + "(input []byte, config *Config) (*Result, error) {",
			"    if len(input) == 0 {",
			"        return nil, errors.New(\"input " + seed + " cannot be empty\")",
			"    }",
			"    result := &Result{Data: make([]byte, len(input)), Kind: \"" + seed + "\"}",
			"    for i, b := range input {",
			"        result.Data[i] = b ^ config.XORMask" + seed,
			"    }",
			"    result.Checksum = calculateChecksum(result.Data, \"" + seed + "\")",
			"    return result, nil",
			"}",
		}
	}
	lines := []string{"package processor", ""}
	for _, seed := range []string{"Alpha", "Bravo", "Charlie", "Delta", "Echo"} {
		lines = append(lines, block(seed)...)
		lines = append(lines, "")
	}

	first := ""
	for run := 0; run < 12; run++ {
		rule := NewCrossFileDuplicateRule()
		rule.minBlockSize = 8
		rule.ResetState()

		rule.AnalyzeFile(&core.FileContext{
			Path:    "/project/pkg/a/data.go",
			RelPath: "pkg/a/data.go",
			Lines:   lines,
		})
		violations := rule.AnalyzeFile(&core.FileContext{
			Path:    "/project/pkg/b/data.go",
			RelPath: "pkg/b/data.go",
			Lines:   lines,
		})
		require.NotEmpty(t, violations, "duplicate blocks must be reported")

		var got []string
		for i, v := range violations {
			got = append(got, fmt.Sprintf("%s:%d", v.File, v.Line))
			if i > 0 {
				require.Greater(t, v.Line, violations[i-1].Line, "findings must be ordered by line")
			}
		}
		order := strings.Join(got, ",")
		if run == 0 {
			first = order
			continue
		}
		require.Equal(t, first, order, "finding order changed between runs")
	}
}

// ResetState must clear cross-run state so that a second project root does not
// inherit blocks from the first one.
func TestCrossFileDuplicateResetStateClearsBlocks(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	rule.minBlockSize = 8

	lines := []string{
		"package processor",
		"func processData(input []byte, config *Config) (*Result, error) {",
		"    if len(input) == 0 {",
		"        return nil, errors.New(\"input cannot be empty\")",
		"    }",
		"    result := &Result{Data: make([]byte, len(input))}",
		"    for i, b := range input {",
		"        result.Data[i] = b ^ config.XORMask",
		"    }",
		"    result.Checksum = calculateChecksum(result.Data)",
		"    return result, nil",
		"}",
	}

	rule.AnalyzeFile(&core.FileContext{Path: "/a/x.go", RelPath: "x.go", Lines: lines})
	rule.ResetState()
	violations := rule.AnalyzeFile(&core.FileContext{Path: "/b/y.go", RelPath: "y.go", Lines: lines})

	assert.Empty(t, violations, "state from the previous run must not leak after ResetState")
}
