package duplication

import (
	"fmt"
	"github.com/aiseeq/glint/pkg/core"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// regionBody returns n distinct, non-trivial statement lines.
func regionBody(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "\tresultValue%d := transformInputRecord(record, \"field_%d\", configuration)\n", i, i)
	}
	return b.String()
}

// Every copy of a block is reported against the first one, the fourth and
// later copies too, and each copy with the same range: a copy reported once
// must not hide the block from the next file. The function's closing brace is
// part of the copy, hence one line past the body.
func TestCrossFileDuplicateReportsEveryCopy(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	body := regionBody(10)

	var got []string
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		ctx := createTestContext(t, "copies/"+name+".go", "package copies\n\nfunc process"+name+"() {\n"+body+"}\n")
		for _, v := range rule.AnalyzeFile(ctx) {
			got = append(got, fmt.Sprintf("%s:%d %s", v.File, v.Line, v.Message))
		}
	}

	var want []string
	for _, name := range []string{"b", "c", "d", "e", "f", "g"} {
		want = append(want, "copies/"+name+".go:4 Cross-file duplicate (lines 4-14): same as copies/a.go:4-14")
	}
	assert.Equal(t, want, got)
}

// A region longer than the window is one finding with the region's range, not
// one per window offset.
func TestCrossFileDuplicateReportsRegionRange(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	body := regionBody(25)

	assert.Empty(t, rule.AnalyzeFile(createTestContext(t, "copies/a.go", "package copies\n\nfunc a() {\n"+body+"}\n")))
	violations := rule.AnalyzeFile(createTestContext(t, "copies/b.go", "package copies\n\n\nfunc b() {\n"+body+"}\n"))

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Equal(t, "Cross-file duplicate (lines 5-30): same as copies/a.go:4-29", violations[0].Message)
}

// A repeated region longer than the window is one finding for the region, not
// one per window offset inside it.
func TestDuplicateBlockReportsRegionOnce(t *testing.T) {
	rule := NewDuplicateBlockRule()
	body := regionBody(50)
	code := "package blk\n\nfunc first() {\n" + body + "}\n\nfunc second() {\n" + body + "}\n"

	violations := rule.AnalyzeFile(createTestContext(t, "blk/x.go", code))

	require.Len(t, violations, 1)
	assert.Equal(t, 57, violations[0].Line)
	assert.Equal(t, "Duplicate block (51 lines) - same as lines 4-54", violations[0].Message)
}

// A backtick in a line comment is prose, not a raw-string delimiter: an odd
// number of them must not blank the rest of the file.
func TestDuplicationIgnoresBacktickInComment(t *testing.T) {
	body := regionBody(12)
	code := "package bt\n\n// Use the `name field instead.\nfunc first() {\n" + body + "}\n\n/* a ` in a block\n comment ` too ` */\nfunc second() {\n" + body + "}\n"

	rule := NewDuplicateBlockRule()
	rule.minBlockSize = 10
	assert.Len(t, rule.AnalyzeFile(createTestContext(t, "bt/a.go", code)), 1)

	cross := NewCrossFileDuplicateRule()
	assert.Empty(t, cross.AnalyzeFile(createTestContext(t, "bt/a.go", "package bt\n\n// the `x` and `y\nfunc a() {\n"+body+"}\n")))
	assert.Len(t, cross.AnalyzeFile(createTestContext(t, "bt/b.go", "package bt\n\nfunc b() {\n"+body+"}\n")), 1)
}

// A block size that is not a positive whole number, or too small to ever hold
// enough meaningful lines, is a configuration error, not a panic later.
func TestDuplicationRulesRejectInvalidBlockSize(t *testing.T) {
	for _, value := range []any{-1, 0, 3, 2.5, "10"} {
		assert.Error(t, NewCrossFileDuplicateRule().Configure(map[string]any{"min_block_size": value}), "cross-file %v", value)
		assert.Error(t, NewDuplicateBlockRule().Configure(map[string]any{"min_block_size": value}), "duplicate-block %v", value)
	}
	cross := NewCrossFileDuplicateRule()
	require.NoError(t, cross.Configure(map[string]any{"min_block_size": 12}))
	assert.Equal(t, 12, cross.minBlockSize)
	block := NewDuplicateBlockRule()
	require.NoError(t, block.Configure(map[string]any{"min_block_size": float64(30)}))
	assert.Equal(t, 30, block.minBlockSize)
	require.NoError(t, block.Configure(map[string]any{}))
	assert.Equal(t, defaultBlockSize, block.minBlockSize)
}

// A file read from disk ends with a newline, and splitting it leaves an empty
// last element that is not a line of the file: a region running to the end of
// the file stops at its last line.
func TestCrossFileDuplicateRegionStopsAtLastLine(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	body := regionBody(25)
	a := core.NewFileContext("/copies/a.go", "/", []byte("package copies\n\nfunc a() {\n"+body+"}\n"), nil)
	b := core.NewFileContext("/copies/b.go", "/", []byte("package copies\n\n\nfunc b() {\n"+body+"}\n"), nil)

	assert.Empty(t, rule.AnalyzeFile(a))
	violations := rule.AnalyzeFile(b)

	require.Len(t, violations, 1)
	assert.Equal(t, "Cross-file duplicate (lines 5-30): same as copies/a.go:4-29", violations[0].Message)
}
