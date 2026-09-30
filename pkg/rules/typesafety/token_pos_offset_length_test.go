package typesafety

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The difference of two positions is a length, valid in any file set; the
// position minus its file's base is how token.File.Offset itself computes the
// in-file offset. Neither is the bug.
func TestTokenPosOffsetAcceptsLengthAndBaseOffset(t *testing.T) {
	violations := analyzeTokenPos(t, `package lines

import (
	"go/ast"
	"go/token"
)

func length(n ast.Node) int {
	return int(n.End()) - int(n.Pos())
}

func offset(f *token.File, p token.Pos) int {
	return int(p) - f.Base()
}
`)

	assert.Empty(t, violations)
}

// Content indexed by a token.Pos directly, without a conversion to int, is the
// same bug as indexing by int(pos).
func TestTokenPosOffsetReportsUnconvertedPosIndex(t *testing.T) {
	violations := analyzeTokenPos(t, `package lines

import "go/ast"

func charAt(content []byte, n ast.Node) byte {
	return content[n.Pos()-1]
}

func span(content string, n ast.Node) string {
	return content[n.Pos():n.End()]
}
`)

	require.Len(t, violations, 2)
	assert.Equal(t, 6, violations[0].Line)
	assert.Equal(t, 10, violations[1].Line)
}
