package typesafety

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeTokenPos(t *testing.T, source string) []*core.Violation {
	t.Helper()
	project := rulestest.Project(t, map[string]string{"lines.go": source})
	violations, err := NewTokenPosOffsetRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	return violations
}

// Repro from glint itself (fixed in f88a6e9): three rules counted lines by
// walking the file content up to int(pos)-1, which stopped being the right
// offset as soon as the project shared one FileSet.
func TestTokenPosOffsetReportsManualLineCount(t *testing.T) {
	violations := analyzeTokenPos(t, `package lines

import "go/ast"

func lineOf(content []byte, node ast.Node) int {
	offset := int(node.Pos()) - 1
	if offset < 0 || offset >= len(content) {
		return 1
	}
	line := 1
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[0].Message, "file set")
}

// Resolving through the file set is the correct way and stays silent.
func TestTokenPosOffsetAcceptsFileSetPosition(t *testing.T) {
	violations := analyzeTokenPos(t, `package lines

import (
	"go/ast"
	"go/token"
)

func lineOf(fset *token.FileSet, node ast.Node) int {
	return fset.Position(node.Pos()).Line
}
`)

	assert.Empty(t, violations)
}

// Comparing positions needs no conversion, and none is reported.
func TestTokenPosOffsetAcceptsPositionComparison(t *testing.T) {
	violations := analyzeTokenPos(t, `package lines

import "go/ast"

func within(node ast.Node, start, end ast.Node) bool {
	return node.Pos() >= start.Pos() && node.Pos() <= end.Pos()
}
`)

	assert.Empty(t, violations)
}

// Converting an ordinary integer is not this rule's business.
func TestTokenPosOffsetIgnoresOtherConversions(t *testing.T) {
	violations := analyzeTokenPos(t, `package lines

func widen(n int32) int64 {
	return int64(n)
}
`)

	assert.Empty(t, violations)
}

// Repro from glint itself: a position converted to an int only to key a map of
// already-reported findings is an identifier, not an offset.
func TestTokenPosOffsetIgnoresMapKey(t *testing.T) {
	violations := analyzeTokenPos(t, `package lines

import "go/ast"

func dedupe(nodes []ast.Node) int {
	reported := make(map[int]bool)
	for _, node := range nodes {
		if reported[int(node.Pos())] {
			continue
		}
		reported[int(node.Pos())] = true
	}
	return len(reported)
}
`)

	assert.Empty(t, violations)
}

// Indexing the file content by a position is the bug this rule is about.
func TestTokenPosOffsetReportsContentIndexing(t *testing.T) {
	violations := analyzeTokenPos(t, `package lines

import "go/ast"

func charAt(content []byte, node ast.Node) byte {
	return content[int(node.Pos())]
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
}

func TestTokenPosOffsetMetadata(t *testing.T) {
	rule := NewTokenPosOffsetRule()
	assert.Equal(t, "token-pos-offset", rule.Name())
	assert.Equal(t, "typesafety", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
	assert.Nil(t, rule.AnalyzeFile(nil))
}

func TestTokenPosOffsetRejectsNilProject(t *testing.T) {
	_, err := NewTokenPosOffsetRule().AnalyzeGoProject(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil Go project context")
}
