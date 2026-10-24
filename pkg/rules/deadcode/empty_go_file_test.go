package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Repro from a real project: the only function of a file was deleted, and the
// file stayed with the package clause and the comment that described it.
func TestEmptyGoFileReportsFileLeftWithComment(t *testing.T) {
	ctx := parseGoContext(t, "hitting.go", `package defense

// Foes hitting ours at the bases: a foe with damage that has one of ours in
// reach, counted only next to our own halls.
`)
	violations := NewEmptyGoFileRule().AnalyzeFile(ctx)

	require.Len(t, violations, 1)
	assert.Equal(t, 1, violations[0].Line)
	assert.Contains(t, violations[0].Message, "hitting.go")
}

// A package clause alone is the same leftover.
func TestEmptyGoFileReportsBarePackageClause(t *testing.T) {
	ctx := parseGoContext(t, "left.go", "package defense\n")

	assert.Len(t, NewEmptyGoFileRule().AnalyzeFile(ctx), 1)
}

// A doc.go holds the package doc and nothing else by design.
func TestEmptyGoFileAcceptsPackageDoc(t *testing.T) {
	ctx := parseGoContext(t, "doc.go", `// Package defense holds the defense lines of the bot.
package defense
`)

	assert.Empty(t, NewEmptyGoFileRule().AnalyzeFile(ctx))
}

// A file under a build constraint keeps the package buildable where the rest
// is excluded; blank imports are there for their side effects.
func TestEmptyGoFileAcceptsConstraintAndBlankImports(t *testing.T) {
	constrained := parseGoContext(t, "stub_other.go", `//go:build !linux

package defense
`)
	tools := parseGoContext(t, "tools.go", `package defense

import _ "embed"
`)

	assert.Empty(t, NewEmptyGoFileRule().AnalyzeFile(constrained))
	assert.Empty(t, NewEmptyGoFileRule().AnalyzeFile(tools))
}

// A file with a declaration is not empty.
func TestEmptyGoFileAcceptsDeclaration(t *testing.T) {
	ctx := parseGoContext(t, "defense.go", `package defense

const reach = 6
`)

	assert.Empty(t, NewEmptyGoFileRule().AnalyzeFile(ctx))
}
