package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Repro from a real project: the constant group that the comment documented
// was deleted, and the comment ended up at the bottom of the import group.
func TestDeclGroupTrailingCommentReportsCommentAfterLastImport(t *testing.T) {
	ctx := parseGoContext(t, "ids.go", `package economy

import (
	"example.com/game/data"
	// Ids of types, abilities and buffs of the game API. The source is the
	// enums of the protocol: ability/enum.go, buff/enum.go.
)

var _ = data.One
`)
	violations := NewDeclGroupTrailingCommentRule().AnalyzeFile(ctx)

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Contains(t, violations[0].Message, "import")
}

// The last constant of a group was deleted and its doc stayed under the one
// before it.
func TestDeclGroupTrailingCommentReportsDocOfRemovedConstant(t *testing.T) {
	ctx := parseGoContext(t, "ids.go", `package economy

const (
	// TypeWorker — id of the worker.
	TypeWorker = 45

	// TypeHall — id of the hall.
)
`)
	violations := NewDeclGroupTrailingCommentRule().AnalyzeFile(ctx)

	require.Len(t, violations, 1)
	assert.Equal(t, 7, violations[0].Line)
}

// The doc of an entry, a line comment on the last entry, a comment between
// entries, and an empty group (left to empty-decl-group) are not trailing
// comments.
func TestDeclGroupTrailingCommentAcceptsCommentsOfEntries(t *testing.T) {
	ctx := parseGoContext(t, "ids.go", `package economy

import (
	"fmt"

	// The embed package for the assets below.
	_ "embed"
)

const (
	// TypeWorker — id of the worker.
	TypeWorker = 45
	// worker kinds above, hall kinds below
	TypeHall = 86 // the main hall
)

var (
	a = fmt.Sprint(TypeWorker)
	b = 2 /* second */ // in pairs
)

const (
	// TypeGone — id of a removed type.
)

const (
	holdSec = 1.0 // the picture holds: the view of its workers updates a
	// frame after ours come into sight
	seeRange = 8 // sight of a worker: closer to its start its line is seen
	// (two of thirteen seen from the edge)
)
`)

	assert.Empty(t, NewDeclGroupTrailingCommentRule().AnalyzeFile(ctx))
}
