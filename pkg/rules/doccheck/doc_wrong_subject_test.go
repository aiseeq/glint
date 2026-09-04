package doccheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeDocSubject(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := NewDocWrongSubjectRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

// Repro from a real project: new code was pasted between a comment and the
// function it described, and the reasoning behind a measurement ended up
// attributed to a neighbour. The package had 22 such comments.
func TestDocWrongSubjectReportsDetachedComment(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"tactics.go": `package tactics

// pickAnchor returns the first anchor that fits, measured over 200 runs.
func newTimer() int { return 0 }

func pickAnchor() int { return 0 }
`})

	require.Len(t, violations, 1)
	assert.Equal(t, 4, violations[0].Line)
	assert.Contains(t, violations[0].Message, "pickAnchor")
	assert.Contains(t, violations[0].Message, "newTimer")
}

// The subject may live in another file of the same package.
func TestDocWrongSubjectReportsAcrossFiles(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{
		"a.go": `package tactics

// pickAnchor returns the first anchor that fits.
func newTimer() int { return 0 }
`,
		"b.go": `package tactics

func pickAnchor() int { return 0 }
`,
	})

	require.Len(t, violations, 1)
}

// The normal case: the comment starts with the name of its own function.
func TestDocWrongSubjectAcceptsOwnName(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"tactics.go": `package tactics

// pickAnchor returns the first anchor that fits.
func pickAnchor() int { return 0 }

// newTimer starts the countdown.
func newTimer() int { return 0 }
`})

	assert.Empty(t, violations)
}

// A method carries the same name as a function elsewhere; the doc belongs to
// the method it sits on.
func TestDocWrongSubjectAcceptsMethodOfSameName(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"tactics.go": `package tactics

type Plan struct{}

// run executes the plan.
func (p *Plan) run() {}

func run() {}
`})

	assert.Empty(t, violations)
}

// Mentioning another function later in the sentence is normal prose.
func TestDocWrongSubjectAcceptsMentionOfAnotherFunction(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"tactics.go": `package tactics

// newTimer starts the countdown used by pickAnchor.
func newTimer() int { return 0 }

func pickAnchor() int { return 0 }
`})

	assert.Empty(t, violations)
}

// A doc that starts with an ordinary word has no subject to confuse.
func TestDocWrongSubjectAcceptsProseComment(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"tactics.go": `package tactics

// Returns the first anchor that fits.
func pickAnchor() int { return 0 }
`})

	assert.Empty(t, violations)
}

// The doc names another function first but also names its own — an explanation
// of the pair, not a comment that lost its function.
func TestDocWrongSubjectAcceptsDocNamingBoth(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"tactics.go": `package tactics

// pickAnchor is the caller of newTimer, which starts the countdown.
func newTimer() int { return 0 }

func pickAnchor() int { return 0 }
`})

	assert.Empty(t, violations)
}
