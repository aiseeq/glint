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

// Repro from a real project: a function was deleted and its comment stayed,
// glued to the doc of the next function. The first word names nothing the
// package declares any more, and the own name opens a later line.
func TestDocWrongSubjectReportsCommentOfRemovedFunctionGluedToNextDoc(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"detect.go": `package detect

// heatSpot — a hot spot of a hidden unit: a foe nobody sees stands next to
// one of ours, measured over 40 runs.
// hiddenNearBase — hidden foes next to our bases.
func hiddenNearBase() int { return 0 }
`})

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[0].Message, "heatSpot")
	assert.Contains(t, violations[0].Message, "hiddenNearBase")
}

// The removed function's comment is the whole doc: the first word is a name
// the package does not declare, written like an identifier.
func TestDocWrongSubjectReportsCommentOfRemovedFunction(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"detect.go": `package detect

// heatSpot reports a hidden foe next to one of ours.
func hiddenNearBase() int { return 0 }
`})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "heatSpot")
}

// A function declared elsewhere and glued above the own doc is the same
// leftover, even though the doc also names its own function.
func TestDocWrongSubjectReportsDeclaredSubjectGluedToOwnDoc(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"tactics.go": `package tactics

// pickAnchor returns the first anchor that fits.
// newTimer starts the countdown.
func newTimer() int { return 0 }

func pickAnchor() int { return 0 }
`})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "pickAnchor")
}

// A name the code of the package uses — a parameter, a field, a variable —
// is a subject the doc may well start with.
func TestDocWrongSubjectAcceptsNameUsedInCode(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"tactics.go": `package tactics

type plan struct{ maxSteps int }

// maxSteps must be positive; the plan stops at it.
func (p *plan) limit() int { return p.maxSteps }

// stepCount is how many steps to run.
func run(stepCount int) int { return stepCount }
`})

	assert.Empty(t, violations)
}

// An ordinary word, a one-word name or a brand written in capitals is prose,
// not the name of a removed function.
func TestDocWrongSubjectAcceptsWordsThatAreNotNames(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"tactics.go": `package tactics

// sharpy keeps the hot spot for 30 seconds.
func keepSpot() int { return 0 }

// PostgreSQL rejects an empty array here.
func emptyArray() int { return 0 }

// Note: the anchor list is sorted.
// pickAnchor returns the first anchor that fits.
func pickAnchor() int { return 0 }
`})

	assert.Empty(t, violations)
}

func TestDocWrongSubjectReportsFunctionDocAttachedToGenDecl(t *testing.T) {
	tests := []struct {
		name    string
		decl    string
		subject string
		kind    string
	}{
		{name: "unexported method", decl: `// saveNote stores a note atomically.
const noteOrigin = "manual"

func (r *repo) saveNote() {}`, subject: "saveNote", kind: "const"},
		{name: "exported method", decl: `// SaveNote stores a note atomically.
var noteOrigin = "manual"

func (r *repo) SaveNote() {}`, subject: "SaveNote", kind: "var"},
		{name: "function", decl: `// fetchAll loads every record.
type retryPolicy struct{}

func fetchAll() {}`, subject: "fetchAll", kind: "type"},
		{name: "exported function", decl: `// FetchAll loads every record.
var noteOrigin = "manual"

func FetchAll() {}`, subject: "FetchAll", kind: "var"},
		{name: "grouped const spec", decl: `const (
	// fetchAll loads every record.
	retryDelay = 1
)

func fetchAll() {}`, subject: "fetchAll", kind: "const"},
		{name: "grouped const declaration", decl: `// fetchAll loads every record.
const (
	retryDelay = 1
)

func fetchAll() {}`, subject: "fetchAll", kind: "const"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := "package subject\n\ntype repo struct{}\n\n" + tt.decl + "\n"
			violations := analyzeDocSubject(t, map[string]string{"subject.go": source})
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tt.subject)
			assert.Contains(t, violations[0].Message, tt.kind)
			assert.Contains(t, violations[0].Suggestion, tt.kind)
		})
	}
}

func TestDocWrongSubjectAcceptsGenDeclComments(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"subject.go": `package subject

// retryDelay controls spacing between attempts.
const retryDelay = 1

// fetchAll waits this long between attempts.
const wait = retryDelay

// fetchAll waits this long between attempts.
func fetchAll() {}

// maxAttempts is the maximum number of retries.
const maxAttempts = 3
`})

	assert.Empty(t, violations)
}

func TestDocWrongSubjectReportsDocAboveSeveralInsertedDecls(t *testing.T) {
	violations := analyzeDocSubject(t, map[string]string{"subject.go": `package subject

// saveNote stores a note and its revision.
const noteOrigin = "manual"
var saveTimeout = 30

func saveNote() {}
`})

	require.Len(t, violations, 1)
	assert.Equal(t, 4, violations[0].Line)
	assert.Contains(t, violations[0].Message, "saveNote")
}

func TestDocWrongSubjectReportsGroupDocAtTheGroup(t *testing.T) {
	for name, specs := range map[string]string{"one spec": "\tlimit = 1\n", "two specs": "\tlimit = 1\n\tdepth = 2\n"} {
		t.Run(name, func(t *testing.T) {
			violations := analyzeDocSubject(t, map[string]string{"subject.go": "package subject\n\n// fetch loads records.\nconst (\n" + specs + ")\n\nfunc fetch() {}\n"})
			require.Len(t, violations, 1)
			assert.Equal(t, 4, violations[0].Line)
		})
	}
}
