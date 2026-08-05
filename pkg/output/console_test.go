package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// withColorState pins the fatih/color global to a known value for the duration
// of the test: in CI stdout is not a tty and NoColor defaults to true, so
// color assertions would otherwise depend on the environment.
func withColorState(t *testing.T, noColor bool) {
	t.Helper()
	saved := color.NoColor
	color.NoColor = noColor
	t.Cleanup(func() { color.NoColor = saved })
}

func consoleViolations() core.ViolationList {
	return core.ViolationList{
		core.NewViolation("magic-number", "patterns", "b.go", 20, core.SeverityLow, "magic number 42"),
		core.NewViolation("sql-injection", "security", "a.go", 15, core.SeverityCritical, "string concat in query").
			WithCode("  query := \"SELECT * FROM t WHERE id=\" + id  ").
			WithSuggestion("Use parameterized queries"),
		core.NewViolation("god-object", "architecture", "a.go", 3, core.SeverityHigh, "struct has 30 methods"),
		core.NewViolation("dead-code", "deadcode", "a.go", 3, core.SeverityMedium, "unused function"),
	}
}

func TestConsoleOutputWithViolations(t *testing.T) {
	withColorState(t, true)

	var buf bytes.Buffer
	err := NewConsoleOutput().WithWriter(&buf).Write(consoleViolations(), Stats{FilesAnalyzed: 12, FilesSkipped: 2})
	require.NoError(t, err)
	got := buf.String()

	// Header.
	assert.Contains(t, got, "GLINT ANALYSIS RESULTS")
	assert.Contains(t, got, "Files analyzed: 12")
	assert.Contains(t, got, "Files skipped: 2")

	// Severity labels next to messages.
	assert.Contains(t, got, "[CRITICAL] string concat in query (sql-injection)")
	assert.Contains(t, got, "[HIGH] struct has 30 methods (god-object)")
	assert.Contains(t, got, "[MEDIUM] unused function (dead-code)")
	assert.Contains(t, got, "[LOW] magic number 42 (magic-number)")

	// Code snippet is trimmed, suggestion is printed.
	assert.Contains(t, got, "> query := \"SELECT * FROM t WHERE id=\" + id\n")
	assert.Contains(t, got, "Suggestion: Use parameterized queries")

	// Summary counts per severity.
	assert.Contains(t, got, "SUMMARY: 4 issues found")
	assert.Contains(t, got, "Critical: 1")
	assert.Contains(t, got, "High: 1")
	assert.Contains(t, got, "Medium: 1")
	assert.Contains(t, got, "Low: 1")
	assert.NotContains(t, got, "No issues found")
}

func TestConsoleOutputGroupsAndSortsViolations(t *testing.T) {
	withColorState(t, true)

	var buf bytes.Buffer
	require.NoError(t, NewConsoleOutput().WithWriter(&buf).Write(consoleViolations(), Stats{FilesAnalyzed: 1}))
	got := buf.String()

	// Files sorted alphabetically, each printed once.
	posA := strings.Index(got, "a.go\n")
	posB := strings.Index(got, "b.go\n")
	require.GreaterOrEqual(t, posA, 0, "a.go header missing")
	require.GreaterOrEqual(t, posB, 0, "b.go header missing")
	assert.Less(t, posA, posB, "files must be sorted alphabetically")
	assert.Equal(t, 1, strings.Count(got, "a.go\n"), "each file header printed once")

	// Within a file: sorted by line, ties broken by rule name.
	deadCode := strings.Index(got, "(dead-code)")
	godObject := strings.Index(got, "(god-object)")
	sqlInjection := strings.Index(got, "(sql-injection)")
	assert.Less(t, deadCode, godObject, "same line: rule name order")
	assert.Less(t, godObject, sqlInjection, "line 3 before line 15")
}

func TestConsoleOutputNoIssues(t *testing.T) {
	withColorState(t, true)

	var buf bytes.Buffer
	require.NoError(t, NewConsoleOutput().WithWriter(&buf).Write(nil, Stats{FilesAnalyzed: 5}))
	got := buf.String()

	assert.Contains(t, got, "No issues found!")
	assert.Contains(t, got, "Files analyzed: 5")
	assert.NotContains(t, got, "GLINT ANALYSIS RESULTS")
	assert.NotContains(t, got, "SUMMARY")
}

func TestConsoleOutputSkippedFilesHiddenWhenZero(t *testing.T) {
	withColorState(t, true)

	var buf bytes.Buffer
	require.NoError(t, NewConsoleOutput().WithWriter(&buf).Write(consoleViolations(), Stats{FilesAnalyzed: 3}))
	assert.NotContains(t, buf.String(), "Files skipped")
}

func TestConsoleOutputColorEscapeCodes(t *testing.T) {
	withColorState(t, false)

	var buf bytes.Buffer
	require.NoError(t, NewConsoleOutput().WithWriter(&buf).Write(consoleViolations(), Stats{FilesAnalyzed: 1}))
	assert.Contains(t, buf.String(), "\x1b[", "colored mode must emit ANSI escape codes")
}

func TestConsoleOutputWithNoColorSuppressesEscapeCodes(t *testing.T) {
	withColorState(t, false)

	var buf bytes.Buffer
	out := NewConsoleOutput().WithWriter(&buf).WithNoColor(true)
	require.NoError(t, out.Write(consoleViolations(), Stats{FilesAnalyzed: 1}))
	assert.NotContains(t, buf.String(), "\x1b[", "WithNoColor(true) must strip ANSI escape codes")
}

func TestConsoleOutputWithNoColorFalseKeepsColors(t *testing.T) {
	withColorState(t, false)

	var buf bytes.Buffer
	out := NewConsoleOutput().WithWriter(&buf).WithNoColor(false)
	require.NoError(t, out.Write(consoleViolations(), Stats{FilesAnalyzed: 1}))
	assert.Contains(t, buf.String(), "\x1b[", "WithNoColor(false) must not disable colors")
}

// failingWriter fails every write after the first n bytes-worth of calls.
type failingWriter struct {
	failAfter int
	calls     int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	f.calls++
	if f.calls > f.failAfter {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

func TestConsoleOutputPropagatesWriteError(t *testing.T) {
	withColorState(t, true)

	err := NewConsoleOutput().WithWriter(&failingWriter{failAfter: 2}).Write(consoleViolations(), Stats{FilesAnalyzed: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
}

func TestReportWriterStopsAfterFirstError(t *testing.T) {
	fw := &failingWriter{failAfter: 1}
	rw := newReportWriter(fw)
	rw.line("first")                             // ok
	rw.printf("second")                          // fails
	rw.line("third")                             // must be skipped
	rw.colored(color.New(color.FgRed), "fourth") // must be skipped

	require.Error(t, rw.Err())
	assert.Equal(t, 2, fw.calls, "writes after the first failure must be no-ops")
}
