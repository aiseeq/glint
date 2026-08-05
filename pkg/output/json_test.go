package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestJSONOutputWritesMachineReadableResults(t *testing.T) {
	violations := core.ViolationList{
		core.NewViolation("nil-slice", "patterns", "b.go", 10, core.SeverityLow, "use len").WithCode("if xs == nil").WithSuggestion("Use len(xs) == 0"),
		core.NewViolation("query-in-loop", "performance", "a.go", 5, core.SeverityMedium, "query inside loop").WithColumn(3).WithContext("repo", "UserRepo"),
	}
	stats := Stats{FilesAnalyzed: 7, FilesSkipped: 1, RulesRun: 42, Duration: 1.25}

	var buf bytes.Buffer
	err := NewJSONOutput().WithWriter(&buf).Write(violations, stats)
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))

	summary := payload["summary"].(map[string]any)
	require.Equal(t, float64(2), summary["total"])
	require.Equal(t, float64(1), summary["medium"])
	require.Equal(t, float64(1), summary["low"])

	statsPayload := payload["stats"].(map[string]any)
	require.Equal(t, float64(7), statsPayload["filesAnalyzed"])
	require.Equal(t, float64(1), statsPayload["filesSkipped"])
	require.Equal(t, float64(42), statsPayload["rulesRun"])
	require.Equal(t, float64(1.25), statsPayload["duration"])

	issues := payload["issues"].([]any)
	require.Len(t, issues, 2)
	first := issues[0].(map[string]any)
	require.Equal(t, "a.go", first["file"])
	require.Equal(t, "query-in-loop", first["rule"])
	require.Equal(t, "medium", first["severity"])
	require.Equal(t, float64(3), first["column"])
	require.Equal(t, "UserRepo", first["context"].(map[string]any)["repo"])

	byRule := payload["byRule"].(map[string]any)
	require.Equal(t, float64(1), byRule["nil-slice"])
	require.Equal(t, float64(1), byRule["query-in-loop"])
}

func TestJSONOutputWritesEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	err := NewJSONOutput().WithWriter(&buf).Write(nil, Stats{FilesAnalyzed: 3})
	require.NoError(t, err)

	var payload struct {
		Summary struct {
			Total int `json:"total"`
		} `json:"summary"`
		Issues []jsonIssue `json:"issues"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))
	require.Equal(t, 0, payload.Summary.Total)
	require.Empty(t, payload.Issues)
}

func TestJSONOutputSeverityMapAlwaysHasAllKeys(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, NewJSONOutput().WithWriter(&buf).Write(nil, Stats{}))

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))

	bySeverity := payload["bySeverity"].(map[string]any)
	for _, key := range []string{"critical", "high", "medium", "low"} {
		require.Contains(t, bySeverity, key)
		require.Equal(t, float64(0), bySeverity[key])
	}
}

func TestJSONOutputCountsByCategory(t *testing.T) {
	violations := core.ViolationList{
		core.NewViolation("r1", "security", "a.go", 1, core.SeverityHigh, "m"),
		core.NewViolation("r2", "security", "a.go", 2, core.SeverityHigh, "m"),
		core.NewViolation("r3", "naming", "b.go", 3, core.SeverityLow, "m"),
	}

	var buf bytes.Buffer
	require.NoError(t, NewJSONOutput().WithWriter(&buf).Write(violations, Stats{}))

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))

	byCategory := payload["byCategory"].(map[string]any)
	require.Equal(t, float64(2), byCategory["security"])
	require.Equal(t, float64(1), byCategory["naming"])

	bySeverity := payload["bySeverity"].(map[string]any)
	require.Equal(t, float64(2), bySeverity["high"])
	require.Equal(t, float64(1), bySeverity["low"])
	require.Equal(t, float64(0), bySeverity["critical"])
}

func TestJSONOutputEscapesSpecialCharacters(t *testing.T) {
	message := "quotes \"here\", newline\nhere, tab\there, unicode: приложение 🚀, backslash \\path"
	violations := core.ViolationList{
		core.NewViolation("r1", "patterns", `dir\file "x".go`, 1, core.SeverityLow, message).
			WithSuggestion("use <html> & \"escapes\"").
			WithCode("s := \"multi\nline\""),
	}

	var buf bytes.Buffer
	require.NoError(t, NewJSONOutput().WithWriter(&buf).Write(violations, Stats{}))

	// The output must survive a strict round-trip: parse it back and compare
	// the strings byte for byte.
	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))

	issue := payload["issues"].([]any)[0].(map[string]any)
	require.Equal(t, message, issue["message"])
	require.Equal(t, `dir\file "x".go`, issue["file"])
	require.Equal(t, "use <html> & \"escapes\"", issue["suggestion"])
	require.Equal(t, "s := \"multi\nline\"", issue["code"])
}

func TestJSONOutputSortsIssuesByFileLineColumnRule(t *testing.T) {
	violations := core.ViolationList{
		core.NewViolation("z-rule", "patterns", "b.go", 1, core.SeverityLow, "m"),
		core.NewViolation("b-rule", "patterns", "a.go", 5, core.SeverityLow, "m"),
		core.NewViolation("a-rule", "patterns", "a.go", 5, core.SeverityLow, "m"),
		core.NewViolation("c-rule", "patterns", "a.go", 2, core.SeverityLow, "m").WithColumn(9),
		core.NewViolation("c-rule", "patterns", "a.go", 2, core.SeverityLow, "m").WithColumn(4),
	}

	var buf bytes.Buffer
	require.NoError(t, NewJSONOutput().WithWriter(&buf).Write(violations, Stats{}))

	var payload struct {
		Issues []jsonIssue `json:"issues"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))
	require.Len(t, payload.Issues, 5)

	got := make([]string, 0, len(payload.Issues))
	for _, is := range payload.Issues {
		got = append(got, is.File+"|"+is.Rule)
	}
	require.Equal(t, []string{
		"a.go|c-rule", // line 2, col 4
		"a.go|c-rule", // line 2, col 9
		"a.go|a-rule", // line 5, rule tie-break
		"a.go|b-rule",
		"b.go|z-rule",
	}, got)
	require.Equal(t, 4, payload.Issues[0].Column)
	require.Equal(t, 9, payload.Issues[1].Column)
}

func TestJSONOutputOmitsEmptyOptionalFields(t *testing.T) {
	violations := core.ViolationList{
		core.NewViolation("r1", "patterns", "a.go", 1, core.SeverityLow, "m"),
	}

	var buf bytes.Buffer
	require.NoError(t, NewJSONOutput().WithWriter(&buf).Write(violations, Stats{}))

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))

	issue := payload["issues"].([]any)[0].(map[string]any)
	for _, key := range []string{"column", "endLine", "suggestion", "code", "context"} {
		require.NotContains(t, issue, key, "empty optional field %q must be omitted", key)
	}

	stats := payload["stats"].(map[string]any)
	require.NotContains(t, stats, "packagesSkipped", "zero packagesSkipped must be omitted")
}

func TestJSONOutputPropagatesWriteError(t *testing.T) {
	err := NewJSONOutput().WithWriter(&failingWriter{failAfter: 0}).Write(nil, Stats{})
	require.Error(t, err)
}
