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
