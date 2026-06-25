package output

import (
	"encoding/json"
	"io"
	"os"
	"sort"

	"github.com/aiseeq/glint/pkg/core"
)

// JSONOutput writes analysis results as machine-readable JSON.
type JSONOutput struct {
	writer io.Writer
}

// NewJSONOutput creates a new JSON output.
func NewJSONOutput() *JSONOutput {
	return &JSONOutput{writer: os.Stdout}
}

// WithWriter sets a custom writer.
func (j *JSONOutput) WithWriter(w io.Writer) *JSONOutput {
	j.writer = w
	return j
}

// Write outputs violations and aggregate counters as JSON.
func (j *JSONOutput) Write(violations core.ViolationList, stats Stats) error {
	result := jsonResult{
		Summary:    buildJSONSummary(violations),
		Stats:      jsonStats(stats),
		Issues:     buildJSONIssues(violations),
		BySeverity: buildSeverityCounts(violations),
		ByRule:     violations.CountByRule(),
		ByCategory: violations.CountByCategory(),
	}

	encoder := json.NewEncoder(j.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

type jsonResult struct {
	Summary    jsonSummary    `json:"summary"`
	Stats      jsonStats      `json:"stats"`
	Issues     []jsonIssue    `json:"issues"`
	BySeverity map[string]int `json:"bySeverity"`
	ByRule     map[string]int `json:"byRule"`
	ByCategory map[string]int `json:"byCategory"`
}

type jsonSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type jsonStats struct {
	FilesAnalyzed int     `json:"filesAnalyzed"`
	FilesSkipped  int     `json:"filesSkipped"`
	RulesRun      int     `json:"rulesRun"`
	Duration      float64 `json:"duration"`
}

type jsonIssue struct {
	Rule       string         `json:"rule"`
	Category   string         `json:"category"`
	Severity   string         `json:"severity"`
	File       string         `json:"file"`
	Line       int            `json:"line"`
	Column     int            `json:"column,omitempty"`
	EndLine    int            `json:"endLine,omitempty"`
	Message    string         `json:"message"`
	Suggestion string         `json:"suggestion,omitempty"`
	Code       string         `json:"code,omitempty"`
	Context    map[string]any `json:"context,omitempty"`
}

func buildJSONSummary(violations core.ViolationList) jsonSummary {
	counts := violations.CountBySeverity()
	return jsonSummary{
		Total:    len(violations),
		Critical: counts[core.SeverityCritical],
		High:     counts[core.SeverityHigh],
		Medium:   counts[core.SeverityMedium],
		Low:      counts[core.SeverityLow],
	}
}

func buildJSONIssues(violations core.ViolationList) []jsonIssue {
	items := make([]*core.Violation, len(violations))
	copy(items, violations)
	sort.Slice(items, func(i, k int) bool {
		if items[i].File != items[k].File {
			return items[i].File < items[k].File
		}
		if items[i].Line != items[k].Line {
			return items[i].Line < items[k].Line
		}
		if items[i].Column != items[k].Column {
			return items[i].Column < items[k].Column
		}
		return items[i].Rule < items[k].Rule
	})

	issues := make([]jsonIssue, 0, len(items))
	for _, v := range items {
		issues = append(issues, jsonIssue{
			Rule:       v.Rule,
			Category:   v.Category,
			Severity:   v.Severity.String(),
			File:       v.File,
			Line:       v.Line,
			Column:     v.Column,
			EndLine:    v.EndLine,
			Message:    v.Message,
			Suggestion: v.Suggestion,
			Code:       v.Code,
			Context:    v.Context,
		})
	}
	return issues
}

func buildSeverityCounts(violations core.ViolationList) map[string]int {
	counts := violations.CountBySeverity()
	return map[string]int{
		core.SeverityCritical.String(): counts[core.SeverityCritical],
		core.SeverityHigh.String():     counts[core.SeverityHigh],
		core.SeverityMedium.String():   counts[core.SeverityMedium],
		core.SeverityLow.String():      counts[core.SeverityLow],
	}
}
