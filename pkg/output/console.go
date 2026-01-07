package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/aiseeq/glint/pkg/core"
)

const (
	outputLineWidth = 60
	topIssuesLimit  = 5
)

// ConsoleOutput writes violations to console with colors
type ConsoleOutput struct {
	writer  io.Writer
	verbose bool
	noColor bool
}

// NewConsoleOutput creates a new console output
func NewConsoleOutput() *ConsoleOutput {
	return &ConsoleOutput{
		writer: os.Stdout,
	}
}

// WithWriter sets a custom writer
func (c *ConsoleOutput) WithWriter(w io.Writer) *ConsoleOutput {
	c.writer = w
	return c
}

// WithVerbose enables verbose output
func (c *ConsoleOutput) WithVerbose(v bool) *ConsoleOutput {
	c.verbose = v
	return c
}

// WithNoColor disables colors
func (c *ConsoleOutput) WithNoColor(v bool) *ConsoleOutput {
	c.noColor = v
	if v {
		color.NoColor = true
	}
	return c
}

// Write outputs violations to console
func (c *ConsoleOutput) Write(violations core.ViolationList, stats Stats) error {
	if len(violations) == 0 {
		c.printSuccess(stats)
		return nil
	}

	c.printHeader(stats)
	c.printViolations(violations)
	c.printSummary(violations)

	return nil
}

func (c *ConsoleOutput) printHeader(stats Stats) {
	fmt.Fprintln(c.writer)
	fmt.Fprintln(c.writer, "GLINT ANALYSIS RESULTS")
	fmt.Fprintln(c.writer, strings.Repeat("=", outputLineWidth))
	fmt.Fprintf(c.writer, "Files analyzed: %d\n", stats.FilesAnalyzed)
	if stats.FilesSkipped > 0 {
		fmt.Fprintf(c.writer, "Files skipped: %d\n", stats.FilesSkipped)
	}
	fmt.Fprintln(c.writer)
}

func (c *ConsoleOutput) printSuccess(stats Stats) {
	green := color.New(color.FgGreen, color.Bold)

	fmt.Fprintln(c.writer)
	green.Fprintln(c.writer, "No issues found!")
	fmt.Fprintf(c.writer, "Files analyzed: %d\n", stats.FilesAnalyzed)
	fmt.Fprintln(c.writer)
}

func (c *ConsoleOutput) printViolations(violations core.ViolationList) {
	// Group by file
	byFile := make(map[string]core.ViolationList)
	for _, v := range violations {
		byFile[v.File] = append(byFile[v.File], v)
	}

	// Sort files
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)

	// Print each file
	for _, file := range files {
		fileViolations := byFile[file]

		// Sort violations by line
		sort.Slice(fileViolations, func(i, j int) bool {
			return fileViolations[i].Line < fileViolations[j].Line
		})

		// Print file header
		cyan := color.New(color.FgCyan, color.Bold)
		cyan.Fprintf(c.writer, "%s\n", file)

		// Print violations
		for _, v := range fileViolations {
			c.printViolation(v)
		}

		fmt.Fprintln(c.writer)
	}
}

func (c *ConsoleOutput) printViolation(v *core.Violation) {
	// Severity color
	var sevColor *color.Color
	switch v.Severity {
	case core.SeverityCritical:
		sevColor = color.New(color.FgRed, color.Bold)
	case core.SeverityHigh:
		sevColor = color.New(color.FgRed)
	case core.SeverityMedium:
		sevColor = color.New(color.FgYellow)
	case core.SeverityLow:
		sevColor = color.New(color.FgBlue)
	}

	// Line number
	gray := color.New(color.FgHiBlack)
	gray.Fprintf(c.writer, "  %d: ", v.Line)

	// Severity
	sevColor.Fprintf(c.writer, "[%s] ", v.Severity.Label())

	// Message
	fmt.Fprintf(c.writer, "%s ", v.Message)

	// Rule name
	gray.Fprintf(c.writer, "(%s)\n", v.Rule)

	// Code snippet if available
	if v.Code != "" {
		gray.Fprintf(c.writer, "     > %s\n", strings.TrimSpace(v.Code))
	}

	// Suggestion if available
	if v.Suggestion != "" {
		green := color.New(color.FgGreen)
		green.Fprintf(c.writer, "     Suggestion: %s\n", v.Suggestion)
	}
}

func (c *ConsoleOutput) printSummary(violations core.ViolationList) {
	counts := violations.CountBySeverity()

	fmt.Fprintln(c.writer, strings.Repeat("-", outputLineWidth))
	fmt.Fprintf(c.writer, "SUMMARY: %d issues found\n", len(violations))

	// Print counts by severity
	if count, ok := counts[core.SeverityCritical]; ok && count > 0 {
		red := color.New(color.FgRed, color.Bold)
		red.Fprintf(c.writer, "  Critical: %d\n", count)
	}
	if count, ok := counts[core.SeverityHigh]; ok && count > 0 {
		red := color.New(color.FgRed)
		red.Fprintf(c.writer, "  High: %d\n", count)
	}
	if count, ok := counts[core.SeverityMedium]; ok && count > 0 {
		yellow := color.New(color.FgYellow)
		yellow.Fprintf(c.writer, "  Medium: %d\n", count)
	}
	if count, ok := counts[core.SeverityLow]; ok && count > 0 {
		blue := color.New(color.FgBlue)
		blue.Fprintf(c.writer, "  Low: %d\n", count)
	}

	fmt.Fprintln(c.writer)
}

// Stats contains analysis statistics
type Stats struct {
	FilesAnalyzed int
	FilesSkipped  int
	RulesRun      int
	Duration      float64
}

// SummaryOutput writes a compact summary for AI agents
type SummaryOutput struct {
	writer io.Writer
}

// NewSummaryOutput creates a new summary output
func NewSummaryOutput() *SummaryOutput {
	return &SummaryOutput{
		writer: os.Stdout,
	}
}

// WithWriter sets a custom writer
func (s *SummaryOutput) WithWriter(w io.Writer) *SummaryOutput {
	s.writer = w
	return s
}

// Write outputs a compact summary
func (s *SummaryOutput) Write(violations core.ViolationList, stats Stats) error {
	s.printHeader(violations)

	if len(violations) > 0 {
		s.printTopIssues(violations)
	}

	fmt.Fprintf(s.writer, "Files analyzed: %d | Duration: %.2fs\n", stats.FilesAnalyzed, stats.Duration)
	return nil
}

func (s *SummaryOutput) printHeader(violations core.ViolationList) {
	counts := violations.CountBySeverity()

	fmt.Fprintln(s.writer, "GLINT ANALYSIS SUMMARY")
	fmt.Fprintln(s.writer, "======================")
	fmt.Fprintf(s.writer, "Critical: %d | High: %d | Medium: %d | Low: %d\n",
		counts[core.SeverityCritical],
		counts[core.SeverityHigh],
		counts[core.SeverityMedium],
		counts[core.SeverityLow],
	)
	fmt.Fprintln(s.writer)
}

type ruleCount struct {
	rule  string
	count int
	sev   core.Severity
}

func (s *SummaryOutput) printTopIssues(violations core.ViolationList) {
	ruleCounts := s.buildRuleCounts(violations)

	fmt.Fprintln(s.writer, "TOP ISSUES:")
	limit := topIssuesLimit
	if len(ruleCounts) < limit {
		limit = len(ruleCounts)
	}
	for i := 0; i < limit; i++ {
		rc := ruleCounts[i]
		fmt.Fprintf(s.writer, "%d. [%s] %s: %d violations\n",
			i+1, rc.sev.Label(), rc.rule, rc.count)
	}
	fmt.Fprintln(s.writer)
}

func (s *SummaryOutput) buildRuleCounts(violations core.ViolationList) []ruleCount {
	byRule := violations.CountByRule()
	var ruleCounts []ruleCount

	for rule, count := range byRule {
		var sev core.Severity
		for _, v := range violations {
			if v.Rule == rule {
				sev = v.Severity
				break
			}
		}
		ruleCounts = append(ruleCounts, ruleCount{rule, count, sev})
	}

	sort.Slice(ruleCounts, func(i, j int) bool {
		if ruleCounts[i].sev != ruleCounts[j].sev {
			return ruleCounts[i].sev > ruleCounts[j].sev
		}
		return ruleCounts[i].count > ruleCounts[j].count
	})

	return ruleCounts
}
