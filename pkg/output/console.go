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
		return c.printSuccess(stats)
	}

	if err := c.printHeader(stats); err != nil {
		return err
	}
	if err := c.printViolations(violations); err != nil {
		return err
	}

	return c.printSummary(violations)
}

func (c *ConsoleOutput) printHeader(stats Stats) error {
	if err := writeLine(c.writer); err != nil {
		return err
	}
	if err := writeLine(c.writer, "GLINT ANALYSIS RESULTS"); err != nil {
		return err
	}
	if err := writeLine(c.writer, strings.Repeat("=", outputLineWidth)); err != nil {
		return err
	}
	if err := writeFormatted(c.writer, "Files analyzed: %d\n", stats.FilesAnalyzed); err != nil {
		return err
	}
	if stats.FilesSkipped > 0 {
		if err := writeFormatted(c.writer, "Files skipped: %d\n", stats.FilesSkipped); err != nil {
			return err
		}
	}
	return writeLine(c.writer)
}

func (c *ConsoleOutput) printSuccess(stats Stats) error {
	green := color.New(color.FgGreen, color.Bold)

	if err := writeLine(c.writer); err != nil {
		return err
	}
	if _, err := green.Fprintln(c.writer, "No issues found!"); err != nil {
		return err
	}
	if err := writeFormatted(c.writer, "Files analyzed: %d\n", stats.FilesAnalyzed); err != nil {
		return err
	}
	return writeLine(c.writer)
}

func (c *ConsoleOutput) printViolations(violations core.ViolationList) error {
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
		if _, err := cyan.Fprintf(c.writer, "%s\n", file); err != nil {
			return err
		}

		// Print violations
		for _, v := range fileViolations {
			if err := c.printViolation(v); err != nil {
				return err
			}
		}

		if err := writeLine(c.writer); err != nil {
			return err
		}
	}

	return nil
}

func (c *ConsoleOutput) printViolation(v *core.Violation) error {
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
	if _, err := gray.Fprintf(c.writer, "  %d: ", v.Line); err != nil {
		return err
	}

	// Severity
	if _, err := sevColor.Fprintf(c.writer, "[%s] ", v.Severity.Label()); err != nil {
		return err
	}

	// Message
	if err := writeFormatted(c.writer, "%s ", v.Message); err != nil {
		return err
	}

	// Rule name
	if _, err := gray.Fprintf(c.writer, "(%s)\n", v.Rule); err != nil {
		return err
	}

	// Code snippet if available
	if v.Code != "" {
		if _, err := gray.Fprintf(c.writer, "     > %s\n", strings.TrimSpace(v.Code)); err != nil {
			return err
		}
	}

	// Suggestion if available
	if v.Suggestion != "" {
		green := color.New(color.FgGreen)
		if _, err := green.Fprintf(c.writer, "     Suggestion: %s\n", v.Suggestion); err != nil {
			return err
		}
	}

	return nil
}

func (c *ConsoleOutput) printSummary(violations core.ViolationList) error {
	counts := violations.CountBySeverity()

	if err := writeLine(c.writer, strings.Repeat("-", outputLineWidth)); err != nil {
		return err
	}
	if err := writeFormatted(c.writer, "SUMMARY: %d issues found\n", len(violations)); err != nil {
		return err
	}

	// Print counts by severity
	if count, ok := counts[core.SeverityCritical]; ok && count > 0 {
		red := color.New(color.FgRed, color.Bold)
		if _, err := red.Fprintf(c.writer, "  Critical: %d\n", count); err != nil {
			return err
		}
	}
	if count, ok := counts[core.SeverityHigh]; ok && count > 0 {
		red := color.New(color.FgRed)
		if _, err := red.Fprintf(c.writer, "  High: %d\n", count); err != nil {
			return err
		}
	}
	if count, ok := counts[core.SeverityMedium]; ok && count > 0 {
		yellow := color.New(color.FgYellow)
		if _, err := yellow.Fprintf(c.writer, "  Medium: %d\n", count); err != nil {
			return err
		}
	}
	if count, ok := counts[core.SeverityLow]; ok && count > 0 {
		blue := color.New(color.FgBlue)
		if _, err := blue.Fprintf(c.writer, "  Low: %d\n", count); err != nil {
			return err
		}
	}

	return writeLine(c.writer)
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
	if err := s.printHeader(violations); err != nil {
		return err
	}

	if len(violations) > 0 {
		if err := s.printTopIssues(violations); err != nil {
			return err
		}
	}

	return writeFormatted(s.writer, "Files analyzed: %d | Duration: %.2fs\n", stats.FilesAnalyzed, stats.Duration)
}

func (s *SummaryOutput) printHeader(violations core.ViolationList) error {
	counts := violations.CountBySeverity()

	if err := writeLine(s.writer, "GLINT ANALYSIS SUMMARY"); err != nil {
		return err
	}
	if err := writeLine(s.writer, "======================"); err != nil {
		return err
	}
	if err := writeFormatted(s.writer, "Critical: %d | High: %d | Medium: %d | Low: %d\n",
		counts[core.SeverityCritical],
		counts[core.SeverityHigh],
		counts[core.SeverityMedium],
		counts[core.SeverityLow],
	); err != nil {
		return err
	}
	return writeLine(s.writer)
}

type ruleCount struct {
	rule  string
	count int
	sev   core.Severity
}

func (s *SummaryOutput) printTopIssues(violations core.ViolationList) error {
	ruleCounts := s.buildRuleCounts(violations)

	if err := writeLine(s.writer, "TOP ISSUES:"); err != nil {
		return err
	}
	limit := topIssuesLimit
	if len(ruleCounts) < limit {
		limit = len(ruleCounts)
	}
	for i := 0; i < limit; i++ {
		rc := ruleCounts[i]
		if err := writeFormatted(s.writer, "%d. [%s] %s: %d violations\n",
			i+1, rc.sev.Label(), rc.rule, rc.count); err != nil {
			return err
		}
	}
	return writeLine(s.writer)
}

func writeLine(w io.Writer, args ...any) error {
	_, err := fmt.Fprintln(w, args...)
	return err
}

func writeFormatted(w io.Writer, format string, args ...any) error {
	_, err := fmt.Fprintf(w, format, args...)
	return err
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
