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

// ReportWriter accumulates the first write error so that report code reads as
// a sequence of writes rather than a chain of identical error checks. Once a
// write fails every later one is a no-op, and Err returns the failure.
// ("Errors are values" — https://go.dev/blog/errors-are-values)
type ReportWriter struct {
	w   io.Writer
	err error
}

func NewReportWriter(w io.Writer) *ReportWriter {
	return &ReportWriter{w: w}
}

// line writes its arguments followed by a newline.
func (rw *ReportWriter) Line(args ...any) {
	if rw.err != nil {
		return
	}
	_, rw.err = fmt.Fprintln(rw.w, args...)
}

// printf writes formatted text.
func (rw *ReportWriter) Printf(format string, args ...any) {
	if rw.err != nil {
		return
	}
	_, rw.err = fmt.Fprintf(rw.w, format, args...)
}

// colored writes formatted text in the given color.
func (rw *ReportWriter) colored(c *color.Color, format string, args ...any) {
	if rw.err != nil {
		return
	}
	if c == nil {
		rw.Printf(format, args...)
		return
	}
	_, rw.err = c.Fprintf(rw.w, format, args...)
}

// Err returns the first write error, if any.
func (rw *ReportWriter) Err() error {
	return rw.err
}

// ConsoleOutput writes violations to console with colors
type ConsoleOutput struct {
	writer io.Writer
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

// WithNoColor disables colors
func (c *ConsoleOutput) WithNoColor(v bool) *ConsoleOutput {
	if v {
		color.NoColor = true
	}
	return c
}

// Write outputs violations to console
func (c *ConsoleOutput) Write(violations core.ViolationList, stats Stats) error {
	out := NewReportWriter(c.writer)

	if len(violations) == 0 {
		c.printSuccess(out, stats)
		return out.Err()
	}

	c.printHeader(out, stats)
	c.printViolations(out, violations)
	c.printSummary(out, violations)

	return out.Err()
}

func (c *ConsoleOutput) printHeader(out *ReportWriter, stats Stats) {
	out.Line()
	out.Line("GLINT ANALYSIS RESULTS")
	out.Line(strings.Repeat("=", outputLineWidth))
	out.Printf("Files analyzed: %d\n", stats.FilesAnalyzed)
	if stats.FilesSkipped > 0 {
		out.Printf("Files skipped: %d\n", stats.FilesSkipped)
	}
	out.Line()
}

func (c *ConsoleOutput) printSuccess(out *ReportWriter, stats Stats) {
	out.Line()
	out.colored(color.New(color.FgGreen, color.Bold), "No issues found!\n")
	out.Printf("Files analyzed: %d\n", stats.FilesAnalyzed)
	out.Line()
}

func (c *ConsoleOutput) printViolations(out *ReportWriter, violations core.ViolationList) {
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

	cyan := color.New(color.FgCyan, color.Bold)
	for _, file := range files {
		fileViolations := byFile[file]

		// Sort violations by line, then by rule so that equal lines keep a
		// stable order.
		sort.SliceStable(fileViolations, func(i, j int) bool {
			if fileViolations[i].Line != fileViolations[j].Line {
				return fileViolations[i].Line < fileViolations[j].Line
			}
			return fileViolations[i].Rule < fileViolations[j].Rule
		})

		out.colored(cyan, "%s\n", file)
		for _, v := range fileViolations {
			c.printViolation(out, v)
		}
		out.Line()
	}
}

func (c *ConsoleOutput) printViolation(out *ReportWriter, v *core.Violation) {
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

	gray := color.New(color.FgHiBlack)
	out.colored(gray, "  %d: ", v.Line)
	out.colored(sevColor, "[%s] ", v.Severity.Label())
	out.Printf("%s ", v.Message)
	out.colored(gray, "(%s)\n", v.Rule)

	if v.Code != "" {
		out.colored(gray, "     > %s\n", strings.TrimSpace(v.Code))
	}
	if v.Suggestion != "" {
		out.colored(color.New(color.FgGreen), "     Suggestion: %s\n", v.Suggestion)
	}
}

func (c *ConsoleOutput) printSummary(out *ReportWriter, violations core.ViolationList) {
	counts := violations.CountBySeverity()

	out.Line(strings.Repeat("-", outputLineWidth))
	out.Printf("SUMMARY: %d issues found\n", len(violations))

	for _, level := range []struct {
		severity core.Severity
		label    string
		color    *color.Color
	}{
		{core.SeverityCritical, "Critical", color.New(color.FgRed, color.Bold)},
		{core.SeverityHigh, "High", color.New(color.FgRed)},
		{core.SeverityMedium, "Medium", color.New(color.FgYellow)},
		{core.SeverityLow, "Low", color.New(color.FgBlue)},
	} {
		if count := counts[level.severity]; count > 0 {
			out.colored(level.color, "  %s: %d\n", level.label, count)
		}
	}

	out.Line()
}

// Stats contains analysis statistics
type Stats struct {
	FilesAnalyzed int
	FilesSkipped  int
	// PackagesSkipped counts packages left out of typed analysis because they
	// do not type-check; non-zero only under --tolerate-broken-packages.
	PackagesSkipped int
	RulesRun        int
	Duration        float64
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
	out := NewReportWriter(s.writer)

	s.printHeader(out, violations)
	if len(violations) > 0 {
		s.printTopIssues(out, violations)
	}
	out.Printf("Files analyzed: %d | Duration: %.2fs\n", stats.FilesAnalyzed, stats.Duration)

	return out.Err()
}

func (s *SummaryOutput) printHeader(out *ReportWriter, violations core.ViolationList) {
	counts := violations.CountBySeverity()

	out.Line("GLINT ANALYSIS SUMMARY")
	out.Line("======================")
	out.Printf("Critical: %d | High: %d | Medium: %d | Low: %d\n",
		counts[core.SeverityCritical],
		counts[core.SeverityHigh],
		counts[core.SeverityMedium],
		counts[core.SeverityLow],
	)
	out.Line()
}

type ruleCount struct {
	rule  string
	count int
	sev   core.Severity
}

func (s *SummaryOutput) printTopIssues(out *ReportWriter, violations core.ViolationList) {
	ruleCounts := s.buildRuleCounts(violations)

	out.Line("TOP ISSUES:")
	limit := topIssuesLimit
	if len(ruleCounts) < limit {
		limit = len(ruleCounts)
	}
	for i := 0; i < limit; i++ {
		rc := ruleCounts[i]
		out.Printf("%d. [%s] %s: %d violations\n", i+1, rc.sev.Label(), rc.rule, rc.count)
	}
	out.Line()
}

func (s *SummaryOutput) buildRuleCounts(violations core.ViolationList) []ruleCount {
	byRule := violations.CountByRule()
	ruleCounts := make([]ruleCount, 0, len(byRule))

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

	// The rule name breaks ties: without it, equally severe and equally
	// frequent rules would swap places between runs (map iteration order).
	sort.Slice(ruleCounts, func(i, j int) bool {
		if ruleCounts[i].sev != ruleCounts[j].sev {
			return ruleCounts[i].sev > ruleCounts[j].sev
		}
		if ruleCounts[i].count != ruleCounts[j].count {
			return ruleCounts[i].count > ruleCounts[j].count
		}
		return ruleCounts[i].rule < ruleCounts[j].rule
	})

	return ruleCounts
}
