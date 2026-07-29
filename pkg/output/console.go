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

// reportWriter accumulates the first write error so that report code reads as
// a sequence of writes rather than a chain of identical error checks. Once a
// write fails every later one is a no-op, and Err returns the failure.
// ("Errors are values" — https://go.dev/blog/errors-are-values)
type reportWriter struct {
	w   io.Writer
	err error
}

func newReportWriter(w io.Writer) *reportWriter {
	return &reportWriter{w: w}
}

// line writes its arguments followed by a newline.
func (rw *reportWriter) line(args ...any) {
	if rw.err != nil {
		return
	}
	_, rw.err = fmt.Fprintln(rw.w, args...)
}

// printf writes formatted text.
func (rw *reportWriter) printf(format string, args ...any) {
	if rw.err != nil {
		return
	}
	_, rw.err = fmt.Fprintf(rw.w, format, args...)
}

// colored writes formatted text in the given color.
func (rw *reportWriter) colored(c *color.Color, format string, args ...any) {
	if rw.err != nil {
		return
	}
	if c == nil {
		rw.printf(format, args...)
		return
	}
	_, rw.err = c.Fprintf(rw.w, format, args...)
}

// Err returns the first write error, if any.
func (rw *reportWriter) Err() error {
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
	out := newReportWriter(c.writer)

	if len(violations) == 0 {
		c.printSuccess(out, stats)
		return out.Err()
	}

	c.printHeader(out, stats)
	c.printViolations(out, violations)
	c.printSummary(out, violations)

	return out.Err()
}

func (c *ConsoleOutput) printHeader(out *reportWriter, stats Stats) {
	out.line()
	out.line("GLINT ANALYSIS RESULTS")
	out.line(strings.Repeat("=", outputLineWidth))
	out.printf("Files analyzed: %d\n", stats.FilesAnalyzed)
	if stats.FilesSkipped > 0 {
		out.printf("Files skipped: %d\n", stats.FilesSkipped)
	}
	out.line()
}

func (c *ConsoleOutput) printSuccess(out *reportWriter, stats Stats) {
	out.line()
	out.colored(color.New(color.FgGreen, color.Bold), "No issues found!\n")
	out.printf("Files analyzed: %d\n", stats.FilesAnalyzed)
	out.line()
}

func (c *ConsoleOutput) printViolations(out *reportWriter, violations core.ViolationList) {
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
		out.line()
	}
}

func (c *ConsoleOutput) printViolation(out *reportWriter, v *core.Violation) {
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
	out.printf("%s ", v.Message)
	out.colored(gray, "(%s)\n", v.Rule)

	if v.Code != "" {
		out.colored(gray, "     > %s\n", strings.TrimSpace(v.Code))
	}
	if v.Suggestion != "" {
		out.colored(color.New(color.FgGreen), "     Suggestion: %s\n", v.Suggestion)
	}
}

func (c *ConsoleOutput) printSummary(out *reportWriter, violations core.ViolationList) {
	counts := violations.CountBySeverity()

	out.line(strings.Repeat("-", outputLineWidth))
	out.printf("SUMMARY: %d issues found\n", len(violations))

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

	out.line()
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
	out := newReportWriter(s.writer)

	s.printHeader(out, violations)
	if len(violations) > 0 {
		s.printTopIssues(out, violations)
	}
	out.printf("Files analyzed: %d | Duration: %.2fs\n", stats.FilesAnalyzed, stats.Duration)

	return out.Err()
}

func (s *SummaryOutput) printHeader(out *reportWriter, violations core.ViolationList) {
	counts := violations.CountBySeverity()

	out.line("GLINT ANALYSIS SUMMARY")
	out.line("======================")
	out.printf("Critical: %d | High: %d | Medium: %d | Low: %d\n",
		counts[core.SeverityCritical],
		counts[core.SeverityHigh],
		counts[core.SeverityMedium],
		counts[core.SeverityLow],
	)
	out.line()
}

type ruleCount struct {
	rule  string
	count int
	sev   core.Severity
}

func (s *SummaryOutput) printTopIssues(out *reportWriter, violations core.ViolationList) {
	ruleCounts := s.buildRuleCounts(violations)

	out.line("TOP ISSUES:")
	limit := topIssuesLimit
	if len(ruleCounts) < limit {
		limit = len(ruleCounts)
	}
	for i := 0; i < limit; i++ {
		rc := ruleCounts[i]
		out.printf("%d. [%s] %s: %d violations\n", i+1, rc.sev.Label(), rc.rule, rc.count)
	}
	out.line()
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
