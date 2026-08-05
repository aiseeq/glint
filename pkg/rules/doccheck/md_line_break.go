package doccheck

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMdLineBreakRule())
}

// MdLineBreakRule detects consecutive bold-label lines that need hard line breaks
type MdLineBreakRule struct {
	*rules.BaseRule
	// Pattern for lines like **Label:** value
	boldLabelPattern *regexp.Regexp
}

// NewMdLineBreakRule creates the rule
func NewMdLineBreakRule() *MdLineBreakRule {
	return &MdLineBreakRule{
		BaseRule: rules.NewBaseRule(
			"md-line-break",
			"documentation",
			"Detects consecutive bold-label lines in Markdown that will render as single line",
			core.SeverityLow,
		),
		// Match lines starting with **Label:** or **Label**: (colon inside or after bold)
		// Example: **Версия:** 1.0.0 or **ID**: VUL-002
		boldLabelPattern: regexp.MustCompile(`^\s*\*\*[^*]+:\*\*|^\s*\*\*[^*]+\*\*\s*:`),
	}
}

// AnalyzeFile checks for consecutive bold-label lines in Markdown
func (r *MdLineBreakRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	// Only process Markdown files
	if !strings.HasSuffix(ctx.Path, ".md") {
		return nil
	}
	if strings.HasPrefix(ctx.RelPath, "docs/") || strings.HasPrefix(ctx.RelPath, ".claude/") {
		return nil
	}

	var violations []*core.Violation
	lines := ctx.Lines

	// Track groups of consecutive bold-label lines
	groupStart := -1
	groupEnd := -1
	inFence := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Lines inside fenced code blocks are literal examples, not prose
		if isFenceDelimiter(line) {
			inFence = !inFence
		}

		// Check if line matches bold-label pattern
		if !inFence && r.boldLabelPattern.MatchString(line) {
			if groupStart == -1 {
				groupStart = i
			}
			groupEnd = i
		} else {
			// End of potential group
			if v := r.reportGroup(ctx, groupStart, groupEnd); v != nil {
				violations = append(violations, v)
			}
			groupStart = -1
			groupEnd = -1
		}
	}

	// Check for group at end of file
	if v := r.reportGroup(ctx, groupStart, groupEnd); v != nil {
		violations = append(violations, v)
	}

	return violations
}

// reportGroup builds a violation for a group of 2+ consecutive bold-label lines
// when at least one of them (except the last) lacks a hard line break, the
// trailing "  ". Returns nil when there is no group or nothing to fix.
func (r *MdLineBreakRule) reportGroup(ctx *core.FileContext, groupStart, groupEnd int) *core.Violation {
	if groupStart == -1 || groupEnd <= groupStart {
		return nil
	}

	needsFix := false
	for j := groupStart; j < groupEnd; j++ { // Not including last line
		if !strings.HasSuffix(ctx.Lines[j], "  ") {
			needsFix = true
			break
		}
	}
	if !needsFix {
		return nil
	}

	v := r.CreateViolation(ctx.RelPath, groupStart+1,
		"Consecutive bold-label lines will render as single paragraph; add hard line breaks")
	v.WithCode(ctx.Lines[groupStart])
	v.WithSuggestion("Add two trailing spaces '  ' to each line (except last) for hard line break, or use blank lines between them")
	v.WithContext("group_start", groupStart+1)
	v.WithContext("group_end", groupEnd+1)
	v.WithContext("lines_count", groupEnd-groupStart+1)
	return v
}
