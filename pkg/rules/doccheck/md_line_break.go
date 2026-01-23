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

	var violations []*core.Violation
	lines := ctx.Lines

	// Track groups of consecutive bold-label lines
	groupStart := -1
	groupEnd := -1

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Check if line matches bold-label pattern
		if r.boldLabelPattern.MatchString(line) {
			if groupStart == -1 {
				groupStart = i
			}
			groupEnd = i
		} else {
			// End of potential group
			if groupEnd > groupStart && groupStart != -1 {
				// Found a group of 2+ consecutive bold-label lines
				// Check if any of them lack hard line break (trailing "  ")
				needsFix := false
				for j := groupStart; j < groupEnd; j++ { // Not including last line
					if !strings.HasSuffix(lines[j], "  ") {
						needsFix = true
						break
					}
				}

				if needsFix {
					v := r.CreateViolation(ctx.RelPath, groupStart+1,
						"Consecutive bold-label lines will render as single paragraph; add hard line breaks")
					v.WithCode(lines[groupStart])
					v.WithSuggestion("Add two trailing spaces '  ' to each line (except last) for hard line break, or use blank lines between them")
					v.WithContext("group_start", groupStart+1)
					v.WithContext("group_end", groupEnd+1)
					v.WithContext("lines_count", groupEnd-groupStart+1)
					violations = append(violations, v)
				}
			}
			groupStart = -1
			groupEnd = -1
		}
	}

	// Check for group at end of file
	if groupEnd > groupStart && groupStart != -1 {
		needsFix := false
		for j := groupStart; j < groupEnd; j++ {
			if !strings.HasSuffix(lines[j], "  ") {
				needsFix = true
				break
			}
		}

		if needsFix {
			v := r.CreateViolation(ctx.RelPath, groupStart+1,
				"Consecutive bold-label lines will render as single paragraph; add hard line breaks")
			v.WithCode(lines[groupStart])
			v.WithSuggestion("Add two trailing spaces '  ' to each line (except last) for hard line break, or use blank lines between them")
			v.WithContext("group_start", groupStart+1)
			v.WithContext("group_end", groupEnd+1)
			v.WithContext("lines_count", groupEnd-groupStart+1)
			violations = append(violations, v)
		}
	}

	return violations
}

// Fix implements the Fixer interface for auto-fix support
func (r *MdLineBreakRule) Fix(ctx *core.FileContext, violation *core.Violation) (*rules.Fix, error) {
	groupStart, ok := violation.Context["group_start"].(int)
	if !ok {
		return nil, nil
	}
	groupEnd, ok := violation.Context["group_end"].(int)
	if !ok {
		return nil, nil
	}

	// Convert to 0-based index
	groupStart--
	groupEnd--

	// Build the fixed content
	var fixedLines []string
	for i := groupStart; i <= groupEnd; i++ {
		line := ctx.Lines[i]
		// Add trailing spaces to all lines except the last one
		if i < groupEnd && !strings.HasSuffix(line, "  ") {
			line = line + "  "
		}
		fixedLines = append(fixedLines, line)
	}

	// Build old and new text
	oldLines := ctx.Lines[groupStart : groupEnd+1]
	oldText := strings.Join(oldLines, "\n")
	newText := strings.Join(fixedLines, "\n")

	return &rules.Fix{
		File:      ctx.Path,
		StartLine: groupStart + 1,
		EndLine:   groupEnd + 1,
		OldText:   oldText,
		NewText:   newText,
	}, nil
}
