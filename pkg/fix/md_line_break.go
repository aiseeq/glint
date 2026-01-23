package fix

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// MdLineBreakFixer fixes consecutive bold-label lines in Markdown
type MdLineBreakFixer struct{}

// NewMdLineBreakFixer creates the fixer
func NewMdLineBreakFixer() *MdLineBreakFixer {
	return &MdLineBreakFixer{}
}

// RuleName returns the rule name
func (f *MdLineBreakFixer) RuleName() string {
	return "md-line-break"
}

// CanFix returns true if the violation can be fixed
func (f *MdLineBreakFixer) CanFix(v *core.Violation) bool {
	if v == nil || v.Rule != "md-line-break" {
		return false
	}
	// Check if we have the required context from the rule
	_, hasStart := v.Context["group_start"]
	_, hasEnd := v.Context["group_end"]
	return hasStart && hasEnd
}

// GenerateFix generates the fix for a violation
func (f *MdLineBreakFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) *Fix {
	if ctx == nil || v == nil {
		return nil
	}

	// Get group boundaries from violation context
	groupStartRaw, ok := v.Context["group_start"]
	if !ok {
		return nil
	}
	groupEndRaw, ok := v.Context["group_end"]
	if !ok {
		return nil
	}

	// Type assertion - context values might be int or float64 (from JSON)
	var groupStart, groupEnd int
	switch gs := groupStartRaw.(type) {
	case int:
		groupStart = gs
	case float64:
		groupStart = int(gs)
	default:
		return nil
	}
	switch ge := groupEndRaw.(type) {
	case int:
		groupEnd = ge
	case float64:
		groupEnd = int(ge)
	default:
		return nil
	}

	// Convert to 0-based index
	groupStart--
	groupEnd--

	if groupStart < 0 || groupEnd >= len(ctx.Lines) || groupStart > groupEnd {
		return nil
	}

	// Build old and new text
	var oldLines, newLines []string
	for i := groupStart; i <= groupEnd; i++ {
		line := ctx.Lines[i]
		oldLines = append(oldLines, line)

		// Add trailing spaces to all lines except the last one
		if i < groupEnd && !strings.HasSuffix(line, "  ") {
			line = line + "  "
		}
		newLines = append(newLines, line)
	}

	oldText := strings.Join(oldLines, "\n")
	newText := strings.Join(newLines, "\n")

	// If no change needed, skip
	if oldText == newText {
		return nil
	}

	return &Fix{
		File:      ctx.Path,
		StartLine: groupStart + 1,
		EndLine:   groupEnd + 1,
		OldText:   oldText,
		NewText:   newText,
		Message:   "Add hard line breaks to consecutive bold-label lines",
		RuleName:  "md-line-break",
	}
}

func init() {
	DefaultRegistry.Register(NewMdLineBreakFixer())
}
