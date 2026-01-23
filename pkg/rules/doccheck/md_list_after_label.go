package doccheck

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMdListAfterLabelRule())
}

// MdListAfterLabelRule detects bold labels followed by lists without blank line
type MdListAfterLabelRule struct {
	*rules.BaseRule
	// Pattern for bold label on its own line
	labelPattern *regexp.Regexp
	// Pattern for list item
	listPattern *regexp.Regexp
}

// NewMdListAfterLabelRule creates the rule
func NewMdListAfterLabelRule() *MdListAfterLabelRule {
	return &MdListAfterLabelRule{
		BaseRule: rules.NewBaseRule(
			"md-list-after-label",
			"documentation",
			"Detects bold labels followed by lists without blank line (causes rendering issues)",
			core.SeverityLow,
		),
		// Match label patterns on their own line:
		// 1. **Label:** - colon inside bold
		// 2. **Label**: - colon after bold
		// 3. **Bold text** extra content: - bold at start, ends with colon (allows colons in middle)
		// 4. **Bold text** - just bold text on its own line (no colon)
		labelPattern: regexp.MustCompile(`^\*\*[^*]+:\*\*\s*$|^\*\*[^*]+\*\*\s*:\s*$|^\*\*[^*]+\*\*.*:\s*$|^\*\*[^*]+\*\*\s*$`),
		// Match list items (- or * or numbered)
		listPattern: regexp.MustCompile(`^\s*[-*]\s+|^\s*\d+\.\s+`),
	}
}

// AnalyzeFile checks for labels followed by lists without blank line
func (r *MdListAfterLabelRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !strings.HasSuffix(ctx.Path, ".md") {
		return nil
	}

	var violations []*core.Violation
	lines := ctx.Lines

	for i := 0; i < len(lines)-1; i++ {
		line := strings.TrimSpace(lines[i])
		nextLine := strings.TrimSpace(lines[i+1])

		// Check if current line is a bold label
		if r.labelPattern.MatchString(line) {
			// Check if next line is a list item (without blank line between)
			if r.listPattern.MatchString(nextLine) {
				v := r.CreateViolation(ctx.RelPath, i+1,
					"Bold label followed by list without blank line; may render incorrectly")
				v.WithCode(lines[i])
				v.WithSuggestion("Add a blank line between the label and the list")
				v.WithContext("label_line", i+1)
				v.WithContext("list_line", i+2)
				violations = append(violations, v)
			}
		}
	}

	return violations
}
