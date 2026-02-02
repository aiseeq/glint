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
	boldLabelPattern *regexp.Regexp
	// Pattern for any text ending with colon (plain text label)
	plainLabelPattern *regexp.Regexp
	// Pattern for list item
	listPattern *regexp.Regexp
	// Pattern for lines to skip (code blocks, frontmatter, headers, etc.)
	skipPattern *regexp.Regexp
}

// NewMdListAfterLabelRule creates the rule
func NewMdListAfterLabelRule() *MdListAfterLabelRule {
	return &MdListAfterLabelRule{
		BaseRule: rules.NewBaseRule(
			"md-list-after-label",
			"documentation",
			"Detects labels followed by lists without blank line (causes rendering issues)",
			core.SeverityLow,
		),
		// Match bold label patterns on their own line:
		// 1. **Label:** - colon inside bold
		// 2. **Label**: - colon after bold
		// 3. **Bold text** extra content: - bold at start, ends with colon
		// 4. **Bold text** - just bold text on its own line (no colon)
		boldLabelPattern: regexp.MustCompile(`^\*\*[^*]+:\*\*\s*$|^\*\*[^*]+\*\*\s*:\s*$|^\*\*[^*]+\*\*.*:\s*$|^\*\*[^*]+\*\*\s*$`),
		// Match plain text ending with colon (e.g., "Some text describing a list:")
		// Must have at least 10 chars to avoid false positives on short labels
		plainLabelPattern: regexp.MustCompile(`^.{10,}:\s*$`),
		// Match list items (- or * or numbered)
		listPattern: regexp.MustCompile(`^\s*[-*]\s+|^\s*\d+\.\s+`),
		// Skip patterns: code blocks, frontmatter, headers, table rows, blockquotes
		skipPattern: regexp.MustCompile("^```|^---|^#|^\\||^>"),
	}
}

// AnalyzeFile checks for labels followed by lists without blank line
func (r *MdListAfterLabelRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !strings.HasSuffix(ctx.Path, ".md") {
		return nil
	}

	var violations []*core.Violation
	lines := ctx.Lines
	inCodeBlock := false

	for i := 0; i < len(lines)-1; i++ {
		line := strings.TrimSpace(lines[i])
		nextLine := strings.TrimSpace(lines[i+1])

		// Track code blocks
		if strings.HasPrefix(line, "```") {
			inCodeBlock = !inCodeBlock
			continue
		}
		if inCodeBlock {
			continue
		}

		// Skip certain line types
		if r.skipPattern.MatchString(line) {
			continue
		}

		// Check if current line is a label (bold or plain text ending with colon)
		isLabel := r.boldLabelPattern.MatchString(line) || r.plainLabelPattern.MatchString(line)

		if isLabel {
			// Check if next line is a list item (without blank line between)
			if r.listPattern.MatchString(nextLine) {
				v := r.CreateViolation(ctx.RelPath, i+1,
					"Label followed by list without blank line; may render incorrectly")
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
