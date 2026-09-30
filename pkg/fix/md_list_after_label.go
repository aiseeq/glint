package fix

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// MdListAfterLabelFixer fixes labels followed by lists without blank line
type MdListAfterLabelFixer struct{}

// NewMdListAfterLabelFixer creates the fixer
func NewMdListAfterLabelFixer() *MdListAfterLabelFixer {
	return &MdListAfterLabelFixer{}
}

// RuleName returns the rule name
func (f *MdListAfterLabelFixer) RuleName() string {
	return "md-list-after-label"
}

// CanFix returns true if the violation can be fixed
func (f *MdListAfterLabelFixer) CanFix(v *core.Violation) bool {
	if v == nil || v.Rule != "md-list-after-label" {
		return false
	}
	_, hasLabel := v.Context["label_line"]
	return hasLabel
}

// GenerateFix generates the fix for a violation
func (f *MdListAfterLabelFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) []*Fix {
	if ctx == nil || v == nil {
		return nil
	}

	labelLineRaw, ok := v.Context["label_line"]
	if !ok {
		return nil
	}

	var labelLine int
	switch ll := labelLineRaw.(type) {
	case int:
		labelLine = ll
	case float64:
		labelLine = int(ll)
	default:
		return nil
	}

	// The blank line is inserted at the start of the line after the label,
	// so the edit does not touch the label line another fix may change. It
	// ends the way the label line does, LF or CRLF.
	idx := labelLine - 1
	if idx < 0 || idx+1 >= len(ctx.Lines) {
		return nil
	}
	blank := "\n"
	if strings.HasSuffix(ctx.Lines[idx], "\r") {
		blank = "\r\n"
	}

	return []*Fix{&Fix{
		File:      ctx.Path,
		StartLine: labelLine + 1,
		EndLine:   labelLine + 1,
		StartCol:  1,
		EndCol:    1,
		OldText:   "",
		NewText:   blank,
		Message:   "Add blank line between label and list",
		RuleName:  "md-list-after-label",
	}}
}

func init() {
	DefaultRegistry.Register(NewMdListAfterLabelFixer())
}
