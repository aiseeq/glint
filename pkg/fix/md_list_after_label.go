package fix

import (
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
func (f *MdListAfterLabelFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) *Fix {
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

	idx := labelLine - 1
	if idx < 0 || idx >= len(ctx.Lines) {
		return nil
	}

	oldLine := ctx.Lines[idx]
	newText := oldLine + "\n"

	return &Fix{
		File:      ctx.Path,
		StartLine: labelLine,
		EndLine:   labelLine,
		OldText:   oldLine,
		NewText:   newText,
		Message:   "Add blank line between label and list",
		RuleName:  "md-list-after-label",
	}
}

func init() {
	DefaultRegistry.Register(NewMdListAfterLabelFixer())
}
