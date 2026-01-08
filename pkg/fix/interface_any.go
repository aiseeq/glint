package fix

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// InterfaceAnyFixer fixes interface{} -> any
type InterfaceAnyFixer struct{}

// NewInterfaceAnyFixer creates the fixer
func NewInterfaceAnyFixer() *InterfaceAnyFixer {
	return &InterfaceAnyFixer{}
}

// RuleName returns the rule name
func (f *InterfaceAnyFixer) RuleName() string {
	return "interface-any"
}

// CanFix returns true if the violation can be fixed
func (f *InterfaceAnyFixer) CanFix(v *core.Violation) bool {
	if v == nil || v.Rule != "interface-any" {
		return false
	}
	// Check if it's not in an exception pattern (like JWT callback)
	if v.Context != nil {
		if exception, ok := v.Context["exception"]; ok && exception == true {
			return false
		}
	}
	return true
}

// GenerateFix generates the fix for a violation
func (f *InterfaceAnyFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) *Fix {
	if ctx == nil || v == nil {
		return nil
	}

	if v.Line < 1 || v.Line > len(ctx.Lines) {
		return nil
	}

	line := ctx.Lines[v.Line-1]

	// Find interface{} in the line
	if !strings.Contains(line, "interface{}") {
		return nil
	}

	return &Fix{
		File:      ctx.Path,
		StartLine: v.Line,
		EndLine:   v.Line,
		OldText:   "interface{}",
		NewText:   "any",
		Message:   "Replace interface{} with any (Go 1.18+)",
		RuleName:  "interface-any",
		Violation: v,
	}
}

func init() {
	// Register with default registry when package is imported
	DefaultRegistry.Register(NewInterfaceAnyFixer())
}
