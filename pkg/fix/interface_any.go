package fix

import (
	"go/ast"
	"strings"
	"unicode"

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

// CanFix reports whether the violation pins the interface{} it is about. The
// rule reports only where 'any' compiles - a Go 1.18+ module whose package
// does not declare its own any - so a violation is itself the permission.
func (f *InterfaceAnyFixer) CanFix(v *core.Violation) bool {
	if v == nil || v.Rule != "interface-any" || v.Column < 1 {
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

// GenerateFix replaces the empty interface type the violation points to.
func (f *InterfaceAnyFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) []*Fix {
	if ctx == nil || ctx.GoAST == nil || !f.CanFix(v) {
		return nil
	}

	var target *ast.InterfaceType
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if target != nil {
			return false
		}
		iface, ok := n.(*ast.InterfaceType)
		if ok && violationPosition(ctx, v, iface) {
			target = iface
			return false
		}
		return true
	})
	if target == nil || (target.Methods != nil && len(target.Methods.List) > 0) {
		return nil
	}

	fix, ok := nodeFix(ctx, target.Pos(), target.End(), "any")
	if !ok || stripSpace(fix.OldText) != "interface{}" {
		return nil // a comment inside the braces would be lost
	}
	fix.Message = "Replace interface{} with any (Go 1.18+)"
	fix.RuleName = "interface-any"
	fix.Violation = v
	return []*Fix{fix}
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

func init() {
	// Register with default registry when package is imported
	DefaultRegistry.Register(NewInterfaceAnyFixer())
}
