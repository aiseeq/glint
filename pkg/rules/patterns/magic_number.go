package patterns

import (
	"go/ast"
	"go/token"
	"strconv"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMagicNumberRule())
}

// MagicNumberRule detects hardcoded numbers that should be named constants
type MagicNumberRule struct {
	*rules.BaseRule
	minValue int // Minimum value to flag (0, 1, -1 are usually OK)
}

// NewMagicNumberRule creates the rule
func NewMagicNumberRule() *MagicNumberRule {
	return &MagicNumberRule{
		BaseRule: rules.NewBaseRule(
			"magic-number",
			"patterns",
			"Detects hardcoded numbers that should be named constants",
			core.SeverityLow,
		),
		minValue: 2, // Default: flag numbers >= 2
	}
}

// Configure allows setting rule options
func (r *MagicNumberRule) Configure(settings map[string]any) error {
	if v, ok := settings["min_value"]; ok {
		if minVal, ok := v.(int); ok {
			r.minValue = minVal
		}
	}
	return nil
}

// AnalyzeFile checks for magic numbers
func (r *MagicNumberRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}

	// Skip test files - magic numbers in tests are often acceptable
	if ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok {
			return true
		}

		// Only check integer literals
		if lit.Kind != token.INT {
			return true
		}

		// Parse the value
		value, err := strconv.ParseInt(lit.Value, 0, 64)
		if err != nil {
			return true
		}

		// Skip small values (0, 1, -1 are usually OK)
		if value >= 0 && value < int64(r.minValue) {
			return true
		}

		// Skip if this is part of a const declaration
		if r.isInConstDecl(ctx.GoAST, lit) {
			return true
		}

		// Skip common acceptable values
		if r.isAcceptableValue(value) {
			return true
		}

		// Skip if in array/slice index or capacity
		if r.isArrayContext(ctx.GoAST, lit) {
			return true
		}

		pos := ctx.PositionFor(lit)
		v := r.CreateViolation(ctx.RelPath, pos.Line, "Consider using a named constant instead of magic number")
		v.WithCode(lit.Value)
		v.WithSuggestion("Define a const with a descriptive name")
		violations = append(violations, v)

		return true
	})

	return violations
}

func (r *MagicNumberRule) isInConstDecl(file *ast.File, lit *ast.BasicLit) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		genDecl, ok := n.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			return true
		}

		// Check if the literal is within this const declaration
		if lit.Pos() >= genDecl.Pos() && lit.End() <= genDecl.End() {
			found = true
			return false
		}
		return true
	})
	return found
}

func (r *MagicNumberRule) isAcceptableValue(value int64) bool {
	// Common acceptable magic numbers
	acceptable := map[int64]bool{
		2:    true, // Common for doubling
		10:   true, // Decimal base
		16:   true, // Hex base
		32:   true, // Common size
		64:   true, // Common size
		100:  true, // Percentage
		1000: true, // Common multiplier
		1024: true, // KB/KiB
		8:    true, // Bits in byte
	}
	return acceptable[value]
}

func (r *MagicNumberRule) isArrayContext(file *ast.File, lit *ast.BasicLit) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ArrayType:
			if node.Len == lit {
				found = true
				return false
			}
		case *ast.IndexExpr:
			if node.Index == lit {
				found = true
				return false
			}
		case *ast.SliceExpr:
			if node.Low == lit || node.High == lit || node.Max == lit {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
