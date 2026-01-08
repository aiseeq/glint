package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewGoModernRule())
}

// GoModernRule detects patterns that could use modern Go features
type GoModernRule struct {
	*rules.BaseRule
}

// NewGoModernRule creates the rule
func NewGoModernRule() *GoModernRule {
	return &GoModernRule{
		BaseRule: rules.NewBaseRule(
			"go-modern",
			"patterns",
			"Detects patterns that could use modern Go features (1.21+)",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks for outdated patterns
func (r *GoModernRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			violations = append(violations, r.checkCallExpr(ctx, node)...)

		case *ast.ForStmt:
			violations = append(violations, r.checkForStmt(ctx, node)...)

		case *ast.IfStmt:
			violations = append(violations, r.checkIfStmt(ctx, node)...)
		}

		return true
	})

	return violations
}

// checkCallExpr checks for function calls that have modern alternatives
func (r *GoModernRule) checkCallExpr(ctx *core.FileContext, call *ast.CallExpr) []*core.Violation {
	var violations []*core.Violation

	// Check for sort.Slice with manual less function that could use slices.SortFunc
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok {
			funcName := ident.Name + "." + sel.Sel.Name

			switch funcName {
			case "sort.Slice", "sort.SliceStable":
				// Suggest slices.SortFunc for Go 1.21+
				pos := ctx.PositionFor(call)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Consider using slices.SortFunc (Go 1.21+) instead of "+funcName)
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Use slices.SortFunc or slices.SortStableFunc from the slices package")
				v.WithContext("pattern", "sort-modernization")
				violations = append(violations, v)

			case "sort.Search":
				// Suggest slices.BinarySearch for Go 1.21+
				pos := ctx.PositionFor(call)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Consider using slices.BinarySearch (Go 1.21+) instead of sort.Search")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Use slices.BinarySearch or slices.BinarySearchFunc from the slices package")
				v.WithContext("pattern", "search-modernization")
				violations = append(violations, v)

			case "reflect.SliceHeader", "reflect.StringHeader":
				// These are deprecated in Go 1.20+
				pos := ctx.PositionFor(call)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					funcName+" is deprecated, use unsafe.Slice/unsafe.String instead")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Use unsafe.Slice and unsafe.String (Go 1.20+)")
				v.WithContext("pattern", "deprecated-reflect")
				violations = append(violations, v)
			}
		}
	}

	// Check for max/min patterns that could use built-in max/min (Go 1.21+)
	if ident, ok := call.Fun.(*ast.Ident); ok {
		if ident.Name == "math.Max" || ident.Name == "math.Min" {
			// This is actually a selector, handled above
		}
	}

	// Check for math.Max/math.Min
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "math" {
			if sel.Sel.Name == "Max" || sel.Sel.Name == "Min" {
				pos := ctx.PositionFor(call)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Consider using built-in "+strings.ToLower(sel.Sel.Name)+" (Go 1.21+) instead of math."+sel.Sel.Name)
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Use built-in max() or min() for integer types")
				v.WithContext("pattern", "builtin-minmax")
				violations = append(violations, v)
			}
		}
	}

	return violations
}

// checkForStmt checks for loop patterns that could be modernized
func (r *GoModernRule) checkForStmt(ctx *core.FileContext, stmt *ast.ForStmt) []*core.Violation {
	// ForStmt is a regular for loop, not a range loop
	// Range loops are handled separately as ast.RangeStmt
	// For now, we don't have specific patterns to check in regular for loops
	return nil
}

// checkIfStmt checks for if patterns that could be simplified
func (r *GoModernRule) checkIfStmt(ctx *core.FileContext, stmt *ast.IfStmt) []*core.Violation {
	var violations []*core.Violation

	// Check for "if err != nil { return ..., err }" without wrapping
	// This is handled by error-wrap rule, skip here

	// Check for manual nil checks that could use cmp.Or (Go 1.22+)
	// Pattern: if x == nil { x = defaultValue }
	if stmt.Else == nil && stmt.Init == nil {
		if bin, ok := stmt.Cond.(*ast.BinaryExpr); ok && bin.Op == token.EQL {
			if _, ok := bin.Y.(*ast.Ident); ok {
				// Could be a nil check, but need more context
				// Skip for now - too many false positives
			}
		}
	}

	return violations
}
