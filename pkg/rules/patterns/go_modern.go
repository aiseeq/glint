package patterns

import (
	"go/ast"

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
			"Detects patterns that could use modern Go features (1.21+, 1.23+ iterators)",
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

	return violations
}

// checkForStmt checks for loop patterns that could be modernized
func (r *GoModernRule) checkForStmt(ctx *core.FileContext, stmt *ast.ForStmt) []*core.Violation {
	// ForStmt is a regular for loop, not a range loop
	// Range loops are handled separately as ast.RangeStmt
	// For now, we don't have specific patterns to check in regular for loops
	return nil
}
