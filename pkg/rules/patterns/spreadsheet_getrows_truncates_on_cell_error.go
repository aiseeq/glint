package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSpreadsheetGetRowsTruncatesOnCellErrorRule())
}

// SpreadsheetGetRowsTruncatesOnCellErrorRule detects a sheet read whose
// row-slice result is returned directly, without checking every cell or using
// an iterator that reports row-read errors.
type SpreadsheetGetRowsTruncatesOnCellErrorRule struct{ *rules.BaseRule }

// NewSpreadsheetGetRowsTruncatesOnCellErrorRule creates the rule.
func NewSpreadsheetGetRowsTruncatesOnCellErrorRule() *SpreadsheetGetRowsTruncatesOnCellErrorRule {
	return &SpreadsheetGetRowsTruncatesOnCellErrorRule{rules.NewBaseRule(
		"spreadsheet-getrows-truncates-on-cell-error",
		"patterns",
		"Detects a typed GetRows result returned as a complete sheet without validating cell reads",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op because the rule needs the method result types.
func (r *SpreadsheetGetRowsTruncatesOnCellErrorRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SpreadsheetGetRowsTruncatesOnCellErrorRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports excelize GetRows calls in functions without a
// cell-by-cell check or a checked row iterator.
func (r *SpreadsheetGetRowsTruncatesOnCellErrorRule) AnalyzeGoProject(project *core.GoProjectContext) ([]*core.Violation, error) {
	if project == nil {
		return nil, nil
	}
	return rules.AnalyzeGoFiles(project, r.Name(), func(ctx *core.FileContext, info *types.Info) []*core.Violation {
		if ctx.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		analyze := func(node ast.Node) {
			if functionChecksSheetReads(info, node) {
				return
			}
			ast.Inspect(node, func(child ast.Node) bool {
				if child != node {
					if _, ok := child.(*ast.FuncLit); ok {
						return false
					}
				}
				call, ok := child.(*ast.CallExpr)
				if !ok || !returnsSheetRows(info, call) {
					return true
				}
				line := ctx.PositionFor(call).Line
				if ctx.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(ctx.RelPath, line,
					"GetRows result is trusted as a complete sheet without checking individual cell reads")
				v.WithCode(ctx.GetLine(line))
				v.WithSuggestion("Check cell reads across the sheet dimensions, or read rows through an iterator and handle its row and column errors")
				violations = append(violations, v)
				return true
			})
		}
		ast.Inspect(ctx.GoAST, func(node ast.Node) bool {
			switch fn := node.(type) {
			case *ast.FuncDecl:
				if fn.Body != nil {
					analyze(fn.Body)
				}
			case *ast.FuncLit:
				analyze(fn.Body)
				return false
			}
			return true
		})
		return violations
	})
}

// functionChecksSheetReads reports a cell read or a Rows iterator whose
// column and terminal errors are checked in the same function.
func functionChecksSheetReads(info *types.Info, function ast.Node) bool {
	calls := make(map[string]bool)
	ast.Inspect(function, func(node ast.Node) bool {
		if node != function {
			if _, ok := node.(*ast.FuncLit); ok {
				return false
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, name := range []string{"GetCellValue", "Rows", "Error", "Columns"} {
			if isExcelizeMethod(info, call, name) {
				calls[name] = true
			}
		}
		return true
	})
	if calls["GetCellValue"] {
		return true
	}
	return calls["Rows"] && checkedExcelizeErrorCall(info, function, "Error") && checkedExcelizeErrorCall(info, function, "Columns")
}

// checkedExcelizeErrorCall reports an error-returning method used to initialize
// an error variable that is subsequently tested against nil in an if condition.
func checkedExcelizeErrorCall(info *types.Info, function ast.Node, methodName string) bool {
	checked := make(map[string]bool)
	var calls []*ast.CallExpr
	ast.Inspect(function, func(node ast.Node) bool {
		if node != function {
			if _, ok := node.(*ast.FuncLit); ok {
				return false
			}
		}
		switch node := node.(type) {
		case *ast.CallExpr:
			if isExcelizeMethod(info, node, methodName) {
				calls = append(calls, node)
			}
		case *ast.IfStmt:
			if node.Init != nil {
				if assign, ok := node.Init.(*ast.AssignStmt); ok && assignsExcelizeMethod(info, assign, methodName) {
					for _, lhs := range assign.Lhs {
						if ident, ok := lhs.(*ast.Ident); ok {
							checked[ident.Name] = true
						}
					}
					if conditionChecksError(node.Cond, checked) {
						return false
					}
				}
			}
		}
		return true
	})
	if len(calls) == 0 {
		return false
	}
	for _, call := range calls {
		parentAssign := errorResultAssignment(function, call)
		if parentAssign == "" {
			continue
		}
		found := false
		ast.Inspect(function, func(node ast.Node) bool {
			if ifStmt, ok := node.(*ast.IfStmt); ok && conditionChecksError(ifStmt.Cond, map[string]bool{parentAssign: true}) {
				found = true
				return false
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

func assignsExcelizeMethod(info *types.Info, assign *ast.AssignStmt, methodName string) bool {
	for _, rhs := range assign.Rhs {
		call, ok := ast.Unparen(rhs).(*ast.CallExpr)
		if ok && isExcelizeMethod(info, call, methodName) {
			return true
		}
	}
	return false
}

func errorResultAssignment(function ast.Node, target *ast.CallExpr) string {
	name := ""
	ast.Inspect(function, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, rhs := range assign.Rhs {
			if rhs == target && len(assign.Lhs) >= 2 {
				if ident, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident); ok {
					name = ident.Name
					return false
				}
			}
		}
		return true
	})
	return name
}

func conditionChecksError(condition ast.Expr, names map[string]bool) bool {
	bin, ok := ast.Unparen(condition).(*ast.BinaryExpr)
	if !ok || (bin.Op != token.NEQ && bin.Op != token.EQL) {
		return false
	}
	left, leftOK := ast.Unparen(bin.X).(*ast.Ident)
	rightNil := isNilExpr(bin.Y)
	right, rightOK := ast.Unparen(bin.Y).(*ast.Ident)
	leftNil := isNilExpr(bin.X)
	return (leftOK && names[left.Name] && rightNil) || (rightOK && names[right.Name] && leftNil)
}

func isNilExpr(expr ast.Expr) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && ident.Name == "nil"
}

func isExcelizeMethod(info *types.Info, call *ast.CallExpr, methodName string) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != methodName {
		return false
	}
	selection := info.Selections[selector]
	if selection == nil {
		return false
	}
	method, ok := selection.Obj().(*types.Func)
	return ok && method.Pkg() != nil && strings.HasPrefix(method.Pkg().Path(), "github.com/xuri/excelize")
}

// returnsSheetRows restricts the finding to excelize methods with the
// GetRows result shape that truncates silently on a cell-read error.
func returnsSheetRows(info *types.Info, call *ast.CallExpr) bool {
	if !isExcelizeMethod(info, call, "GetRows") {
		return false
	}
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	selection := info.Selections[selector]
	if selection == nil {
		return false
	}
	method, ok := selection.Obj().(*types.Func)
	if !ok {
		return false
	}
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Results().Len() != 2 {
		return false
	}
	rows, ok := types.Unalias(sig.Results().At(0).Type()).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	row, ok := types.Unalias(rows.Elem()).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	cell, ok := types.Unalias(row.Elem()).Underlying().(*types.Basic)
	if !ok || cell.Kind() != types.String {
		return false
	}
	return isErrorType(sig.Results().At(1).Type())
}
