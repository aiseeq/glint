package moneyrules

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewNegativeMoneyClampedToZeroRule())
}

// NewNegativeMoneyClampedToZeroRule detects a negative decimal replaced with
// zero in a function that cannot return an error.
func NewNegativeMoneyClampedToZeroRule() *patternkit.TypedFuncRule {
	return patternkit.NewFuncRule(
		"negative-money-clamped-to-zero",
		"Detects a negative decimal replaced with zero in a function without an error result — the caller receives a plausible amount instead of the integrity failure",
		core.SeverityHigh,
		"Return an error for the negative amount, or preserve the amount and report the inconsistency to the caller",
		negativeMoneyClampedToZero,
	)
}

func negativeMoneyClampedToZero(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
	info := scope.Info
	if patternkit.ReturnsErrorResult(info, fn) {
		return nil
	}
	var found []patternkit.FuncFinding
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		branch, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		amount := negativeDecimalCompared(info, branch.Cond)
		if amount == nil || !branchClampsDecimalToZero(info, fn.Body, branch.Body, amount) {
			return true
		}
		found = append(found, patternkit.FuncFinding{Node: branch, Message: "A negative decimal amount is replaced with zero in a function without an error result — the caller receives a plausible amount"})
		return true
	})
	return found
}

func negativeDecimalCompared(info *types.Info, cond ast.Expr) types.Object {
	var amount types.Object
	ast.Inspect(cond, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "LessThan" || !isShopspringDecimalType(info.TypeOf(selector.X)) || !patternkit.IsDecimalZero(info, call.Args[0]) {
			return true
		}
		if ident, ok := ast.Unparen(selector.X).(*ast.Ident); ok {
			amount = info.ObjectOf(ident)
		}
		return false
	})
	return amount
}

func branchClampsDecimalToZero(info *types.Info, fnBody, body *ast.BlockStmt, amount types.Object) bool {
	clamped, logged := false, false
	loggers := make(map[types.Object]bool)
	ast.Inspect(fnBody, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		ident, ok := ast.Unparen(assign.Lhs[0]).(*ast.Ident)
		selector, selectorOK := ast.Unparen(assign.Rhs[0]).(*ast.SelectorExpr)
		if ok && selectorOK && logMethod(selector.Sel.Name) {
			if object := info.ObjectOf(ident); object != nil {
				loggers[object] = true
			}
		}
		return true
	})
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch statement := node.(type) {
		case *ast.AssignStmt:
			if statement.Tok != token.ASSIGN || len(statement.Lhs) != 1 || len(statement.Rhs) != 1 || !patternkit.IsDecimalZero(info, statement.Rhs[0]) {
				return true
			}
			ident, ok := ast.Unparen(statement.Lhs[0]).(*ast.Ident)
			clamped = ok && info.ObjectOf(ident) == amount
		case *ast.CallExpr:
			if selector, ok := ast.Unparen(statement.Fun).(*ast.SelectorExpr); ok && logMethod(selector.Sel.Name) {
				logged = true
			} else if ident, ok := ast.Unparen(statement.Fun).(*ast.Ident); ok && loggers[info.ObjectOf(ident)] {
				logged = true
			}
		}
		return true
	})
	return clamped && logged
}

func logMethod(name string) bool {
	return strings.Contains(name, "Error") || strings.Contains(name, "Warn") || strings.Contains(name, "Log")
}
