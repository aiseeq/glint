package moneyrules

import (
	"fmt"
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewMoneyMapMissingKeyReadAsZeroRule())
}

// NewMoneyMapMissingKeyReadAsZeroRule detects unchecked decimal map reads
// keyed by values from another collection.
func NewMoneyMapMissingKeyReadAsZeroRule() *patternkit.TypedFuncRule {
	return patternkit.NewTypedFuncRule(
		rules.NewBaseRule("money-map-missing-key-read-as-zero", "patterns",
			"Detects a shopspring/decimal map indexed without comma-ok by a key derived from a separate collection; a missing entry becomes a zero amount",
			core.SeverityMedium),
		"Use the comma-ok lookup and handle a missing amount explicitly",
		moneyMapMissingKeyReadAsZero,
	)
}

func moneyMapMissingKeyReadAsZero(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
	info := scope.Info
	parameters := make(map[types.Object]bool)
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			for _, name := range field.Names {
				if obj := info.ObjectOf(name); obj != nil {
					parameters[obj] = true
				}
			}
		}
	}
	keyOrigins := make(map[types.Object]types.Object)
	var rootFor func(ast.Expr) types.Object
	rootFor = func(expr ast.Expr) types.Object {
		if root := patternkit.RootObject(info, expr); root != nil {
			return root
		}
		if call, ok := ast.Unparen(expr).(*ast.CallExpr); ok {
			if info.Types[call.Fun].IsType() && len(call.Args) > 0 {
				return rootFor(call.Args[0])
			}
			return patternkit.RootObject(info, call.Fun)
		}
		return nil
	}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range assign.Rhs {
			if i >= len(assign.Lhs) {
				continue
			}
			root := rootFor(rhs)
			if !parameters[root] {
				continue
			}
			if id, ok := assign.Lhs[i].(*ast.Ident); ok {
				if obj := info.ObjectOf(id); obj != nil && keyOrigins[obj] == nil {
					keyOrigins[obj] = root
				}
			}
		}
		return true
	})

	var found []patternkit.FuncFinding
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		index, ok := node.(*ast.IndexExpr)
		if !ok {
			return true
		}
		typ := info.TypeOf(index.X)
		if typ == nil {
			return true
		}
		mapType, ok := typ.Underlying().(*types.Map)
		if !ok || !patternkit.IsStringType(mapType.Key()) || !isShopspringDecimalType(mapType.Elem()) {
			return true
		}
		keyRoot := rootFor(index.Index)
		if id, ok := ast.Unparen(index.Index).(*ast.Ident); ok {
			if origin := keyOrigins[info.ObjectOf(id)]; origin != nil {
				keyRoot = origin
			}
		}
		mapRoot := patternkit.RootObject(info, index.X)
		if keyRoot == nil || mapRoot == nil || keyRoot == mapRoot || !parameters[keyRoot] ||
			moneyMapLookupHasCommaOK(fn.Body, index) || !moneyMapValueFeedsField(info, fn.Body, index) {
			return true
		}
		found = append(found, patternkit.FuncFinding{Node: index, Message: fmt.Sprintf("%s is indexed by a key derived from another parameter without checking whether the decimal amount is present", types.ExprString(index.X))})
		return true
	})
	return found
}

func moneyMapValueFeedsField(info *types.Info, body *ast.BlockStmt, lookup *ast.IndexExpr) bool {
	valueObjects := make(map[types.Object]bool)
	ast.Inspect(body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range assign.Rhs {
			index, ok := rhs.(*ast.IndexExpr)
			if !ok || index != lookup || i >= len(assign.Lhs) {
				continue
			}
			if id, ok := assign.Lhs[i].(*ast.Ident); ok {
				if obj := info.ObjectOf(id); obj != nil {
					valueObjects[obj] = true
				}
			}
		}
		return true
	})

	feedsField := false
	ast.Inspect(body, func(node ast.Node) bool {
		field, ok := node.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if expressionContainsNode(field.Value, lookup) {
			feedsField = true
			return false
		}
		for obj := range valueObjects {
			if expressionContainsIdentifier(info, field.Value, obj) {
				feedsField = true
				return false
			}
		}
		return !feedsField
	})
	return feedsField
}

func expressionContainsNode(expr ast.Expr, target ast.Node) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if node == target {
			found = true
			return false
		}
		return !found
	})
	return found
}

func expressionContainsIdentifier(info *types.Info, expr ast.Expr, target types.Object) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && info.ObjectOf(id) == target {
			found = true
			return false
		}
		return !found
	})
	return found
}

func moneyMapLookupHasCommaOK(body *ast.BlockStmt, lookup *ast.IndexExpr) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 {
			return true
		}
		for _, rhs := range assign.Rhs {
			if index, ok := rhs.(*ast.IndexExpr); ok && index == lookup {
				found = true
				return false
			}
		}
		return !found
	})
	return found
}
