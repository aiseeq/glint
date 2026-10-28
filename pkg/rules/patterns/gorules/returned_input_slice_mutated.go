package gorules

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() { rules.Register(NewReturnedInputSliceMutatedRule()) }

// NewReturnedInputSliceMutatedRule finds a returned slice parameter whose
// caller mutates an element and then reads the original argument.
func NewReturnedInputSliceMutatedRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{BaseRule: rules.NewBaseRule(
		"returned-input-slice-mutated-while-original-kept", "patterns",
		"Detects mutation of a returned slice parameter when the caller later reads the original slice, which shares its backing array",
		core.SeverityMedium,
	), Suggestion: "Clone the slice before changing its elements when the original data must remain unchanged"}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		if fn.Body == nil || fn.Name == nil {
			return nil
		}
		object, ok := scope.Info.Defs[fn.Name].(*types.Func)
		if !ok {
			return nil
		}
		callee, loaded := scope.Decls[object.Origin()]
		if !loaded {
			return nil
		}
		var findings []patternkit.FuncFinding
		for index := range callee.Decl.Type.Params.List {
			param, ok := patternkit.ParamObject(callee, index).(*types.Var)
			if !ok {
				continue
			}
			resultIndex, returned := returnedParamIndex(callee, param)
			if !returned {
				continue
			}
			if _, ok := param.Type().Underlying().(*types.Slice); !ok {
				continue
			}
			returnNode := returnedParamNode(callee, param)
			if returnNode == nil {
				continue
			}
			for _, site := range scope.Callers[object.Origin()] {
				if index >= len(site.Call.Args) {
					continue
				}
				id, ok := ast.Unparen(site.Call.Args[index]).(*ast.Ident)
				if !ok {
					continue
				}
				original := site.Caller.Info.Uses[id]
				if original == nil {
					continue
				}
				result := calledResultIdent(site.Caller.Info, site.Caller.Decl.Body, site.Call, resultIndex)
				// items = pass(items) keeps no second view of the old slice.
				if result == nil || result == original {
					continue
				}
				mutation := firstElementMutation(site.Caller.Info, site.Caller.Decl.Body, result)
				if mutation != nil && sliceReadAfter(site.Caller.Info, site.Caller.Decl.Body, original, mutation.Pos()) {
					findings = append(findings, patternkit.FuncFinding{Node: returnNode, Message: "returning the input slice lets callers mutate the original backing array"})
					break
				}
			}
		}
		return findings
	}
	return r
}

func returnedParamNode(d patternkit.TypedFuncDecl, param *types.Var) ast.Node {
	var found ast.Node
	ast.Inspect(d.Decl.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, expr := range ret.Results {
			if id, ok := ast.Unparen(expr).(*ast.Ident); ok && d.Info.Uses[id] == param {
				found = id
				return false
			}
		}
		return found == nil
	})
	return found
}

func returnedParamIndex(d patternkit.TypedFuncDecl, param *types.Var) (int, bool) {
	index := -1
	ast.Inspect(d.Decl.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for i, e := range ret.Results {
			if id, ok := ast.Unparen(e).(*ast.Ident); ok && d.Info.Uses[id] == param {
				index = i
				return false
			}
		}
		return index < 0
	})
	return index, index >= 0
}

func calledResultIdent(info *types.Info, body *ast.BlockStmt, call *ast.CallExpr, result int) *types.Var {
	for _, stmt := range body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || assign.Rhs[0] != call || result >= len(assign.Lhs) {
			continue
		}
		id, ok := assign.Lhs[result].(*ast.Ident)
		if !ok {
			continue
		}
		obj := info.Defs[id]
		if obj == nil {
			obj = info.Uses[id]
		}
		if v, ok := obj.(*types.Var); ok {
			return v
		}
	}
	return nil
}

func firstElementMutation(info *types.Info, body *ast.BlockStmt, result *types.Var) ast.Node {
	var mutation ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if mutation != nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if elementFieldOf(info, lhs, result) {
					mutation = x
					return false
				}
			}
		case *ast.CallExpr:
			for _, arg := range x.Args {
				u, ok := ast.Unparen(arg).(*ast.UnaryExpr)
				if ok && u.Op == token.AND && elementOf(info, u.X, result) {
					mutation = x
					return false
				}
			}
		}
		return true
	})
	return mutation
}

func elementOf(info *types.Info, expr ast.Expr, result *types.Var) bool {
	idx, ok := ast.Unparen(expr).(*ast.IndexExpr)
	if !ok {
		return false
	}
	id, ok := ast.Unparen(idx.X).(*ast.Ident)
	return ok && info.Uses[id] == result
}

func elementFieldOf(info *types.Info, expr ast.Expr, result *types.Var) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return elementOf(info, sel.X, result)
}

func sliceReadAfter(info *types.Info, body *ast.BlockStmt, original types.Object, pos token.Pos) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Pos() > pos && info.Uses[id] == original {
			found = true
		}
		return !found
	})
	return found
}
