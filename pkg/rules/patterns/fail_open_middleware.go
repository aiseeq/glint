package patterns

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
)

// middlewareChecks reports the fail-open shapes of a function that passes the
// request on (next.ServeHTTP):
//
//	if claim := ctx.Value(key); claim == nil { next.ServeHTTP(w, r); return }
//	... // the restriction applies only to a request that carries the claim
//
//	if err == nil { ... http.Error(w, "denied", 403) ... }
//	next.ServeHTTP(w, r) // a failed read or decode skips the check
func (r *FailOpenRule) middlewareChecks(ctx *core.FileContext, body *ast.BlockStmt) []*core.Violation {
	passOns := ownPassOns(body)
	if len(passOns) == 0 {
		return nil
	}
	contextValues := make(map[string]bool)
	var violations []*core.Violation
	var reported []*ast.IfStmt
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if id, ok := node.Lhs[min(i, len(node.Lhs)-1)].(*ast.Ident); ok && isContextValue(rhs) {
					contextValues[id.Name] = true
				}
			}
		case *ast.IfStmt:
			for _, outer := range reported {
				if node.Pos() > outer.Pos() && node.End() <= outer.End() {
					return true
				}
			}
			if subject := nilSubject(node.Cond); subject != nil && contextValue(subject, contextValues) {
				if call := passOnCall(node.Body); call != nil && rejectsOutside(body, node) {
					violations = append(violations, r.violation(ctx, call,
						"The request without this context value is passed on unrestricted, while one that carries it is checked - a missing claim grants the widest access"))
					reported = append(reported, node)
				}
				return true
			}
			if node.Else == nil && successGuard(node.Cond) && rejectsInside(node.Body) && passedOnAfter(passOns, node) {
				violations = append(violations, r.violation(ctx, node,
					"The check runs only when the read or decode succeeded - on its error the request skips the check and is passed on"))
				reported = append(reported, node)
			}
		}
		return true
	})
	return violations
}

// ownPassOns returns the next.ServeHTTP calls of a function body, outside
// the function literals in it.
func ownPassOns(body *ast.BlockStmt) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ServeHTTP" {
				calls = append(calls, node)
			}
		}
		return true
	})
	return calls
}

// isContextValue reports ctx.Value(key) or r.Context().Value(key).
func isContextValue(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Value"
}

func contextValue(expr ast.Expr, values map[string]bool) bool {
	if id, ok := expr.(*ast.Ident); ok {
		return values[id.Name]
	}
	return isContextValue(expr)
}

// nilSubject returns x of x == nil.
func nilSubject(cond ast.Expr) ast.Expr {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL || !isNilIdent(bin.Y) {
		return nil
	}
	return bin.X
}

// successGuard reports a condition that holds only when a call succeeded:
// err == nil, json.Unmarshal(...) == nil, alone or in an && chain.
func successGuard(cond ast.Expr) bool {
	switch expr := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		switch expr.Op {
		case token.LAND:
			return successGuard(expr.X) || successGuard(expr.Y)
		case token.EQL:
			if !isNilIdent(expr.Y) {
				return false
			}
			switch x := ast.Unparen(expr.X).(type) {
			case *ast.Ident:
				return isErrorVarName(x.Name)
			case *ast.CallExpr:
				return true
			}
		}
	}
	return false
}

// rejectsInside reports a block that answers with an error response
// somewhere inside it.
func rejectsInside(block *ast.BlockStmt) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "WriteHeader" || (sel.Sel.Name == "Error" && isIdentNamed(sel.X, "http"))) {
				found = true
			}
		}
		return !found
	})
	return found
}

// rejectsOutside reports a function body that answers with an error response
// outside the given if.
func rejectsOutside(body *ast.BlockStmt, skip *ast.IfStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			if node == skip {
				return false
			}
		case *ast.BlockStmt:
			if node != body && rejectsInsideOwn(node) {
				found = true
			}
		}
		return !found
	})
	return found
}

// rejectsInsideOwn reports a block whose own statements answer with an
// error response.
func rejectsInsideOwn(block *ast.BlockStmt) bool {
	for _, stmt := range block.List {
		if expr, ok := stmt.(*ast.ExprStmt); ok {
			if rejectsInside(&ast.BlockStmt{List: []ast.Stmt{expr}}) {
				return true
			}
		}
	}
	return false
}

// passedOnAfter reports a pass-on call that follows the if.
func passedOnAfter(passOns []*ast.CallExpr, stmt *ast.IfStmt) bool {
	for _, call := range passOns {
		if call.Pos() > stmt.End() {
			return true
		}
	}
	return false
}
