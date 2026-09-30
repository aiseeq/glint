package security

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// Shared reading of what an HTTP handler takes from its request: the headers
// a proxy sets, the address of the connection, the Host header.

// headerGet returns the header a call reads — X.Header.Get("Name") or
// X.Header.Values("Name") — or "" for any other call.
func headerGet(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Get" && sel.Sel.Name != "Values") || len(call.Args) != 1 {
		return ""
	}
	header, ok := ast.Unparen(sel.X).(*ast.SelectorExpr)
	if !ok || header.Sel.Name != "Header" {
		return ""
	}
	return stringLiteral(call.Args[0])
}

// stringLiteral returns the value of a string literal, or "".
func stringLiteral(expr ast.Expr) string {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	// The parser accepted the literal, so it unquotes.
	if value, err := strconv.Unquote(lit.Value); err == nil {
		return value
	}
	return ""
}

// isRemoteAddr reports X.RemoteAddr read as a field: net.Conn's RemoteAddr()
// is a method and returns a net.Addr.
func isRemoteAddr(expr ast.Expr, parents map[ast.Node]ast.Node) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "RemoteAddr" {
		return false
	}
	call, isCall := parents[sel].(*ast.CallExpr)
	return !isCall || call.Fun != sel
}

// isRequestExpr reports an expression that reads as the incoming request:
// r, req, request, httpReq, c.Request.
func isRequestExpr(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e.Name == "r" || e.Name == "req" || strings.HasSuffix(e.Name, "Req") ||
			strings.HasSuffix(strings.ToLower(e.Name), "request")
	case *ast.SelectorExpr:
		return e.Sel.Name == "Request" || e.Sel.Name == "Req"
	}
	return false
}

// parentMap maps every node under root to its parent.
func parentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	return parents
}

// insideLogCall reports a node that is an argument, at any depth, of a log
// line or a print.
func insideLogCall(node ast.Node, parents map[ast.Node]ast.Node) bool {
	for p := parents[node]; p != nil; p = parents[p] {
		call, ok := p.(*ast.CallExpr)
		if !ok {
			continue
		}
		if helpers.IsLoggerCall(call) {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && helpers.IsStderrPrint(sel, call) {
			return true
		}
		if pkg, ok := callPackage(call); ok && pkg == "fmt" && !strings.HasPrefix(callName(call), "S") &&
			!strings.HasPrefix(callName(call), "Errorf") {
			return true
		}
	}
	return false
}

// callPackage returns the package a pkg.Func call names.
func callPackage(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}

// callName returns the name a call is made by: Func for pkg.Func and x.Func.
func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// isStringsCall reports strings.<name>(...).
func isStringsCall(expr ast.Expr, names ...string) (*ast.CallExpr, bool) {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	if pkg, ok := callPackage(call); !ok || pkg != "strings" {
		return nil, false
	}
	for _, name := range names {
		if callName(call) == name {
			return call, true
		}
	}
	return nil, false
}

// assignedValues calls visit for every name a body assigns from a single
// value: x := v, x = v, var x = v.
func assignedValues(body *ast.BlockStmt, visit func(name *ast.Ident, value ast.Expr)) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
					visit(ident, node.Rhs[i])
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) != len(node.Values) {
				return true
			}
			for i, name := range node.Names {
				visit(name, node.Values[i])
			}
		}
		return true
	})
}
