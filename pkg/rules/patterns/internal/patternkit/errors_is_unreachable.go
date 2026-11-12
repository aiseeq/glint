package patternkit

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

const SqlxPath = "github.com/jmoiron/sqlx"

// StdlibPath reports a standard library import path.
func StdlibPath(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

// SentinelName reports a name given to sentinel errors: ErrNotFound, errClosed.
func SentinelName(name string) bool {
	return strings.HasPrefix(name, "Err") || strings.HasPrefix(name, "err")
}

// MentionsVar reports a node that defines or uses the variable.
func MentionsVar(info *types.Info, node ast.Node, v *types.Var) bool {
	return helpers.ContainsNode[*ast.Ident](node, func(ident *ast.Ident) bool {
		return info.ObjectOf(ident) == v
	})
}

// ParamIndex returns the position of a parameter of the function.
func ParamIndex(fn TypedFunc, v *types.Var) (int, bool) {
	index := 0
	for _, field := range fn.Decl.Type.Params.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, name := range field.Names {
			if fn.Info.Defs[name] == v {
				return index, true
			}
			index++
		}
	}
	return 0, false
}

// AssignsVar reports a statement assigning the variable.
func AssignsVar(info *types.Info, stmt ast.Stmt, v *types.Var) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && info.ObjectOf(ident) == v {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// MayMutateVar reports whether a node assigns the variable or takes its
// address. AST inspection includes nested statements and closures.
func MayMutateVar(info *types.Info, node ast.Node, v *types.Var) bool {
	if stmt, ok := node.(ast.Stmt); ok && AssignsVar(info, stmt, v) {
		return true
	}
	return AddressTakenVar(info, node, v)
}

// AddressTakenVar reports whether a node takes the variable's address.
func AddressTakenVar(info *types.Info, node ast.Node, v *types.Var) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		unary, ok := n.(*ast.UnaryExpr)
		if !ok || unary.Op != token.AND {
			return true
		}
		ident, ok := ast.Unparen(unary.X).(*ast.Ident)
		found = ok && info.ObjectOf(ident) == v
		return !found
	})
	return found
}

// MutatedVarInClosure reports whether a function literal assigns the variable
// or takes its address anywhere inside node.
func MutatedVarInClosure(info *types.Info, node ast.Node, v *types.Var) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		literal, ok := n.(*ast.FuncLit)
		if ok && MayMutateVar(info, literal.Body, v) {
			found = true
		}
		return !found
	})
	return found
}
