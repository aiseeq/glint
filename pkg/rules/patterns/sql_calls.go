package patterns

import (
	"go/ast"
)

// sqlCall is a call that passes SQL text: the text written right in the
// argument, or in the variable or constant the argument names.
type sqlCall struct {
	call     *ast.CallExpr
	queryArg int // index of the argument that carries the SQL
	literal  sqlLiteral
}

// sqlCalls returns the calls of a file that pass SQL text.
func sqlCalls(file *ast.File) []sqlCall {
	byExpr := make(map[ast.Expr]sqlLiteral)
	for _, literal := range sqlLiterals(file) {
		byExpr[literal.expr] = literal
	}
	if len(byExpr) == 0 {
		return nil
	}
	var calls []sqlCall
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for i, arg := range call.Args {
			if literal, ok := byExpr[declaredValue(arg)]; ok {
				calls = append(calls, sqlCall{call: call, queryArg: i, literal: literal})
				break
			}
		}
		return true
	})
	return calls
}

// declaredValue returns the expression itself, or for an identifier the
// value its declaration in the file gives it (query := `...`, const q = ...).
func declaredValue(expr ast.Expr) ast.Expr {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok || id.Obj == nil {
		return ast.Unparen(expr)
	}
	switch decl := id.Obj.Decl.(type) {
	case *ast.AssignStmt:
		for i, lhs := range decl.Lhs {
			if l, ok := lhs.(*ast.Ident); ok && l.Name == id.Name && i < len(decl.Rhs) && len(decl.Lhs) == len(decl.Rhs) {
				return ast.Unparen(decl.Rhs[i])
			}
		}
	case *ast.ValueSpec:
		for i, name := range decl.Names {
			if name.Name == id.Name && i < len(decl.Values) {
				return ast.Unparen(decl.Values[i])
			}
		}
	}
	return ast.Unparen(expr)
}
