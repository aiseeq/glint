package helpers

import (
	"go/ast"
	"go/token"
)

// DeclaresName reports whether the file declares the name anywhere: at package
// level, as a parameter, result, receiver or type parameter, as a variable,
// constant or type in a function, as an import name or as a range or
// short-declaration variable. It answers from syntax alone, for files without
// type information; a declaration in another file of the package is not seen.
func DeclaresName(file *ast.File, name string) bool {
	if file == nil {
		return false
	}
	declared := false
	matches := func(idents ...*ast.Ident) {
		for _, ident := range idents {
			if ident != nil && ident.Name == name {
				declared = true
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if declared {
			return false
		}
		switch node := n.(type) {
		case *ast.ImportSpec:
			matches(node.Name)
		case *ast.TypeSpec:
			matches(node.Name)
		case *ast.ValueSpec:
			matches(node.Names...)
		case *ast.FuncDecl:
			if node.Recv == nil {
				matches(node.Name)
			}
		case *ast.Field:
			matches(node.Names...)
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						matches(ident)
					}
				}
			}
		case *ast.RangeStmt:
			if node.Tok == token.DEFINE {
				for _, target := range []ast.Expr{node.Key, node.Value} {
					if ident, ok := target.(*ast.Ident); ok {
						matches(ident)
					}
				}
			}
		}
		return true
	})
	return declared
}
