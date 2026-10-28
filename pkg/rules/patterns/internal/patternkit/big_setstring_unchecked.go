package patternkit

import (
	"go/ast"
	"strings"
)

func IsBlank(expr ast.Expr) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "_"
}

// ImportsPackage reports whether the file imports the package path.
func ImportsPackage(file *ast.File, importPath string) bool {
	for _, spec := range file.Imports {
		if strings.Trim(spec.Path.Value, "\"`") == importPath {
			return true
		}
	}
	return false
}
