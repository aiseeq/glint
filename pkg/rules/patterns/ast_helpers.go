package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"path"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// analyzeGoFunctions runs check over every function body of a Go source file
// and collects what it reports. Rules that work per function share this guard:
// non-Go files, tests and files that failed to parse have nothing to analyze.
func analyzeGoFunctions(ctx *core.FileContext, check func(*ast.FuncDecl) []*core.Violation) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		violations = append(violations, check(fn)...)
	}
	return violations
}

// isNilIdent reports whether the expression is the nil identifier.
func isNilIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}

// forEachTypedFuncDecl visits every function with a body in the typed syntax
// of the project's packages, test files included, with its package's types;
// obj is nil for a declaration the type checker did not define.
func forEachTypedFuncDecl(ctx *core.GoProjectContext, visit func(info *types.Info, fn *ast.FuncDecl, obj *types.Func)) error {
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return fmt.Errorf("package has no typed syntax")
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				obj, _ := info.Defs[fn.Name].(*types.Func)
				visit(info, fn, obj)
			}
		}
	}
	return nil
}

// loopBodies returns the parts of the loops under node that run on every
// iteration: the body, and a for loop's condition and post statement.
// Closures defined inside a loop count as inside it.
func loopBodies(node ast.Node) []ast.Node {
	var parts []ast.Node
	ast.Inspect(node, func(n ast.Node) bool {
		switch loop := n.(type) {
		case *ast.ForStmt:
			parts = append(parts, loop.Body)
			if loop.Cond != nil {
				parts = append(parts, loop.Cond)
			}
			if loop.Post != nil {
				parts = append(parts, loop.Post)
			}
		case *ast.RangeStmt:
			parts = append(parts, loop.Body)
		}
		return true
	})
	return parts
}

// fileImport is one import of a file: its path and the name the file uses
// for it - the explicit name, or the last element of the path.
type fileImport struct {
	path, name string
}

// fileImports returns the imports of a file.
func fileImports(file *ast.File) []fileImport {
	imports := make([]fileImport, 0, len(file.Imports))
	for _, spec := range file.Imports {
		// The parser only accepts string literals here, quoted or raw.
		importPath := strings.Trim(spec.Path.Value, "\"`")
		name := path.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports = append(imports, fileImport{path: importPath, name: name})
	}
	return imports
}
