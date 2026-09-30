package fix

import (
	"go/ast"
	"go/token"
	"path"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// canReferToPackage reports whether new code in the file may name the package
// at importPath by its default name. It may when the name means nothing else in
// the file: no other import takes it, and every identifier spelled like it is
// the package qualifier of a selector while the file imports the package under
// that name. A declaration of the name anywhere in the file - a parameter, a
// variable, a type - could shadow the package where the new code lands, so the
// file is then left alone.
//
// A declaration of the name in another file of the package cannot be seen from
// here; the rules that need that certainty check the package scope themselves.
func canReferToPackage(file *ast.File, importPath string) bool {
	if file == nil {
		return false
	}
	name := path.Base(importPath)

	// The parser accepted every import path, so a path is its literal without
	// the quotes; a literal spelled with escapes reads as another package,
	// whose name then keeps the package name taken.
	imported := false
	for _, spec := range file.Imports {
		specPath := strings.Trim(spec.Path.Value, "\"`")
		local := path.Base(specPath)
		if spec.Name != nil {
			local = spec.Name.Name
		}
		if local != name {
			continue
		}
		if specPath != importPath {
			return false // another package already answers to the name
		}
		imported = true
	}

	// The package clause and the selected names of selectors (x.name) do not
	// live in the file's scope; the qualifiers (name.X) refer to the import.
	qualifiers := make(map[*ast.Ident]bool)
	selected := map[*ast.Ident]bool{file.Name: true}
	free := true
	ast.Inspect(file, func(n ast.Node) bool {
		if !free {
			return false
		}
		switch node := n.(type) {
		case *ast.ImportSpec:
			return false
		case *ast.SelectorExpr:
			selected[node.Sel] = true
			if ident, ok := node.X.(*ast.Ident); ok {
				qualifiers[ident] = true
			}
		case *ast.Ident:
			if node.Name == name && !selected[node] && (!imported || !qualifiers[node]) {
				free = false
			}
		}
		return true
	})
	return free
}

// nodeFix builds a fix that replaces the source between from and to - the
// span of a syntax node - with newText. The span is taken from the parsed file
// itself, so the fix touches exactly the node and nothing that merely looks
// like it on the same line.
func nodeFix(ctx *core.FileContext, from, to token.Pos, newText string) (*Fix, bool) {
	if ctx == nil || ctx.GoFileSet == nil || !from.IsValid() || !to.IsValid() {
		return nil, false
	}
	start := ctx.GoFileSet.Position(from)
	end := ctx.GoFileSet.Position(to)
	if start.Offset < 0 || end.Offset > len(ctx.Content) || start.Offset > end.Offset {
		return nil, false
	}
	return &Fix{
		File:      ctx.Path,
		StartLine: start.Line,
		StartCol:  start.Column,
		EndLine:   end.Line,
		EndCol:    end.Column,
		OldText:   string(ctx.Content[start.Offset:end.Offset]),
		NewText:   newText,
	}, true
}

// sourceOf returns the source text of a node as the file spells it.
func sourceOf(ctx *core.FileContext, node ast.Node) (string, bool) {
	if ctx == nil || ctx.GoFileSet == nil || node == nil {
		return "", false
	}
	start := ctx.GoFileSet.Position(node.Pos())
	end := ctx.GoFileSet.Position(node.End())
	if start.Offset < 0 || end.Offset > len(ctx.Content) || start.Offset > end.Offset {
		return "", false
	}
	return string(ctx.Content[start.Offset:end.Offset]), true
}

// violationPosition reports whether the node starts at the line and column the
// violation points to.
func violationPosition(ctx *core.FileContext, v *core.Violation, node ast.Node) bool {
	pos := ctx.GoFileSet.Position(node.Pos())
	return pos.Line == v.Line && pos.Column == v.Column
}
