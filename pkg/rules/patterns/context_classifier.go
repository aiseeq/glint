package patterns

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// contextClassifier tells whether an expression is a context.Context value.
// With type information the expression's type answers. Without it only what
// the file declares counts: a variable or parameter declared as
// context.Context, or a call to a context constructor. A name the file does
// not declare is unknown - its spelling ("ctx") is not evidence.
type contextClassifier struct {
	info     *types.Info
	inferred *TypeInferrer
	aliases  map[string]bool
}

// newContextClassifier builds the classifier for code inside scope, a
// function declaration or literal of file. info may be nil.
func newContextClassifier(file *ast.File, scope ast.Node, info *types.Info) contextClassifier {
	if info != nil {
		return contextClassifier{info: info}
	}
	return contextClassifier{
		inferred: NewTypeInferrerFromNode(scope),
		aliases:  helpers.PackageAliases(file, `"context"`, "context"),
	}
}

// contextValueConstructors are the context package functions whose single
// result is a context.Context.
var contextValueConstructors = map[string]bool{
	"Background": true, "TODO": true, "WithValue": true, "WithoutCancel": true,
}

// classify reports whether expr is a context.Context and whether that is
// known at all.
func (c contextClassifier) classify(expr ast.Expr) (isContext, known bool) {
	expr = ast.Unparen(expr)
	if c.info != nil {
		t := c.info.TypeOf(expr)
		if t == nil {
			return false, false
		}
		return isContextArg(types.Unalias(t)), true
	}
	switch node := expr.(type) {
	case *ast.Ident:
		if node.Name == "nil" {
			return false, true
		}
		declared, ok := c.inferred.GetType(node.Name)
		if !ok || declared.TypeName == "" {
			return false, false
		}
		return c.isContextTypeName(declared.TypeName), true
	case *ast.CallExpr:
		selector, ok := node.Fun.(*ast.SelectorExpr)
		if !ok {
			return false, false
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || !c.aliases[pkg.Name] {
			return false, false
		}
		return contextValueConstructors[selector.Sel.Name], true
	case *ast.SelectorExpr, *ast.IndexExpr, *ast.TypeAssertExpr, *ast.StarExpr:
		return false, false
	default:
		// Literals, composites, address-of and arithmetic are never a Context.
		return false, true
	}
}

// isContextTypeName reports whether a declared type name, as the file spells
// it, is context.Context.
func (c contextClassifier) isContextTypeName(typeName string) bool {
	for alias := range c.aliases {
		if typeName == alias+".Context" {
			return true
		}
	}
	return false
}
