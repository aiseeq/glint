package patternkit

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
)

// EnvFileSkipDirs are the directories whose env files are not the project's.
var EnvFileSkipDirs = map[string]bool{"node_modules": true, ".git": true, "vendor": true, "dist": true}

// CalleeName renders `pkg.Func` or `Func` for a call expression; the rendering
// itself is core.ExtractFullFunctionName.
func CalleeName(call *ast.CallExpr) string {
	return core.ExtractFullFunctionName(call)
}

// GoStringLiteral returns the value of a string literal, or false for any other
// literal kind. The literal comes from go/parser, which only produces
// well-formed string literals, so decoding one cannot fail; a failure means the
// AST was built by hand wrongly, and that is a bug to surface, not a value to
// guess.
func GoStringLiteral(lit *ast.BasicLit) (string, bool) {
	if lit.Kind != token.STRING {
		return "", false
	}
	value := constant.MakeFromLiteral(lit.Value, token.STRING, 0)
	if value.Kind() != constant.String {
		panic(fmt.Sprintf("malformed string literal from go/parser: %s", lit.Value))
	}
	return constant.StringVal(value), true
}
