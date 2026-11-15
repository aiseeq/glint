package patternkit

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
)

// EnvFileSkipDirs are the dependency directories whose env files, templates
// and tsconfigs are never the project's, even under an explicit
// settings.skip_dirs that leaves them in. A build directory (dist, build, out,
// bin) is not here: RepositoryTree decides it as the run's walk does, reading
// one git tracks.
var EnvFileSkipDirs = map[string]bool{"node_modules": true, ".git": true, "vendor": true}

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
