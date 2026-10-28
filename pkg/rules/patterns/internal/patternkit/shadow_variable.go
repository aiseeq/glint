package patternkit

import (
	"fmt"
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
)

// fileScopesKey keys the single-file check in core.FileShared.
type fileScopesKey struct{}

// FileScopes type-checks one file on its own and returns its definitions,
// uses and scopes, once per file for every rule that asks; the result must not
// be modified. Imports are not resolved and names from other files of the
// package are missing, so the checker reports errors; they are expected and
// ignored: they concern types, not the lexical scopes read here. An imported
// package still gets its name: a qualifier resolves to a *types.PkgName.
func FileScopes(ctx *core.FileContext) *types.Info {
	return core.FileShared(ctx, fileScopesKey{}, func() *types.Info { return checkFileScopes(ctx) })
}

// IsPackageName reports whether ident names an imported package in the file
// the scopes were checked from, and not a local declaration of the same name.
// The parser's own resolution (ast.Ident.Obj) cannot tell: the project load
// parses without it.
func IsPackageName(scopes *types.Info, ident *ast.Ident) bool {
	_, ok := scopes.Uses[ident].(*types.PkgName)
	return ok
}

func checkFileScopes(ctx *core.FileContext) *types.Info {
	info := &types.Info{
		Defs:   make(map[*ast.Ident]types.Object),
		Uses:   make(map[*ast.Ident]types.Object),
		Scopes: make(map[ast.Node]*types.Scope),
	}
	conf := types.Config{
		Importer: unresolvedImporter{},
		Error:    func(error) {},
	}
	_, _ = conf.Check(ctx.GoAST.Name.Name, ctx.GoFileSet, []*ast.File{ctx.GoAST}, info) // ignored-error: safe — the first of the expected unresolved-name errors; the scopes are complete regardless
	return info
}

// unresolvedImporter refuses every import: a file checked on its own has no
// access to the packages it imports.
type unresolvedImporter struct{}

func (unresolvedImporter) Import(path string) (*types.Package, error) {
	return nil, fmt.Errorf("import %q: not resolved in a single-file check", path)
}

var _ types.Importer = unresolvedImporter{}
