package patterns

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
)

// typedFuncDecl is a function declaration of a loaded package with the type
// information of its package.
type typedFuncDecl struct {
	decl *ast.FuncDecl
	info *types.Info
}

// funcDeclsKey caches the function declarations of every loaded package once
// per module load.
type funcDeclsKey struct{}

// funcDeclsByObject indexes the function and method declarations with a body
// of the loaded packages by their object, so a rule can follow a call into
// the callee. A function whose body is not loaded is absent.
func funcDeclsByObject(ctx *core.GoProjectContext) (map[*types.Func]typedFuncDecl, error) {
	return core.SharedLoad(ctx, funcDeclsKey{}, func() (map[*types.Func]typedFuncDecl, error) {
		decls := make(map[*types.Func]typedFuncDecl)
		for _, pkgCtx := range ctx.Packages {
			if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
				continue
			}
			info := pkgCtx.Package.TypesInfo
			for _, file := range pkgCtx.Package.Syntax {
				for _, decl := range file.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Body == nil {
						continue
					}
					if obj, ok := info.Defs[fn.Name].(*types.Func); ok {
						decls[obj] = typedFuncDecl{decl: fn, info: info}
					}
				}
			}
		}
		return decls, nil
	})
}

// funcCallSite is a static call of a loaded function from a loaded body.
type funcCallSite struct {
	call   *ast.CallExpr
	caller typedFuncDecl
}

// callSitesKey caches the call sites of every loaded body once per module
// load.
type callSitesKey struct{}

// funcCallSites indexes the static calls of the loaded bodies by callee, so
// a rule can follow a parameter up to what the callers pass.
func funcCallSites(ctx *core.GoProjectContext, decls map[*types.Func]typedFuncDecl) (map[*types.Func][]funcCallSite, error) {
	return core.SharedLoad(ctx, callSitesKey{}, func() (map[*types.Func][]funcCallSite, error) {
		return collectCallSites(decls), nil
	})
}

// collectCallSites indexes the static calls of the loaded bodies by callee.
func collectCallSites(decls map[*types.Func]typedFuncDecl) map[*types.Func][]funcCallSite {
	sites := make(map[*types.Func][]funcCallSite)
	for _, caller := range decls {
		ast.Inspect(caller.decl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if fn := staticFunc(caller.info, call); fn != nil {
					sites[fn.Origin()] = append(sites[fn.Origin()], funcCallSite{call: call, caller: caller})
				}
			}
			return true
		})
	}
	return sites
}
