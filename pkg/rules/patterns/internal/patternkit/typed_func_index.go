package patternkit

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
)

// TypedFuncDecl is a function declaration of a loaded package with the type
// information of its package.
type TypedFuncDecl struct {
	Decl *ast.FuncDecl
	Info *types.Info
}

// funcDeclsKey caches the function declarations of every loaded package once
// per module load.
type funcDeclsKey struct{}

// FuncDeclsByObject indexes the function and method declarations with a body
// of the loaded packages by their object, so a rule can follow a call into
// the callee. A function whose body is not loaded is absent.
func FuncDeclsByObject(ctx *core.GoProjectContext) (map[*types.Func]TypedFuncDecl, error) {
	return core.SharedLoad(ctx, funcDeclsKey{}, func() (map[*types.Func]TypedFuncDecl, error) {
		decls := make(map[*types.Func]TypedFuncDecl)
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
						decls[obj] = TypedFuncDecl{Decl: fn, Info: info}
					}
				}
			}
		}
		return decls, nil
	})
}

// FuncCallSite is a static call of a loaded function from a loaded body.
type FuncCallSite struct {
	Call   *ast.CallExpr
	Caller TypedFuncDecl
}

// callSitesKey caches the call sites of every loaded body once per module
// load.
type callSitesKey struct{}

// FuncCallSites indexes the static calls of the loaded bodies by callee, so
// a rule can follow a parameter up to what the callers pass.
func FuncCallSites(ctx *core.GoProjectContext, decls map[*types.Func]TypedFuncDecl) (map[*types.Func][]FuncCallSite, error) {
	return core.SharedLoad(ctx, callSitesKey{}, func() (map[*types.Func][]FuncCallSite, error) {
		return CollectCallSites(decls), nil
	})
}

// CollectCallSites indexes the static calls of the loaded bodies by callee.
func CollectCallSites(decls map[*types.Func]TypedFuncDecl) map[*types.Func][]FuncCallSite {
	sites := make(map[*types.Func][]FuncCallSite)
	for _, caller := range decls {
		ast.Inspect(caller.Decl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if fn := StaticFunc(caller.Info, call); fn != nil {
					sites[fn.Origin()] = append(sites[fn.Origin()], FuncCallSite{Call: call, Caller: caller})
				}
			}
			return true
		})
	}
	return sites
}
