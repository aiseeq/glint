package patterns

import (
	"go/ast"
	"go/types"
	"sort"

	"github.com/aiseeq/glint/pkg/core"
)

// helperBackground is a function without a context of its own that opens
// context.Background/TODO.
type helperBackground struct {
	file  *core.FileContext
	calls []*ast.CallExpr
	uses  int // references to the function
	live  int // of them: calls from a function holding a context or a request
}

// requestPathHelpers reports context.Background/TODO in a function without a
// context parameter that is only ever called from functions holding one:
//
//	func (a *Admin) marketRate(pair string) { a.store.Rate(context.Background(), pair) }
//	func (a *Admin) handleQuote(w http.ResponseWriter, r *http.Request) { a.marketRate(pair) }
//
// Every caller has the request's context, and the helper cuts it off: a
// client gone or a deadline hit never reaches the call inside.
func (r *ContextBackgroundRule) requestPathHelpers(project *core.GoProjectContext) []*core.Violation {
	helpers := make(map[*types.Func]*helperBackground)
	for _, pkg := range project.Packages {
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() {
				continue
			}
			for _, decl := range file.GoAST.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				// A context parameter declared _ is discarded on purpose.
				if accepts, _ := contextParams(file.GoAST, info, fn.Type); accepts || holdsContext(file.GoAST, info, fn.Type) {
					continue
				}
				obj, ok := info.Defs[fn.Name].(*types.Func)
				if !ok {
					continue
				}
				if calls := ownBackgroundCalls(file.GoAST, info, fn.Body); len(calls) > 0 {
					helpers[obj] = &helperBackground{file: file, calls: calls}
				}
			}
		}
	}
	if len(helpers) == 0 {
		return nil
	}
	for _, pkg := range project.Packages {
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Files {
			if file.GoAST == nil {
				continue
			}
			countHelperUses(file.GoAST, info, helpers)
		}
	}
	var violations []*core.Violation
	for _, helper := range helpers {
		if helper.uses == 0 || helper.live != helper.uses {
			continue
		}
		for _, call := range helper.calls {
			line := helper.file.LineFor(call)
			v := r.CreateViolation(helper.file.RelPath, line,
				"context.Background() in a helper whose every caller holds a context - the caller's cancellation and deadline stop here")
			v.WithCode(helper.file.GetLine(line))
			v.WithSuggestion("Take ctx as the first parameter and pass the caller's context through")
			violations = append(violations, v)
		}
	}
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations
}

// holdsContext reports a function with a live context.Context or
// *http.Request parameter.
func holdsContext(file *ast.File, info *types.Info, funcType *ast.FuncType) bool {
	if _, live := contextParams(file, info, funcType); live {
		return true
	}
	return len(requestParameterNames(file, info, funcType)) > 0
}

// ownBackgroundCalls returns the context.Background/TODO calls of the body
// outside function literals, which run on their own schedule.
func ownBackgroundCalls(file *ast.File, info *types.Info, body *ast.BlockStmt) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if name, ok := packageFuncName(file, info, node, "context"); ok && (name == "Background" || name == "TODO") {
				calls = append(calls, node)
			}
		}
		return true
	})
	return calls
}

// countHelperUses counts the references to each helper and the calls from a
// function that holds a context. A reference that is not a call (a method
// value, a callback) counts as a caller without one.
func countHelperUses(file *ast.File, info *types.Info, helpers map[*types.Func]*helperBackground) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		live := holdsContext(file, info, fn.Type)
		called := make(map[*ast.Ident]bool)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.GoStmt:
				// go helper(): the work outlives the caller on purpose.
				if id := calleeIdent(node.Call); id != nil {
					if helper := helpers[funcObj(info, id)]; helper != nil {
						helper.uses++
					}
				}
				return false
			case *ast.FuncLit:
				// A literal may run after the caller returned.
				ast.Inspect(node.Body, func(inner ast.Node) bool {
					if id, ok := inner.(*ast.Ident); ok {
						if helper := helpers[funcObj(info, id)]; helper != nil {
							helper.uses++
						}
					}
					return true
				})
				return false
			case *ast.CallExpr:
				if id := calleeIdent(node); id != nil {
					called[id] = true
				}
			case *ast.Ident:
				helper := helpers[funcObj(info, node)]
				if helper == nil {
					return true
				}
				helper.uses++
				if live && called[node] {
					helper.live++
				}
			}
			return true
		})
	}
}

func funcObj(info *types.Info, id *ast.Ident) *types.Func {
	fn, _ := info.Uses[id].(*types.Func)
	return fn
}

// calleeIdent returns the identifier naming the called function: f in f(),
// m in x.m().
func calleeIdent(call *ast.CallExpr) *ast.Ident {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		return fun
	case *ast.SelectorExpr:
		return fun.Sel
	}
	return nil
}
