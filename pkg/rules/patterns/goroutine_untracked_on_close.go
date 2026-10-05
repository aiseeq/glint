package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewGoroutineUntrackedOnCloseRule())
}

// GoroutineUntrackedOnCloseRule detects a goroutine a service starts outside
// the WaitGroup its Close waits on:
//
//	func (s *Service) Enqueue(e Event) {
//	    ...
//	    go s.flush()          // not counted in s.wg
//	}
//	func (s *Service) Close() { close(s.done); s.wg.Wait() }
//
// Close is meant to return once the service's work is done, and does so for
// the goroutines counted in the WaitGroup; the one started without Add keeps
// running past it, and the process exits in the middle of the flush - the
// events it held are lost. The rule looks at the methods of a type whose
// Close, Shutdown or Stop waits on a WaitGroup field: a goroutine of such a
// method whose function (a literal or a method of the type) never calls Done
// on that field is reported, unless the method calls Add on it.
//
// A main package is the same service without a Close: a worker it starts with
// a context (go poller.Run(ctx)) in a program that refers to no WaitGroup or
// errgroup is cancelled on shutdown and never waited for.
type GoroutineUntrackedOnCloseRule struct {
	*rules.BaseRule
}

// NewGoroutineUntrackedOnCloseRule creates the rule
func NewGoroutineUntrackedOnCloseRule() *GoroutineUntrackedOnCloseRule {
	return &GoroutineUntrackedOnCloseRule{BaseRule: rules.NewBaseRule(
		"goroutine-untracked-on-close",
		"patterns",
		"Detects a goroutine started by a service outside the WaitGroup its Close waits on — Close returns while it runs and its work is cut off; also workers main starts with a context in a program that waits on no WaitGroup",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the method, its goroutine and Close may sit in
// different files.
func (r *GoroutineUntrackedOnCloseRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *GoroutineUntrackedOnCloseRule) RequiresSSA() bool { return false }

var closeMethods = map[string]bool{"Close": true, "Shutdown": true, "Stop": true}

type methodDeclsKey struct{}

// AnalyzeGoProject reports the untracked goroutines of closable services.
func (r *GoroutineUntrackedOnCloseRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	decls, err := core.SharedLoad(ctx, methodDeclsKey{}, func() (map[*types.Func]*ast.FuncDecl, error) {
		return collectMethodDecls(ctx)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	mainWaits := mainPackagesWaiting(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		waited := make(map[*types.Named]closeWaits)
		violations := r.untrackedMainWorkers(file, info, mainWaits)
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			method, ok := info.Defs[fn.Name].(*types.Func)
			if !ok {
				continue
			}
			named := receiverNamed(method)
			if named == nil {
				continue
			}
			waits, ok := waited[named]
			if !ok {
				waits = closeWaitedGroups(named, decls, info)
				waited[named] = waits
			}
			fields := waits.fields
			if len(fields) == 0 || callsGroupMethod(fn.Body, info, fields, "Add") {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				stmt, ok := n.(*ast.GoStmt)
				if !ok {
					return true
				}
				group, untracked := untrackedGoroutine(stmt, named, fields, decls, info)
				if !untracked {
					return true
				}
				line := file.LineFor(stmt)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
					"Goroutine started outside the WaitGroup %s that %s.%s waits on — %s returns while it still runs, and its work is cut off at shutdown",
					group, named.Obj().Name(), waits.closer, waits.closer))
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion(fmt.Sprintf("Call %s.Add(1) before the go statement and defer %s.Done() inside the goroutine", group, group))
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

// mainPackagesWaiting returns, by directory, whether each main package
// refers to a sync.WaitGroup or an errgroup.Group: a program that waits for
// some goroutines has a shutdown it can extend to the others.
func mainPackagesWaiting(ctx *core.GoProjectContext) map[string]bool {
	waits := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.Name != "main" || pkg.Package.TypesInfo == nil {
			continue
		}
		found := false
		for _, obj := range pkg.Package.TypesInfo.Uses {
			if tn, ok := obj.(*types.TypeName); ok && tn.Pkg() != nil &&
				((tn.Pkg().Path() == "sync" && tn.Name() == "WaitGroup") || (tn.Pkg().Path() == "golang.org/x/sync/errgroup" && tn.Name() == "Group")) {
				found = true
				break
			}
		}
		for _, file := range pkg.Files {
			waits[filepath.Dir(file.Path)] = found
		}
	}
	return waits
}

// untrackedMainWorkers reports the workers a main package without any
// WaitGroup starts with a context (go poller.Run(ctx)): main returns after
// cancelling them and the process exits in the middle of their iteration.
// A goroutine without a context argument (the HTTP server's ListenAndServe
// in a literal) has its own shutdown.
func (r *GoroutineUntrackedOnCloseRule) untrackedMainWorkers(file *core.FileContext, info *types.Info, mainWaits map[string]bool) []*core.Violation {
	waits, isMain := mainWaits[filepath.Dir(file.Path)]
	if !isMain || waits || file.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(file.GoAST, func(n ast.Node) bool {
		stmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		if _, literal := stmt.Call.Fun.(*ast.FuncLit); literal || !passesContext(info, stmt.Call) {
			return true
		}
		line := file.LineFor(stmt)
		if file.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(file.RelPath, line,
			"Worker started by main with a context and no WaitGroup in the program — on shutdown main cancels it and returns without waiting, and the process exits in the middle of its iteration")
		v.WithCode(strings.TrimSpace(file.GetLine(line)))
		v.WithSuggestion("Count the workers in a sync.WaitGroup (Add before go, Done when Run returns) and wait on it, with a deadline, after cancelling them")
		violations = append(violations, v)
		return true
	})
	return violations
}

// collectMethodDecls indexes the method declarations of the loaded packages.
func collectMethodDecls(ctx *core.GoProjectContext) (map[*types.Func]*ast.FuncDecl, error) {
	decls := make(map[*types.Func]*ast.FuncDecl)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, fmt.Errorf("package has no typed syntax")
		}
		for _, file := range pkg.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Body == nil {
					continue
				}
				if method, ok := pkg.Package.TypesInfo.Defs[fn.Name].(*types.Func); ok {
					decls[method] = fn
				}
			}
		}
	}
	return decls, nil
}

// closeWaits are the WaitGroup fields a type's Close, Shutdown or Stop waits
// on, with how the code spells each (s.wg), and the waiting method.
type closeWaits struct {
	fields map[*types.Var]string
	closer string
}

// closeWaitedGroups returns the WaitGroup fields the type's Close, Shutdown or
// Stop waits on.
func closeWaitedGroups(named *types.Named, decls map[*types.Func]*ast.FuncDecl, info *types.Info) closeWaits {
	waits := closeWaits{fields: make(map[*types.Var]string)}
	for i := range named.NumMethods() {
		method := named.Method(i)
		if !closeMethods[method.Name()] {
			continue
		}
		decl, ok := decls[method]
		if !ok {
			continue
		}
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			if field, spelled, ok := groupMethodCall(n, info, "Wait"); ok {
				waits.fields[field] = spelled
				waits.closer = method.Name()
			}
			return true
		})
	}
	return waits
}

// groupMethodCall matches a call of method on a sync.WaitGroup field
// (s.wg.Wait()) and returns the field.
func groupMethodCall(n ast.Node, info *types.Info, method string) (*types.Var, string, bool) {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return nil, "", false
	}
	fieldSel, ok := ast.Unparen(sel.X).(*ast.SelectorExpr)
	if !ok {
		return nil, "", false
	}
	field, ok := info.Uses[fieldSel.Sel].(*types.Var)
	if !ok || !field.IsField() || !isWaitGroup(field.Type()) {
		return nil, "", false
	}
	return field, types.ExprString(fieldSel), true
}

func isWaitGroup(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "WaitGroup"
}

// callsGroupMethod reports a body calling method on one of the fields.
func callsGroupMethod(body *ast.BlockStmt, info *types.Info, fields map[*types.Var]string, method string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if field, _, ok := groupMethodCall(n, info, method); ok {
			if _, waited := fields[field]; waited {
				found = true
			}
		}
		return !found
	})
	return found
}

// untrackedGoroutine reports a go statement whose function is visible - a
// literal, or a method of the service - and never calls Done on a waited
// field, nor gets one as an argument. It returns how the code spells the
// field.
func untrackedGoroutine(stmt *ast.GoStmt, named *types.Named, fields map[*types.Var]string,
	decls map[*types.Func]*ast.FuncDecl, info *types.Info) (string, bool) {
	for _, arg := range stmt.Call.Args {
		if mentionsGroup(arg, info, fields) {
			return "", false
		}
	}
	var body *ast.BlockStmt
	switch fun := ast.Unparen(stmt.Call.Fun).(type) {
	case *ast.FuncLit:
		body = fun.Body
	case *ast.SelectorExpr:
		callee, ok := info.Uses[fun.Sel].(*types.Func)
		if !ok || receiverNamed(callee) != named {
			return "", false
		}
		decl, ok := decls[callee.Origin()]
		if !ok {
			return "", false
		}
		body = decl.Body
	default:
		return "", false
	}
	if callsGroupMethod(body, info, fields, "Done") {
		return "", false
	}
	return firstGroup(fields), true
}

// mentionsGroup reports an expression naming one of the fields.
func mentionsGroup(expr ast.Expr, info *types.Info, fields map[*types.Var]string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			if field, ok := info.Uses[ident].(*types.Var); ok {
				if _, waited := fields[field]; waited {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// firstGroup returns the spelling of the field that sorts first, so the
// message does not depend on map order.
func firstGroup(fields map[*types.Var]string) string {
	first := ""
	for _, spelled := range fields {
		if first == "" || spelled < first {
			first = spelled
		}
	}
	return first
}
