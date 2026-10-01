package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"golang.org/x/tools/go/ast/astutil"
)

// detachedReads reports context.WithoutCancel(ctx) whose context only feeds
// reads the function waits for: the caller's cancellation no longer reaches
// them, and a client that has gone keeps the query running. Detaching is
// left alone where it is the point — a write that must complete, work run
// in a goroutine or by a function launched with go, a context handed back
// or stored for later.
func (r *ContextBackgroundRule) detachedReads(ctx *core.FileContext, info *types.Info, fn *ast.FuncDecl, doneAt token.Pos, launched map[string]bool) []*core.Violation {
	if launched[fn.Name.Name] {
		return nil
	}
	params := contextParamNames(ctx.GoAST, info, fn.Type)
	goStmts := goStatements(fn.Body)
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isPackageFuncCall(ctx.GoAST, info, call, "context", "WithoutCancel") || len(call.Args) != 1 {
			return true
		}
		arg, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
		if !ok || !params[arg.Name] || withinAny(call, goStmts) || (doneAt.IsValid() && call.Pos() > doneAt) {
			return true
		}
		reads, ok := detachedUses(ctx.GoAST, info, fn.Body, call, goStmts)
		if !ok || reads == 0 {
			return true
		}
		line := ctx.LineFor(call)
		v := r.CreateViolation(ctx.RelPath, line,
			"context.WithoutCancel(ctx) detaches a read the function waits for — the caller's cancellation no longer stops it, and a client that has gone keeps the query running")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Pass ctx (or a timeout derived from it) to the read; detach only work that must outlive the request — a write that must complete, a goroutine")
		violations = append(violations, v)
		return true
	})
	return violations
}

// detachedUses follows the detached context through context.With* wrappers
// and local variables to the calls that take it. It returns the number of
// those calls, all of them reads, or false when the context escapes: it is
// returned, stored, used in a goroutine, or passed to anything but a read.
func detachedUses(file *ast.File, info *types.Info, body *ast.BlockStmt, detached ast.Expr, goStmts []*ast.GoStmt) (int, bool) {
	path, _ := astutil.PathEnclosingInterval(file, detached.Pos(), detached.End())
	// path[0] is the expression itself (or a node inside it); find its parent.
	var parent ast.Node
	for i, node := range path {
		if node == detached && i+1 < len(path) {
			parent = path[i+1]
			break
		}
	}
	switch p := parent.(type) {
	case *ast.CallExpr:
		if isPackageFuncCall(file, info, p, "context", "WithTimeout", "WithDeadline", "WithCancel", "WithValue") {
			return detachedUses(file, info, body, p, goStmts)
		}
		if readMethod.MatchString(calledFunctionName(p.Fun)) {
			return 1, true
		}
		return 0, false
	case *ast.AssignStmt:
		if len(p.Rhs) != 1 || len(p.Lhs) == 0 {
			return 0, false
		}
		ident, ok := p.Lhs[0].(*ast.Ident)
		if !ok || ident.Name == "_" {
			return 0, false
		}
		return variableReads(info, body, ident, goStmts)
	}
	return 0, false
}

// variableReads counts the read calls a local context variable is passed to,
// or reports false when it goes anywhere else.
func variableReads(info *types.Info, body *ast.BlockStmt, def *ast.Ident, goStmts []*ast.GoStmt) (int, bool) {
	var obj types.Object
	if info != nil {
		obj = info.ObjectOf(def)
	}
	same := func(ident *ast.Ident) bool {
		if obj != nil {
			return info.Uses[ident] == obj
		}
		return ident.Name == def.Name && ident != def
	}
	reads, escapes := 0, false
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		if escapes {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			for _, arg := range node.Args {
				ident, ok := ast.Unparen(arg).(*ast.Ident)
				if !ok || !same(ident) {
					continue
				}
				if withinAny(node, goStmts) || !readMethod.MatchString(calledFunctionName(node.Fun)) {
					escapes = true
					return false
				}
				reads++
			}
			// A method of the context itself (Done, Err) is no hand-off.
			if sel, ok := ast.Unparen(node.Fun).(*ast.SelectorExpr); ok {
				if ident, ok := ast.Unparen(sel.X).(*ast.Ident); ok && same(ident) {
					for _, arg := range node.Args {
						ast.Inspect(arg, visit)
					}
					return false
				}
			}
			for _, arg := range node.Args {
				if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && same(ident) {
					continue
				}
				ast.Inspect(arg, visit)
			}
			ast.Inspect(node.Fun, visit)
			return false
		case *ast.Ident:
			if same(node) {
				escapes = true // returned, stored, sent or captured
			}
		}
		return true
	}
	ast.Inspect(body, visit)
	return reads, !escapes
}

// contextParamNames returns the names of a signature's context parameters.
func contextParamNames(file *ast.File, info *types.Info, funcType *ast.FuncType) map[string]bool {
	names := map[string]bool{}
	if funcType == nil || funcType.Params == nil {
		return names
	}
	for _, field := range funcType.Params.List {
		if !isContextTypeExpr(file, info, field.Type) {
			continue
		}
		for _, name := range field.Names {
			names[name.Name] = true
		}
	}
	return names
}

// launchedFunctions returns the names of the functions and methods a file
// starts with a go statement.
func launchedFunctions(file *ast.File) map[string]bool {
	launched := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if stmt, ok := n.(*ast.GoStmt); ok {
			if name := calledFunctionName(stmt.Call.Fun); name != "" {
				launched[name] = true
			}
		}
		return true
	})
	return launched
}

func goStatements(body *ast.BlockStmt) []*ast.GoStmt {
	var stmts []*ast.GoStmt
	ast.Inspect(body, func(n ast.Node) bool {
		if stmt, ok := n.(*ast.GoStmt); ok {
			stmts = append(stmts, stmt)
		}
		return true
	})
	return stmts
}

func withinAny(node ast.Node, stmts []*ast.GoStmt) bool {
	for _, stmt := range stmts {
		if node.Pos() >= stmt.Pos() && node.End() <= stmt.End() {
			return true
		}
	}
	return false
}
