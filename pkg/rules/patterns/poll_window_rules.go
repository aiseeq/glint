package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewPollWindowStartSetAfterFetchRule())
	rules.Register(NewPollWindowAdvancedPastLoggedFailureRule())
}

// pollWindowDepth bounds how deep the helpers handed the fetched records are
// followed to the write whose failure they only log.
const pollWindowDepth = 2

// NewPollWindowStartSetAfterFetchRule creates poll-window-start-set-after-fetch:
// a poll whose window starts at a time.Time field and that sets the field to
// the current time after the fetch and the processing loses what arrived in
// between:
//
//	history, err := m.client.GetSince(ctx, m.lastCheck)
//	... process history ...
//	m.lastCheck = time.Now()   // records that arrived during the tick are in neither window
//
// The next window has to start where this fetch looked: a time taken before
// the fetch.
func NewPollWindowStartSetAfterFetchRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"poll-window-start-set-after-fetch",
			"patterns",
			"Detects a poll window start (a time.Time field the fetch reads from) set to time.Now() after the fetch — records arriving while the tick runs fall into neither window",
			core.SeverityMedium,
		),
		suggestion: "Take the time before the fetch (fetchedAt := time.Now()) and start the next window there; the overlap is cut by the dedup",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		for _, window := range pollWindows(scope.info, fn) {
			for _, assign := range window.advances {
				if isTimeNow(assign.Rhs[0]) {
					findings = append(findings, funcFinding{node: assign, message: "The poll window start " + window.field.Name() + " is set to time.Now() after the fetch it bounded — what arrived while the tick fetched and processed falls into neither window and is never seen"})
				}
			}
		}
		return findings
	}
	return r
}

// NewPollWindowAdvancedPastLoggedFailureRule creates
// poll-window-advanced-past-logged-failure: a poll that hands the fetched
// records to a helper without an error result, which only logs a failed
// write, and then moves its window on, never fetches the failed record again:
//
//	m.recordOutflows(ctx, history.Data) // a failed write is logged inside
//	m.lastCheck = fetchedAt             // the record is behind the window now
func NewPollWindowAdvancedPastLoggedFailureRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"poll-window-advanced-past-logged-failure",
			"patterns",
			"Detects a poll that hands the fetched records to a helper without an error result, which only logs a failed write, and then moves the window start on — the failed record is never fetched again",
			core.SeverityMedium,
		),
		suggestion: "Return the write failures from the helper (errors.Join) and keep the window where it was when one failed: the next tick fetches the record again",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		for _, window := range pollWindows(scope.info, fn) {
			if len(window.advances) == 0 {
				continue
			}
			last := window.advances[len(window.advances)-1]
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				stmt, ok := n.(*ast.ExprStmt)
				if !ok || stmt.Pos() < window.fetch.End() || stmt.Pos() > last.Pos() {
					return true
				}
				call, ok := stmt.X.(*ast.CallExpr)
				if !ok || !takesAny(scope.info, call, window.fetched) {
					return true
				}
				if decl, ok := scope.callee(call); ok && !returnsErrorResult(decl.info, decl.decl) && logsFailedWrite(scope, decl, pollWindowDepth) {
					findings = append(findings, funcFinding{node: call, message: callName(call) + " gets the fetched records and only logs a failed write, and the poll then moves " + window.field.Name() + " on — the failed record is behind the window and never fetched again"})
				}
				return true
			})
		}
		return findings
	}
	return r
}

// pollWindow is a time.Time field a function fetches from and moves on.
type pollWindow struct {
	field *types.Var
	// fetch is the call handed a time derived from the field.
	fetch *ast.CallExpr
	// fetched are the variables holding what the fetch returned.
	fetched map[types.Object]bool
	// advances are the assignments of the field after the fetch.
	advances []*ast.AssignStmt
}

// pollWindows returns the time.Time fields of fn's receiver that a call
// taking a context is handed (directly or through locals derived from the
// field) and that fn assigns after that call.
func pollWindows(info *types.Info, fn *ast.FuncDecl) []pollWindow {
	if fn.Body == nil || fn.Recv == nil {
		return nil
	}
	var windows []pollWindow
	seen := make(map[*types.Var]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		field, ok := info.ObjectOf(sel.Sel).(*types.Var)
		if !ok || !field.IsField() || seen[field] || !isNamedType(field.Type(), "time", "Time") {
			return true
		}
		seen[field] = true
		if window, ok := pollWindowOf(info, fn.Body, field); ok {
			windows = append(windows, window)
		}
		return true
	})
	return windows
}

// pollWindowOf finds the fetch from field in body and the assignments of the
// field after it.
func pollWindowOf(info *types.Info, body *ast.BlockStmt, field *types.Var) (pollWindow, bool) {
	derived := make(map[types.Object]bool)
	window := pollWindow{field: field, fetched: make(map[types.Object]bool)}
	readsField := func(expr ast.Expr) bool {
		found := false
		ast.Inspect(expr, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				found = found || info.ObjectOf(node.Sel) == field
			case *ast.Ident:
				found = found || derived[info.ObjectOf(node)]
			}
			return !found
		})
		return found
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			if window.fetch == nil {
				if call, ok := ast.Unparen(node.Rhs[0]).(*ast.CallExpr); ok && len(node.Rhs) == 1 && isFetchFrom(info, call, readsField) {
					window.fetch = call
					for _, lhs := range node.Lhs {
						if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
							window.fetched[info.ObjectOf(id)] = true
						}
					}
					return true
				}
				noteDerived(info, node, readsField, derived)
			}
			if window.fetch != nil && node.Pos() > window.fetch.End() && len(node.Lhs) == 1 && len(node.Rhs) == 1 && node.Tok == token.ASSIGN {
				if sel, ok := node.Lhs[0].(*ast.SelectorExpr); ok && info.ObjectOf(sel.Sel) == field {
					window.advances = append(window.advances, node)
				}
			}
		case *ast.CallExpr:
			if window.fetch == nil && isFetchFrom(info, node, readsField) {
				window.fetch = node
			}
		}
		return true
	})
	return window, window.fetch != nil && len(window.advances) > 0
}

// noteDerived adds to derived the locals an assignment sets from an
// expression that reads the field or a local derived from it.
func noteDerived(info *types.Info, assign *ast.AssignStmt, readsField func(ast.Expr) bool, derived map[types.Object]bool) {
	for _, rhs := range assign.Rhs {
		if !readsField(rhs) {
			continue
		}
		for _, lhs := range assign.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
				derived[info.ObjectOf(id)] = true
			}
		}
	}
}

// isFetchFrom reports a call handed a context and a time.Time argument that
// reads the window field.
func isFetchFrom(info *types.Info, call *ast.CallExpr, readsField func(ast.Expr) bool) bool {
	if !takesContext(info, call) {
		return false
	}
	for _, arg := range call.Args {
		if isNamedType(info.TypeOf(arg), "time", "Time") && readsField(arg) {
			return true
		}
	}
	return false
}

// isTimeNow reports time.Now() and a method chain on it (time.Now().UTC()).
func isTimeNow(expr ast.Expr) bool {
	for {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "time" && sel.Sel.Name == "Now" {
			return true
		}
		expr = sel.X
	}
}

// takesAny reports a call handed an argument that reads one of objs.
func takesAny(info *types.Info, call *ast.CallExpr, objs map[types.Object]bool) bool {
	for _, arg := range call.Args {
		found := false
		ast.Inspect(arg, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && objs[info.ObjectOf(id)] {
				found = true
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

// logsFailedWrite reports a function body that checks the error of a write
// call and only logs it - `if err != nil { log; return }` with no error
// result - directly or in the functions it calls, within depth calls.
func logsFailedWrite(scope funcScope, decl typedFuncDecl, depth int) bool {
	writeErrs := make(map[types.Object]bool)
	found := false
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			noteWriteErrs(decl.info, node, writeErrs)
		case *ast.IfStmt:
			if init, ok := node.Init.(*ast.AssignStmt); ok {
				noteWriteErrs(decl.info, init, writeErrs)
			}
			if name, ok := errNotNilName(node.Cond); ok && writeErrs[errObjectNamed(decl.info, node.Cond, name)] && onlyLogsAndLeaves(node.Body) {
				found = true
			}
		case *ast.CallExpr:
			if inner, ok := (funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}).callee(node); ok && depth > 1 &&
				!returnsErrorResult(inner.info, inner.decl) && logsFailedWrite(scope, inner, depth-1) {
				found = true
			}
		}
		return !found
	})
	return found
}

// noteWriteErrs adds the error variables an assignment sets from a write
// call (RecordTransfer, Save, Insert).
func noteWriteErrs(info *types.Info, assign *ast.AssignStmt, writeErrs map[types.Object]bool) {
	if len(assign.Rhs) != 1 {
		return
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok || !helpers.IsWriteName(callName(call)) {
		return
	}
	for _, lhs := range assign.Lhs {
		if id, ok := lhs.(*ast.Ident); ok {
			if v, isVar := info.ObjectOf(id).(*types.Var); isVar && implementsError(v.Type()) {
				writeErrs[v] = true
			}
		}
	}
}

// errObjectNamed returns the object of the identifier name in cond.
func errObjectNamed(info *types.Info, cond ast.Expr, name string) types.Object {
	var obj types.Object
	ast.Inspect(cond, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			obj = info.ObjectOf(id)
		}
		return obj == nil
	})
	return obj
}

// onlyLogsAndLeaves reports a block of logger calls ending in a bare return
// or a continue.
func onlyLogsAndLeaves(body *ast.BlockStmt) bool {
	if len(body.List) < 2 {
		return false
	}
	for _, stmt := range body.List[:len(body.List)-1] {
		if !isLoggerStmt(stmt) {
			return false
		}
	}
	switch last := body.List[len(body.List)-1].(type) {
	case *ast.ReturnStmt:
		return len(last.Results) == 0
	case *ast.BranchStmt:
		return last.Tok == token.CONTINUE
	}
	return false
}
