package dbrules

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewSnapshotAppendedAndRewrittenRule())
}

// NewSnapshotAppendedAndRewrittenRule reports records appended to a list
// loaded from a file earlier (a field or a parameter) and written back whole
// by a function that neither re-reads the file nor locks it: a second process
// that loaded the same file before this write loses its records.
func NewSnapshotAppendedAndRewrittenRule() *patternkit.TypedFuncRule {
	return patternkit.NewFuncRule("snapshot-appended-and-rewritten",
		"Detects a list loaded from a file earlier (a field or a parameter), appended to and written back whole by a function that neither re-reads the file nor locks it — two processes that loaded the same file keep only the last writer's records",
		core.SeverityMedium,
		"Re-read the file under a lock (flock) right before appending and writing, or append the record to the file (O_APPEND) instead of rewriting a snapshot",
		snapshotAppendedAndRewritten)
}

func snapshotAppendedAndRewritten(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
	if fn.Body == nil {
		return nil
	}
	outer := receiverAndParams(scope.Info, fn)
	appended := appendedHolders(scope.Info, fn)
	var out []patternkit.FuncFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		writer, ok := scope.Callee(call)
		if !ok || !rewritesFile(scope, writer, 2) {
			return true
		}
		for _, data := range callData(call) {
			if loaded := loadedSnapshot(scope, outer, appended, data); loaded != "" {
				out = append(out, patternkit.FuncFinding{Node: call, Message: loaded + " was loaded from the file earlier and is written back whole with the new record — a process that loaded the same file meanwhile loses its records, the last writer wins"})
				break
			}
		}
		return true
	})
	return out
}

// receiverAndParams returns the receiver and the parameters of a function:
// values loaded before it runs.
func receiverAndParams(info *types.Info, fn *ast.FuncDecl) map[types.Object]bool {
	out := map[types.Object]bool{}
	for _, list := range []*ast.FieldList{fn.Recv, fn.Type.Params} {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			for _, name := range field.Names {
				if obj := info.Defs[name]; obj != nil {
					out[obj] = true
				}
			}
		}
	}
	return out
}

// appendedHolders returns the values whose list the function appends to in
// place: hist in hist.Matches = append(hist.Matches, rec).
func appendedHolders(info *types.Info, fn *ast.FuncDecl) map[types.Object]ast.Expr {
	out := map[types.Object]ast.Expr{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || !addsRecord(info, assign.Rhs[0]) {
			return true
		}
		if sel, ok := ast.Unparen(assign.Lhs[0]).(*ast.SelectorExpr); ok {
			if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok && info.Uses[id] != nil {
				out[info.Uses[id]] = sel
			}
		}
		return true
	})
	return out
}

// callData returns what a call hands over: its arguments and the receiver of
// a method.
func callData(call *ast.CallExpr) []ast.Expr {
	data := append([]ast.Expr{}, call.Args...)
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		data = append(data, sel.X)
	}
	return data
}

// loadedSnapshot names the loaded list a written value carries with an
// appended record: append(s.hist, rec) of a field or a parameter, or a
// parameter whose list the function appended to; "" for anything else.
func loadedSnapshot(scope patternkit.FuncScope, outer map[types.Object]bool, appended map[types.Object]ast.Expr, data ast.Expr) string {
	data = ast.Unparen(data)
	if call, ok := data.(*ast.CallExpr); ok && addsRecord(scope.Info, call) {
		list := ast.Unparen(call.Args[0])
		if root := patternkit.RootObject(scope.Info, list); root != nil && outer[root] && fileLoaderOf(scope, scope.Info.TypeOf(list)) {
			return types.ExprString(list)
		}
		return ""
	}
	id, ok := data.(*ast.Ident)
	if !ok {
		return ""
	}
	obj := scope.Info.Uses[id]
	list, ok := appended[obj]
	if !ok || !outer[obj] || !fileLoaderOf(scope, obj.Type()) {
		return ""
	}
	return types.ExprString(list)
}

// addsRecord reports append(list, x...): a record added to a list.
func addsRecord(info *types.Info, e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	return ok && len(call.Args) >= 2 && patternkit.IsAppendCall(call, info)
}

// rewritesFile reports a function that writes a file whole (os.WriteFile,
// os.Create, os.OpenFile without O_APPEND), itself or through the functions
// it calls, and neither reads a file nor takes a lock on the way.
func rewritesFile(scope patternkit.FuncScope, decl patternkit.TypedFuncDecl, depth int) bool {
	if decl.Decl.Body == nil {
		return false
	}
	writes, guarded := false, false
	ast.Inspect(decl.Decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case patternkit.CalleeIn(call, decl.Info, "os", "WriteFile", "Create"):
			writes = true
		case patternkit.CalleeIn(call, decl.Info, "os", "OpenFile"):
			writes = writes || !strings.Contains(types.ExprString(call), "O_APPEND")
		case patternkit.CalleeIn(call, decl.Info, "os", "ReadFile", "Open") || locksFile(decl.Info, call):
			guarded = true
		default:
			if inner, ok := scope.Callee(call); ok && depth > 0 && rewritesFile(scope, inner, depth-1) {
				writes = true
			}
		}
		return true
	})
	return writes && !guarded
}

// locksFile reports a call of flock, LockFileEx or a Lock method of a file
// lock.
func locksFile(info *types.Info, call *ast.CallExpr) bool {
	fn := patternkit.StaticFunc(info, call)
	return fn != nil && strings.Contains(strings.ToLower(fn.Name()), "lock") && fn.Name() != "Unlock"
}

// fileLoaderOf reports a function of the project that reads a file and
// returns a value of the type.
func fileLoaderOf(scope patternkit.FuncScope, t types.Type) bool {
	if t == nil {
		return false
	}
	for fn, decl := range scope.Decls {
		if !returnsType(fn, t) || decl.Decl.Body == nil {
			continue
		}
		reads := false
		ast.Inspect(decl.Decl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && patternkit.CalleeIn(call, decl.Info, "os", "ReadFile", "Open") {
				reads = true
			}
			return !reads
		})
		if reads {
			return true
		}
	}
	return false
}

func returnsType(fn *types.Func, t types.Type) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	for v := range sig.Results().Variables() {
		if types.Identical(v.Type(), t) {
			return true
		}
	}
	return false
}
