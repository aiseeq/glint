package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSnapshotAppendedAndRewrittenRule())
}

// NewSnapshotAppendedAndRewrittenRule reports records appended to a list
// loaded from a file earlier (a field or a parameter) and written back whole
// by a function that neither re-reads the file nor locks it: a second process
// that loaded the same file before this write loses its records.
func NewSnapshotAppendedAndRewrittenRule() *typedFuncRule {
	return newFuncRule("snapshot-appended-and-rewritten",
		"Detects a list loaded from a file earlier (a field or a parameter), appended to and written back whole by a function that neither re-reads the file nor locks it — two processes that loaded the same file keep only the last writer's records",
		core.SeverityMedium,
		"Re-read the file under a lock (flock) right before appending and writing, or append the record to the file (O_APPEND) instead of rewriting a snapshot",
		snapshotAppendedAndRewritten)
}

func snapshotAppendedAndRewritten(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	if fn.Body == nil {
		return nil
	}
	outer := receiverAndParams(scope.info, fn)
	appended := appendedHolders(scope.info, fn)
	var out []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		writer, ok := scope.callee(call)
		if !ok || !rewritesFile(scope, writer, 2) {
			return true
		}
		for _, data := range callData(call) {
			if loaded := loadedSnapshot(scope, outer, appended, data); loaded != "" {
				out = append(out, funcFinding{node: call, message: loaded + " was loaded from the file earlier and is written back whole with the new record — a process that loaded the same file meanwhile loses its records, the last writer wins"})
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
func loadedSnapshot(scope funcScope, outer map[types.Object]bool, appended map[types.Object]ast.Expr, data ast.Expr) string {
	data = ast.Unparen(data)
	if call, ok := data.(*ast.CallExpr); ok && addsRecord(scope.info, call) {
		list := ast.Unparen(call.Args[0])
		if root := rootObject(scope.info, list); root != nil && outer[root] && fileLoaderOf(scope, scope.info.TypeOf(list)) {
			return types.ExprString(list)
		}
		return ""
	}
	id, ok := data.(*ast.Ident)
	if !ok {
		return ""
	}
	obj := scope.info.Uses[id]
	list, ok := appended[obj]
	if !ok || !outer[obj] || !fileLoaderOf(scope, obj.Type()) {
		return ""
	}
	return types.ExprString(list)
}

// rootObject returns the variable a selector chain starts from: s in s.hist.
func rootObject(info *types.Info, e ast.Expr) types.Object {
	for {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			return info.Uses[x]
		case *ast.SelectorExpr:
			e = x.X
		default:
			return nil
		}
	}
}

// addsRecord reports append(list, x...): a record added to a list.
func addsRecord(info *types.Info, e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	return ok && len(call.Args) >= 2 && isAppendCall(call, info)
}

// rewritesFile reports a function that writes a file whole (os.WriteFile,
// os.Create, os.OpenFile without O_APPEND), itself or through the functions
// it calls, and neither reads a file nor takes a lock on the way.
func rewritesFile(scope funcScope, decl typedFuncDecl, depth int) bool {
	if decl.decl.Body == nil {
		return false
	}
	writes, guarded := false, false
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case calleeIn(call, decl.info, "os", "WriteFile", "Create"):
			writes = true
		case calleeIn(call, decl.info, "os", "OpenFile"):
			writes = writes || !strings.Contains(types.ExprString(call), "O_APPEND")
		case calleeIn(call, decl.info, "os", "ReadFile", "Open") || locksFile(decl.info, call):
			guarded = true
		default:
			if inner, ok := scope.callee(call); ok && depth > 0 && rewritesFile(scope, inner, depth-1) {
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
	fn := staticFunc(info, call)
	return fn != nil && strings.Contains(strings.ToLower(fn.Name()), "lock") && fn.Name() != "Unlock"
}

// fileLoaderOf reports a function of the project that reads a file and
// returns a value of the type.
func fileLoaderOf(scope funcScope, t types.Type) bool {
	if t == nil {
		return false
	}
	for fn, decl := range scope.decls {
		if !returnsType(fn, t) || decl.decl.Body == nil {
			continue
		}
		reads := false
		ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && calleeIn(call, decl.info, "os", "ReadFile", "Open") {
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
	for i := range sig.Results().Len() {
		if types.Identical(sig.Results().At(i).Type(), t) {
			return true
		}
	}
	return false
}
