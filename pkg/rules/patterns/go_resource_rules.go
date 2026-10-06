package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/types/typeutil"
)

func init() {
	rules.Register(NewDeferredCloseOfWrittenFileRule())
	rules.Register(NewRandIndexOfFilteredSliceRule())
	rules.Register(NewWriteFileWithoutOwnerWriteRule())
	rules.Register(NewSprintOfAnyMapEntryRule())
	rules.Register(NewErrorLoggedAtInfoRule())
	rules.Register(NewBatchStatusResultsDroppedRule())
	rules.Register(NewFixedTempNameRenamedRule())
}

func newFuncRule(name, description string, severity core.Severity, suggestion string, check func(scope funcScope, fn *ast.FuncDecl) []funcFinding) *typedFuncRule {
	return &typedFuncRule{
		BaseRule:   rules.NewBaseRule(name, "patterns", description, severity),
		suggestion: suggestion,
		check:      check,
	}
}

// returnsErrorResult reports whether the function's last result is an error.
func returnsErrorResult(info *types.Info, fn *ast.FuncDecl) bool {
	results := fn.Type.Results
	if results == nil || len(results.List) == 0 {
		return false
	}
	last := results.List[len(results.List)-1]
	return isErrorType(info.TypeOf(last.Type))
}

// calleeIn reports whether the call is to one of the named functions of the
// package path, a method of a type of that package included.
func calleeIn(call *ast.CallExpr, info *types.Info, pkgPath string, names ...string) bool {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != pkgPath {
		return false
	}
	for _, name := range names {
		if fn.Name() == name {
			return true
		}
	}
	return false
}

// NewDeferredCloseOfWrittenFileRule reports a file opened for writing and
// closed only by a bare defer f.Close():
//
//	f, err := os.Create(out)
//	defer f.Close()
//	if err := png.Encode(f, img); err != nil { ... }
//	return nil
//
// Close is where buffered data reaches the disk and where a full disk or a
// failed network file system reports. The deferred call drops that error and
// the function reports success for a truncated file.
func NewDeferredCloseOfWrittenFileRule() *typedFuncRule {
	return newFuncRule("deferred-close-of-written-file",
		"Detects a file opened for writing and closed only by a bare defer Close — the error of the final write is lost and a truncated file counts as written",
		core.SeverityMedium,
		"Return the Close error: close explicitly at the end (return f.Close()), or check it in a deferred func that sets the named error result",
		deferredCloseOfWrittenFile)
}

func deferredCloseOfWrittenFile(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	if !returnsErrorResult(info, fn) {
		return nil
	}
	var found []funcFinding
	for _, file := range writtenFiles(info, fn) {
		deferred, checked := fileCloses(fn.Body, file, info)
		if deferred != nil && !checked {
			found = append(found, funcFinding{deferred, "File " + file.Name() + " is written and closed only by a bare defer — the error Close reports for the final write is dropped, and a truncated file counts as written"})
		}
	}
	return found
}

// writtenFiles returns the variables that take a file opened for writing:
// os.Create, os.CreateTemp, or os.OpenFile with a write flag.
func writtenFiles(info *types.Info, fn *ast.FuncDecl) []types.Object {
	var files []types.Object
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || !opensForWriting(call, info) {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
			if obj := info.ObjectOf(ident); obj != nil {
				files = append(files, obj)
			}
		}
		return true
	})
	return files
}

func opensForWriting(call *ast.CallExpr, info *types.Info) bool {
	if calleeIn(call, info, "os", "Create", "CreateTemp") {
		return true
	}
	if !calleeIn(call, info, "os", "OpenFile") || len(call.Args) < 2 {
		return false
	}
	flags := types.ExprString(call.Args[1])
	for _, flag := range []string{"O_WRONLY", "O_RDWR", "O_APPEND", "O_CREATE", "O_TRUNC"} {
		if strings.Contains(flags, flag) {
			return true
		}
	}
	return false
}

// fileCloses finds a bare defer file.Close() and whether the function also
// learns the outcome of the close or of a sync: a Close or Sync call outside a
// bare defer statement - returned, assigned or tested.
func fileCloses(body *ast.BlockStmt, file types.Object, info *types.Info) (*ast.DeferStmt, bool) {
	var deferred *ast.DeferStmt
	checked := false
	ast.Inspect(body, func(n ast.Node) bool {
		if stmt, ok := n.(*ast.DeferStmt); ok && isMethodOn(stmt.Call, file, info, "Close") {
			if deferred == nil {
				deferred = stmt
			}
			return false
		}
		if stmt, ok := n.(*ast.ExprStmt); ok {
			if call, ok := ast.Unparen(stmt.X).(*ast.CallExpr); ok && isMethodOn(call, file, info, "Close") {
				return false // a bare f.Close() drops the error just the same
			}
		}
		if call, ok := n.(*ast.CallExpr); ok && (isMethodOn(call, file, info, "Close") || isMethodOn(call, file, info, "Sync")) {
			checked = true
		}
		return true
	})
	return deferred, checked
}

// isMethodOn reports whether the call is obj.method().
func isMethodOn(call *ast.CallExpr, obj types.Object, info *types.Info, method string) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != method {
		return false
	}
	ident, ok := ast.Unparen(selector.X).(*ast.Ident)
	return ok && info.ObjectOf(ident) == obj
}

// NewRandIndexOfFilteredSliceRule reports a random index drawn over a slice
// that a filtering loop may leave empty:
//
//	for _, t := range pool { if t == banned { continue }; best = append(best, t) }
//	return best[rnd.Intn(len(best))]   // Intn(0) panics
func NewRandIndexOfFilteredSliceRule() *typedFuncRule {
	return newFuncRule("rand-index-of-filtered-slice",
		"Detects rand.Intn(len(x)) over a slice a filtering loop may leave empty — Intn(0) panics",
		core.SeverityHigh,
		"Check len(x) == 0 before drawing and decide what an empty choice means",
		randIndexOfFilteredSlice)
}

var randIntFuncs = map[string]bool{"Intn": true, "IntN": true, "N": true, "Int31n": true, "Int63n": true, "Int32N": true, "Int64N": true, "UintN": true, "Uint32N": true, "Uint64N": true}

func randIndexOfFilteredSlice(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		callee, ok := typeutil.Callee(info, call).(*types.Func)
		if !ok || callee.Pkg() == nil || !randIntFuncs[callee.Name()] {
			return true
		}
		if path := callee.Pkg().Path(); path != "math/rand" && path != "math/rand/v2" {
			return true
		}
		slice := lenOfIdent(call.Args[0], info)
		if slice == nil {
			return true
		}
		obj := info.ObjectOf(slice)
		if obj == nil || !filteredOnly(fn.Body, obj, info) || comparesLength(fn.Body, obj, info) {
			return true
		}
		found = append(found, funcFinding{call, "Random index over " + slice.Name + ", which a filtering loop may leave empty — with no candidate left the draw panics (Intn(0))"})
		return true
	})
	return found
}

// lenOfIdent returns x of len(x), through a conversion.
func lenOfIdent(expr ast.Expr, info *types.Info) *ast.Ident {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil
	}
	if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
		return lenOfIdent(call.Args[0], info)
	}
	if !isIdent(call.Fun, "len") {
		return nil
	}
	ident, _ := ast.Unparen(call.Args[0]).(*ast.Ident)
	return ident
}

// filteredOnly reports whether every append to the slice is made inside a
// loop under a condition - an if, or after a continue - so the loop may add
// nothing.
func filteredOnly(body *ast.BlockStmt, obj types.Object, info *types.Info) bool {
	filtered, unconditional := false, false
	var walk func(n ast.Node, inLoop, conditional bool)
	walk = func(n ast.Node, inLoop, conditional bool) {
		ast.Inspect(n, func(node ast.Node) bool {
			switch stmt := node.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ForStmt:
				walk(stmt.Body, true, conditional || hasContinue(stmt.Body))
				return false
			case *ast.RangeStmt:
				walk(stmt.Body, true, conditional || hasContinue(stmt.Body))
				return false
			case *ast.IfStmt:
				walk(stmt.Body, inLoop, inLoop || conditional)
				if stmt.Else != nil {
					walk(stmt.Else, inLoop, inLoop || conditional)
				}
				return false
			case *ast.AssignStmt:
				if appendAssigns(stmt, obj, info) {
					if inLoop && conditional {
						filtered = true
					} else {
						unconditional = true
					}
				}
			}
			return true
		})
	}
	walk(body, false, false)
	return filtered && !unconditional
}

func hasContinue(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit, *ast.ForStmt, *ast.RangeStmt:
			return false
		case *ast.BranchStmt:
			if node.Tok == token.CONTINUE && node.Label == nil {
				found = true
			}
		}
		return !found
	})
	return found
}

// appendAssigns reports whether the assignment is x = append(x, ...) for obj.
func appendAssigns(assign *ast.AssignStmt, obj types.Object, info *types.Info) bool {
	if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return false
	}
	ident, ok := assign.Lhs[0].(*ast.Ident)
	if !ok || info.ObjectOf(ident) != obj {
		return false
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	return ok && isIdent(call.Fun, "append")
}

// comparesLength reports whether the function tests the slice for being
// empty: any comparison of len(x) or of x with nil.
func comparesLength(body *ast.BlockStmt, obj types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		binary, ok := n.(*ast.BinaryExpr)
		if !ok || !isComparison(binary.Op) {
			return !found
		}
		for _, side := range []ast.Expr{binary.X, binary.Y} {
			if ident := lenOfIdent(side, info); ident != nil && info.ObjectOf(ident) == obj {
				found = true
			}
			if ident, ok := ast.Unparen(side).(*ast.Ident); ok && info.ObjectOf(ident) == obj {
				found = true
			}
		}
		return !found
	})
	return found
}

// NewWriteFileWithoutOwnerWriteRule reports a file written with a mode that
// does not let its owner write it:
//
//	return os.WriteFile(path, data, 0o444)
//
// The first run creates the file read-only; every later run fails to open it
// for writing with permission denied.
func NewWriteFileWithoutOwnerWriteRule() *typedFuncRule {
	return newFuncRule("write-file-without-owner-write",
		"Detects os.WriteFile or os.OpenFile(O_CREATE) with a mode lacking the owner write bit — the next write of the same path fails with permission denied",
		core.SeverityMedium,
		"Remove the previous file before writing it again (os.Remove, ignoring fs.ErrNotExist), or write a temporary file and rename it into place",
		writeFileWithoutOwnerWrite)
}

func writeFileWithoutOwnerWrite(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 3 {
			return true
		}
		switch {
		case calleeIn(call, info, "os", "WriteFile"):
		case calleeIn(call, info, "os", "OpenFile") && strings.Contains(types.ExprString(call.Args[1]), "O_CREATE"):
		default:
			return true
		}
		mode, ok := constantInt(info, call.Args[2])
		if !ok || mode&0o200 != 0 || replacedBefore(fn.Body, call, info) {
			return true
		}
		found = append(found, funcFinding{call, "File is written with a mode its owner cannot write — the next write of the same path fails with permission denied"})
		return true
	})
	return found
}

// replacedBefore reports whether the function removes the path, or changes
// its mode, before the write.
func replacedBefore(body *ast.BlockStmt, write *ast.CallExpr, info *types.Info) bool {
	path := types.ExprString(write.Args[0])
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found || call.Pos() >= write.Pos() || len(call.Args) == 0 {
			return !found
		}
		if calleeIn(call, info, "os", "Remove", "RemoveAll", "Chmod") && types.ExprString(call.Args[0]) == path {
			found = true
		}
		return !found
	})
	return found
}

// NewSprintOfAnyMapEntryRule reports text made with fmt.Sprint of an entry of
// a map of interface values, without checking that the key is there:
//
//	queue(fmt.Sprint(ev["session_id"]))
//
// A missing key gives nil, and fmt prints it as "<nil>": the code goes on
// with that text as a session id, a path or a name.
func NewSprintOfAnyMapEntryRule() *typedFuncRule {
	return newFuncRule("sprint-of-any-map-entry",
		"Detects fmt.Sprint of a map[string]any entry used as a value without a comma-ok check — a missing key becomes the text \"<nil>\"",
		core.SeverityMedium,
		"Read the entry with v, ok := m[key] and a type assertion to string, and fail when it is missing",
		sprintOfAnyMapEntry)
}

func sprintOfAnyMapEntry(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	compared := map[ast.Expr]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if binary, ok := n.(*ast.BinaryExpr); ok && isComparison(binary.Op) {
			compared[ast.Unparen(binary.X)] = true
			compared[ast.Unparen(binary.Y)] = true
		}
		return true
	})
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || compared[call] {
			return true
		}
		args := call.Args
		switch {
		case calleeIn(call, info, "fmt", "Sprint", "Sprintln"):
		case calleeIn(call, info, "fmt", "Sprintf") && len(args) == 2 && isVerbOnly(args[0], info):
			args = args[1:]
		default:
			return true
		}
		for _, arg := range args {
			if entry := anyMapEntry(arg, info); entry != "" {
				found = append(found, funcFinding{call, "Text of " + entry + " is taken without checking the key is there — a missing key gives nil, printed as \"<nil>\", and that text goes on as a value"})
				break
			}
		}
		return true
	})
	return found
}

func isVerbOnly(expr ast.Expr, info *types.Info) bool {
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	format := constant.StringVal(tv.Value)
	return format == "%v" || format == "%s"
}

// anyMapEntry returns the spelling of m[k] when m maps to an interface type.
func anyMapEntry(expr ast.Expr, info *types.Info) string {
	index, ok := ast.Unparen(expr).(*ast.IndexExpr)
	if !ok {
		return ""
	}
	mapType, ok := typeOrNil(info, index.X).Underlying().(*types.Map)
	if !ok || !types.IsInterface(mapType.Elem()) {
		return ""
	}
	return types.ExprString(index)
}

// NewErrorLoggedAtInfoRule reports an error a function that returns errors
// only logs at Info level:
//
//	if err := scanSide(...); err != nil {
//	    slog.Info("enemy side", "err", err)
//	}
//
// The function tells its caller about other failures, but this one goes to a
// level nobody watches for failures, and the caller takes the run as complete.
func NewErrorLoggedAtInfoRule() *typedFuncRule {
	return newFuncRule("error-logged-at-info",
		"Detects an error that a function returning errors only logs at Info — the failure goes to a level nobody watches, and the caller takes the work as done",
		core.SeverityMedium,
		"Return the error (wrapped), or log it at Warn/Error when the step is optional by design",
		errorLoggedAtInfo)
}

func errorLoggedAtInfo(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	if !returnsErrorResult(info, fn) || !returnsSomeError(fn) {
		return nil
	}
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Else != nil || len(ifStmt.Body.List) == 0 {
			return true
		}
		errObj := errorNotNilObj(ifStmt.Cond, info)
		if errObj == nil || isTeardownInit(ifStmt.Init) {
			return true
		}
		for _, stmt := range ifStmt.Body.List {
			if !isInfoLogOf(stmt, errObj, info) {
				return true
			}
		}
		found = append(found, funcFinding{ifStmt, "Error " + errObj.Name() + " is only logged at Info in a function that returns errors — the failure goes to a level nobody watches, and the caller takes the work as done"})
		return true
	})
	return found
}

// teardownPrefixes name the calls that wind down work already done: their
// failure leaves the result intact, and an Info line is enough.
var teardownPrefixes = []string{"Close", "Leave", "Quit", "Stop", "Shutdown", "Disconnect", "Cancel", "Remove", "Cleanup", "Release", "Unlock"}

// isTeardownInit reports whether the if's init takes the error of a teardown
// call: if err := c.LeaveGame(ctx); err != nil.
func isTeardownInit(init ast.Stmt) bool {
	assign, ok := init.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		return false
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	name := ""
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		name = fun.Sel.Name
	case *ast.Ident:
		name = fun.Name
	}
	for _, prefix := range teardownPrefixes {
		if strings.HasPrefix(name, prefix) || strings.HasPrefix(name, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

// returnsSomeError reports whether the function returns a non-nil error on
// some path: it does tell its callers about failures.
func returnsSomeError(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return !found
		}
		if last := ret.Results[len(ret.Results)-1]; !isNilIdent(last) {
			found = true
		}
		return !found
	})
	return found
}

// errorNotNilObj returns the error variable of a condition err != nil.
func errorNotNilObj(cond ast.Expr, info *types.Info) types.Object {
	binary, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || binary.Op != token.NEQ || !isNilIdent(binary.Y) {
		return nil
	}
	ident, ok := ast.Unparen(binary.X).(*ast.Ident)
	if !ok || !isErrorType(info.TypeOf(ident)) {
		return nil
	}
	return info.ObjectOf(ident)
}

// isInfoLogOf reports whether the statement logs the error at Info level:
// slog.Info, a logger's Info/Infof/Infow, log.Printf is not one (it has no
// level).
func isInfoLogOf(stmt ast.Stmt, errObj types.Object, info *types.Info) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := ast.Unparen(expr.X).(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch selector.Sel.Name {
	case "Info", "Infof", "Infow", "Infoln", "InfoContext":
	default:
		return false
	}
	for _, arg := range call.Args {
		used := false
		ast.Inspect(arg, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && info.ObjectOf(ident) == errObj {
				used = true
			}
			return !used
		})
		if used {
			return true
		}
	}
	return false
}

// NewBatchStatusResultsDroppedRule reports a batch call whose per-item
// statuses are dropped while only its error is checked:
//
//	if _, err := c.Action(ctx, acts); err != nil { ... }
//
// The call succeeds as a whole when the transport does; the items the other
// side refused are reported only in the dropped slice.
func NewBatchStatusResultsDroppedRule() *typedFuncRule {
	return newFuncRule("batch-status-results-dropped",
		"Detects a call returning a slice of status values and an error with the slice dropped — items the other side refused pass as done",
		core.SeverityMedium,
		"Read the statuses and handle the items that did not succeed",
		batchStatusResultsDropped)
}

func batchStatusResultsDropped(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 || !isBlank(assign.Lhs[0]) {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		tuple, ok := info.TypeOf(call).(*types.Tuple)
		if !ok || tuple.Len() != 2 || !isErrorType(tuple.At(1).Type()) {
			return true
		}
		slice, ok := tuple.At(0).Type().Underlying().(*types.Slice)
		if !ok || !isStatusEnum(slice.Elem()) {
			return true
		}
		found = append(found, funcFinding{call, "Statuses of the items (" + types.TypeString(slice.Elem(), packageName) + ") are dropped and only the error is checked — items the other side refused pass as done"})
		return true
	})
	return found
}

// isStatusEnum reports whether the type is a named integer type its package
// declares at least two constants of: an enumeration of outcomes.
func isStatusEnum(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	basic, ok := named.Underlying().(*types.Basic)
	if !ok || basic.Info()&types.IsInteger == 0 {
		return false
	}
	scope := named.Obj().Pkg().Scope()
	count := 0
	for _, name := range scope.Names() {
		if c, ok := scope.Lookup(name).(*types.Const); ok && types.Identical(c.Type(), named) {
			count++
		}
	}
	return count >= 2
}

// packageName qualifies a type by the name of its package.
func packageName(pkg *types.Package) string { return pkg.Name() }

// NewFixedTempNameRenamedRule reports a temp file named after its target
// with a fixed suffix, written and renamed onto the target:
//
//	tmp := dst + ".part"
//	f, err := os.Create(tmp)
//	...
//	return os.Rename(tmp, dst)
//
// Two writers of one target share the temp name: the second truncates the
// first one's file, and the first renames a half-written file into place.
func NewFixedTempNameRenamedRule() *typedFuncRule {
	return newFuncRule("fixed-temp-name-renamed",
		"Detects a temp file named target+\".tmp\" (a fixed suffix), written and renamed onto the target — two writers of one target truncate each other's temp file, and one renames a half-written file into place",
		core.SeverityMedium,
		"Create the temp file with a unique name next to the target: os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+\".*.tmp\"), then rename f.Name()",
		fixedTempNameRenamed)
}

// tempSuffixes are the fixed endings a temp file name is made of.
var tempSuffixes = []string{".tmp", ".part", ".partial", ".new", ".temp", "~"}

func fixedTempNameRenamed(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	if holdsLock(fn.Body) {
		return nil
	}
	// The temp names: variables assigned a fixed-suffix name, and the names
	// written inline, by their text.
	named := make(map[types.Object]ast.Node)
	inline := make(map[string]ast.Node)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			if len(v.Lhs) == 1 && len(v.Rhs) == 1 && fixedTempName(v.Rhs[0], info) {
				if ident, ok := v.Lhs[0].(*ast.Ident); ok {
					if obj := info.ObjectOf(ident); obj != nil {
						named[obj] = v
					}
				}
			}
		case *ast.CallExpr:
			if calleeIn(v, info, "os", "Create", "WriteFile", "OpenFile") && len(v.Args) > 0 && fixedTempName(v.Args[0], info) {
				inline[types.ExprString(v.Args[0])] = v
			}
		}
		return true
	})
	if len(named) == 0 && len(inline) == 0 {
		return nil
	}
	written := make(map[ast.Node]bool)
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		site := tempSite(call.Args[0], info, named, inline)
		switch {
		case site == nil:
		case calleeIn(call, info, "os", "Create", "WriteFile", "OpenFile"):
			written[site] = true
		case calleeIn(call, info, "os", "Rename") && written[site]:
			found = append(found, funcFinding{site, "The temp file is the target's name with a fixed suffix — two writers of one target truncate each other's temp file, and one renames a half-written file into place"})
			written[site] = false
		}
		return true
	})
	return found
}

// tempSite returns the statement that names a temp path: the assignment of
// a variable, or the first inline write of the same text.
func tempSite(arg ast.Expr, info *types.Info, named map[types.Object]ast.Node, inline map[string]ast.Node) ast.Node {
	if ident, ok := ast.Unparen(arg).(*ast.Ident); ok {
		return named[info.ObjectOf(ident)]
	}
	return inline[types.ExprString(arg)]
}

// fixedTempName reports a name made of another name and a constant temp
// suffix, directly or as the last element of a filepath.Join, with nothing
// that differs between processes (a pid, a clock, a random part).
func fixedTempName(e ast.Expr, info *types.Info) bool {
	e = ast.Unparen(e)
	if call, ok := e.(*ast.CallExpr); ok && (calleeIn(call, info, "path/filepath", "Join") || calleeIn(call, info, "path", "Join")) && len(call.Args) > 0 {
		return fixedTempName(call.Args[len(call.Args)-1], info)
	}
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.ADD {
		return false
	}
	tv, ok := info.Types[bin.Y]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	suffix := constant.StringVal(tv.Value)
	fixed := false
	for _, s := range tempSuffixes {
		fixed = fixed || strings.HasSuffix(suffix, s)
	}
	return fixed && !variesByProcess(bin.X)
}

// variesByProcess reports a name part that differs between processes.
func variesByProcess(e ast.Expr) bool {
	text := types.ExprString(e)
	for _, part := range []string{"Getpid", "Now()", "rand.", "uuid", "UUID", "Unix"} {
		if strings.Contains(text, part) {
			return true
		}
	}
	return false
}

// holdsLock reports a function that takes a lock: a mutex or a file lock.
func holdsLock(body *ast.BlockStmt) bool {
	locked := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !locked
		}
		name := ""
		switch f := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = f.Sel.Name
		case *ast.Ident:
			name = f.Name
		}
		locked = locked || name == "Lock" || name == "TryLock" || strings.Contains(strings.ToLower(name), "flock") || strings.Contains(name, "LockFile")
		return !locked
	})
	return locked
}
