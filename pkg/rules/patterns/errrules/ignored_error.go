package errrules

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewIgnoredErrorRule())
}

// IgnoredErrorRule detects error values thrown away with the blank identifier.
//
// Whether a returned value is an error is decided by its type, not by the name of the
// function returning it. The name-based version of this rule matched a fixed list of verbs
// (Read, Parse, Query, Marshal…) and therefore stayed silent on every domain method — the
// shape `items, _ = repo.List(ctx)` reads as "no data" downstream while the query may well
// have failed.
//
// Closing a resource stays exempt: `_ = conn.Close()` and the print family cannot report
// anything useful to the caller, and writing the blank there is the documented way to say
// "checked and deliberately dropped".
type IgnoredErrorRule struct {
	*rules.BaseRule
}

// NewIgnoredErrorRule creates a new ignored error detector
func NewIgnoredErrorRule() *IgnoredErrorRule {
	return &IgnoredErrorRule{
		BaseRule: rules.NewBaseRule(
			"ignored-error",
			"patterns",
			"Detects error values that are explicitly ignored with blank identifier",
			core.SeverityMedium,
		),
	}
}

// RequiresSSA reports that plain type information is enough.
func (r *IgnoredErrorRule) RequiresSSA() bool { return false }

// AnalyzeFile is unused: the rule works on the typed project.
func (r *IgnoredErrorRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// AnalyzeGoProject walks assignments and reports blanks that swallow an error
// value. Test files are skipped; every other file of a typed package is
// production code whatever its name looks like.
func (r *IgnoredErrorRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyzeFile(fileCtx, fileCtx.GoAST, info)
	})
}

func (r *IgnoredErrorRule) analyzeFile(fileCtx *core.FileContext, file *ast.File, info *types.Info) []*core.Violation {
	var violations []*core.Violation
	cleanup := failurePathCleanup(file, info)

	ast.Inspect(file, func(n ast.Node) bool {
		var v *core.Violation
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			if !cleanup[stmt] {
				v = r.checkAssign(fileCtx, stmt, info)
			}
		case *ast.ExprStmt:
			if !cleanup[stmt] {
				v = r.checkBareCall(fileCtx, stmt, info)
			}
		}
		if v != nil {
			violations = append(violations, v)
		}
		return true
	})

	return violations
}

func (r *IgnoredErrorRule) checkAssign(fileCtx *core.FileContext, assign *ast.AssignStmt, info *types.Info) *core.Violation {
	v := r.ignoredAssign(fileCtx, assign, info)
	if v == nil {
		return nil
	}
	// Маркер правила — на самой строке или комментарием над ней.
	if fileCtx.IsSuppressed(v.Line, r.Name()) {
		return nil
	}
	return v
}

// checkBareCall reports a call standing alone as a statement whose results
// hold an error: nothing reads the error, and unlike the blank the drop is not
// written down.
func (r *IgnoredErrorRule) checkBareCall(fileCtx *core.FileContext, stmt *ast.ExprStmt, info *types.Info) *core.Violation {
	call, ok := ast.Unparen(stmt.X).(*ast.CallExpr)
	if !ok || !patternkit.ReturnsError(call, info) {
		return nil
	}
	funcName := core.ExtractFullFunctionName(call)
	if isKnownSafeToIgnore(funcName) || writeCannotFail(call, info) || randReadCannotFail(call, info) {
		return nil
	}
	pos := fileCtx.PositionFor(stmt)
	if fileCtx.IsSuppressed(pos.Line, r.Name()) {
		return nil
	}
	v := r.CreateViolation(fileCtx.RelPath, pos.Line, "Error from "+funcName+" is dropped: the call stands alone and nothing reads its error")
	v.WithCode(strings.TrimSpace(fileCtx.GetLine(pos.Line)))
	v.WithSuggestion("Handle the error, or return it to the caller; a deliberate drop is written as _ = with the reason")
	return v
}

// failurePathCleanup returns the removals of a file or a directory
// (os.Remove, os.RemoveAll) that a return of a non-nil error follows in the
// same block, past other such statements and Close calls: cleanup on the way
// out of a failure, like a rollback. The error that made the path fail goes
// to the caller, and the failure of the cleanup has no one to report to.
func failurePathCleanup(file *ast.File, info *types.Info) map[ast.Stmt]bool {
	cleanup := make(map[ast.Stmt]bool)
	mark := func(list []ast.Stmt) {
		for i, stmt := range list {
			if isRemovalStmt(stmt, info) && returnsFailureAfterCleanup(list[i+1:], info) {
				cleanup[stmt] = true
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch block := n.(type) {
		case *ast.BlockStmt:
			mark(block.List)
		case *ast.CaseClause:
			mark(block.Body)
		case *ast.CommClause:
			mark(block.Body)
		}
		return true
	})
	return cleanup
}

// isRemovalStmt reports os.Remove or os.RemoveAll as a statement of its own
// or assigned to the blank.
func isRemovalStmt(stmt ast.Stmt, info *types.Info) bool {
	var expr ast.Expr
	switch s := stmt.(type) {
	case *ast.ExprStmt:
		expr = s.X
	case *ast.AssignStmt:
		if len(s.Rhs) != 1 {
			return false
		}
		expr = s.Rhs[0]
	default:
		return false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := info.Uses[selector.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "os" && (fn.Name() == "Remove" || fn.Name() == "RemoveAll")
}

// returnsFailureAfterCleanup reports statements that, past more removals and
// Close calls, return an error result other than nil.
func returnsFailureAfterCleanup(rest []ast.Stmt, info *types.Info) bool {
	for _, stmt := range rest {
		if ret, ok := stmt.(*ast.ReturnStmt); ok {
			if len(ret.Results) == 0 {
				return false
			}
			last := ret.Results[len(ret.Results)-1]
			if id, ok := ast.Unparen(last).(*ast.Ident); ok && id.Name == "nil" {
				return false
			}
			t := info.TypeOf(last)
			return t != nil && patternkit.IsErrorType(t)
		}
		if isRemovalStmt(stmt, info) || isCloseStmt(stmt) {
			continue
		}
		return false
	}
	return false
}

// isCloseStmt reports a bare x.Close() statement.
func isCloseStmt(stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := ast.Unparen(expr.X).(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Close"
}

// randReadCannotFail reports crypto/rand.Read, whose documentation promises
// it never returns an error and crashes the program instead.
func randReadCannotFail(call *ast.CallExpr, info *types.Info) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := info.Uses[selector.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "crypto/rand" && fn.Name() == "Read"
}

func (r *IgnoredErrorRule) ignoredAssign(fileCtx *core.FileContext, assign *ast.AssignStmt, info *types.Info) *core.Violation {
	pos := fileCtx.PositionFor(assign)
	line := fileCtx.GetLine(pos.Line)

	for i, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name != "_" {
			continue
		}
		call, ignored := ignoredValue(assign, i, info)
		if call == nil || ignored == nil || !patternkit.IsErrorType(ignored) {
			continue
		}
		funcName := core.ExtractFullFunctionName(call)
		if isKnownSafeToIgnore(funcName) || writeCannotFail(call, info) || randReadCannotFail(call, info) {
			continue
		}

		v := r.CreateViolation(fileCtx.RelPath, pos.Line, "Error from "+funcName+" is dropped into the blank identifier")
		v.WithCode(strings.TrimSpace(line))
		v.WithSuggestion("Handle the error, or return it to the caller so a failure is not read as empty data")
		return v
	}

	return nil
}

// ignoredValue returns the call feeding the i-th assignment target and the type
// landing there — for both `a, _ := f()` and `a, _ := f(), g()`.
func ignoredValue(assign *ast.AssignStmt, i int, info *types.Info) (*ast.CallExpr, types.Type) {
	if len(assign.Rhs) == 1 && len(assign.Lhs) > 1 {
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return nil, nil
		}
		tuple, ok := info.TypeOf(call).(*types.Tuple)
		if !ok || i >= tuple.Len() {
			return nil, nil
		}
		return call, tuple.At(i).Type()
	}

	if i >= len(assign.Rhs) {
		return nil, nil
	}
	call, ok := assign.Rhs[i].(*ast.CallExpr)
	if !ok {
		return nil, nil
	}
	return call, info.TypeOf(call)
}

func isKnownSafeToIgnore(funcName string) bool {
	// Печать и закрытие ресурса: вызывающему такая ошибка ничего не даёт, а blank
	// на этом месте — общепринятая пометка «проверено, осознанно выброшено».
	safeSuffixes := []string{
		"Printf", "Println", "Print",
		"Fprintf", "Fprintln", "Fprint",
		"Close",
		// Откат транзакции идёт по пути, где ошибка уже произошла: сообщать о
		// провале отката некому, а исходную ошибку он не заменяет.
		"Rollback",
	}

	for _, suffix := range safeSuffixes {
		if strings.HasSuffix(funcName, suffix) {
			return true
		}
	}

	return false
}

// writeCannotFail reports a Write on a destination whose documentation promises
// the error is always nil: hash.Hash ("it never returns an error"), and the
// in-memory writers strings.Builder and bytes.Buffer. Demanding a check there
// buys a branch that can never run, so the blank is the honest spelling.
func writeCannotFail(call *ast.CallExpr, info *types.Info) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(selector.Sel.Name, "Write") {
		return false
	}
	recv := info.TypeOf(selector.X)
	if recv == nil {
		return false
	}
	if pointer, ok := recv.Underlying().(*types.Pointer); ok {
		recv = pointer.Elem()
	}
	if named, ok := recv.(*types.Named); ok {
		pkg := named.Obj().Pkg()
		if pkg != nil {
			switch pkg.Path() + "." + named.Obj().Name() {
			case "strings.Builder", "bytes.Buffer":
				return true
			}
		}
	}
	return implementsHash(recv)
}

// implementsHash reports whether the type carries the hash.Hash method set. The
// interface is matched by shape rather than by import so that both hash.Hash
// itself and the concrete hashes returned by fnv, sha256 and friends qualify.
func implementsHash(t types.Type) bool {
	required := map[string]bool{"Write": false, "Sum": false, "Reset": false, "Size": false, "BlockSize": false}
	mark := func(name string) {
		if _, wanted := required[name]; wanted {
			required[name] = true
		}
	}
	if iface, ok := t.Underlying().(*types.Interface); ok {
		// fnv.New64a and friends hand back hash.Hash64, so the value's static
		// type is the interface itself; a pointer to it has no method set.
		for method := range iface.Methods() {
			mark(method.Name())
		}
	} else {
		methods := types.NewMethodSet(types.NewPointer(t))
		for method := range methods.Methods() {
			mark(method.Obj().Name())
		}
	}
	for _, found := range required {
		if !found {
			return false
		}
	}
	return true
}
