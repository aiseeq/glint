package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPartialResultsDroppedOnErrorRule())
}

// NewPartialResultsDroppedOnErrorRule creates partial-results-dropped-on-error:
// a function that returns its results together with the failures of a later
// step (errors.Join of collected errors) promises a partial success, and a
// caller that drops the results on that error and goes on loses what the
// call already did:
//
//	func (s *Service) Sync(a string) ([]*Result, error) {
//	    ... results = append(results, r) ...           // rows already written
//	    return results, s.reconcile(a, results)       // errors.Join(errs...)
//	}
//	results, err := s.Sync(a)
//	if err != nil { log...; continue }                // the written rows are not counted
//
// Reported: the error branch of such a call that neither reads the results
// nor passes the error on (continue, break, or a return without it), while
// the results are read after it.
func NewPartialResultsDroppedOnErrorRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"partial-results-dropped-on-error",
			"patterns",
			"Detects a caller dropping the results of a call that returns them together with joined failures — what the call already did is lost on a partial failure",
			core.SeverityMedium,
		),
		suggestion: "Read the results before the error branch (count what was done), or make the callee return nil results when they must not be used",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		forEachOwnStatementList(fn.Body, func(list []ast.Stmt) {
			for i := 0; i+1 < len(list); i++ {
				if check := droppedPartialResults(scope, list, i); check != nil {
					findings = append(findings, funcFinding{node: check, message: "The results of a call that reports joined failures together with them are dropped on its error — what the call already did is not counted"})
				}
			}
		})
		return findings
	}
	return r
}

// droppedPartialResults returns the error check at list[i+1] of a call at
// list[i] whose partial results it drops.
func droppedPartialResults(scope funcScope, list []ast.Stmt, i int) *ast.IfStmt {
	assign, ok := list[i].(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return nil
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return nil
	}
	resultsIdent, ok1 := assign.Lhs[0].(*ast.Ident)
	errIdent, ok2 := assign.Lhs[1].(*ast.Ident)
	if !ok1 || !ok2 {
		return nil
	}
	results, _ := scope.info.ObjectOf(resultsIdent).(*types.Var)
	errVar, _ := scope.info.ObjectOf(errIdent).(*types.Var)
	if results == nil || errVar == nil || !implementsError(errVar.Type()) {
		return nil
	}
	check, ok := list[i+1].(*ast.IfStmt)
	if !ok || check.Init != nil || check.Else != nil {
		return nil
	}
	if name, isCheck := errNotNilName(check.Cond); !isCheck || name != errIdent.Name {
		return nil
	}
	if mentionsVar(scope.info, check.Body, results) || propagatesError(scope.info, check.Body, errVar) {
		return nil
	}
	readAfter := false
	for _, stmt := range list[i+2:] {
		readAfter = readAfter || mentionsVar(scope.info, stmt, results)
	}
	if !readAfter {
		return nil
	}
	callee, ok := scope.callee(call)
	if !ok || !returnsPartialSuccess(scope, callee, 1) {
		return nil
	}
	return check
}

// propagatesError reports an error branch that hands the error on: returns
// it (wrapped or not) or ends without leaving the enclosing statement list.
func propagatesError(info *types.Info, body *ast.BlockStmt, errVar *types.Var) bool {
	if len(body.List) == 0 {
		return true
	}
	switch last := body.List[len(body.List)-1].(type) {
	case *ast.BranchStmt:
		return last.Tok != token.CONTINUE && last.Tok != token.BREAK
	case *ast.ReturnStmt:
		for _, result := range last.Results {
			if mentionsVar(info, result, errVar) {
				return true
			}
		}
		return false
	}
	return true
}

// returnsPartialSuccess reports a function with a return statement that
// hands out a variable of its own together with joined failures: an
// errors.Join call, a variable assigned one, or a call to a function that
// returns one (followed depth levels deep).
func returnsPartialSuccess(scope funcScope, fn typedFuncDecl, depth int) bool {
	results := fn.decl.Type.Results
	if results == nil || results.NumFields() != 2 {
		return false
	}
	joined := joinedErrorVars(fn.info, fn.decl.Body)
	found := false
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		if _, nested := n.(*ast.FuncLit); nested || found {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 2 {
			return true
		}
		if _, isVar := ast.Unparen(ret.Results[0]).(*ast.Ident); !isVar || isNilIdent(ret.Results[0]) {
			return true
		}
		found = isJoinedError(scope, fn.info, ret.Results[1], joined, depth)
		return !found
	})
	return found
}

// isJoinedError reports an error expression made of joined failures.
func isJoinedError(scope funcScope, info *types.Info, expr ast.Expr, joined map[types.Object]bool, depth int) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return joined[info.ObjectOf(e)]
	case *ast.CallExpr:
		if isErrorsJoin(info, e) {
			return true
		}
		if depth <= 0 {
			return false
		}
		callee, ok := funcScope{info: info, decls: scope.decls}.callee(e)
		return ok && returnsJoinedError(scope, callee, depth-1)
	}
	return false
}

// returnsJoinedError reports a function returning errors.Join of collected
// failures as its error.
func returnsJoinedError(scope funcScope, fn typedFuncDecl, depth int) bool {
	joined := joinedErrorVars(fn.info, fn.decl.Body)
	found := false
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		if _, nested := n.(*ast.FuncLit); nested || found {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) > 0 {
			found = isJoinedError(scope, fn.info, ret.Results[len(ret.Results)-1], joined, depth)
		}
		return !found
	})
	return found
}

// joinedErrorVars returns the variables of a body assigned errors.Join(...).
func joinedErrorVars(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	joined := make(map[types.Object]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			call, isCall := ast.Unparen(rhs).(*ast.CallExpr)
			ident, isIdent := assign.Lhs[i].(*ast.Ident)
			if isCall && isIdent && isErrorsJoin(info, call) {
				joined[info.ObjectOf(ident)] = true
			}
		}
		return true
	})
	return joined
}

// isErrorsJoin reports a call of errors.Join.
func isErrorsJoin(info *types.Info, call *ast.CallExpr) bool {
	fn := staticFunc(info, call)
	return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "errors" && fn.Name() == "Join"
}
