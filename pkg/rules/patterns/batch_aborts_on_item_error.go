package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewBatchAbortsOnItemErrorRule())
}

// NewBatchAbortsOnItemErrorRule creates batch-aborts-on-item-error: a loop
// over items that already skips some failed items (errors.Is(...) → continue)
// is a batch of independent items, and a return of the progress so far on
// another item's failure leaves every later item unprocessed:
//
//	for _, g := range groups {
//	    t, err := client.Status(ctx, g.Hash)
//	    if errors.Is(err, ErrNotFound) { continue }
//	    if err != nil { return corrected, err }   // one bad item stops the batch
//	    ...; corrected++
//	}
//
// Reported: the return, inside such a loop, of a value the loop accumulates
// (a counter, an appended slice) together with the error.
func NewBatchAbortsOnItemErrorRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"batch-aborts-on-item-error",
			"patterns",
			"Detects a batch loop that skips some failed items but returns its progress on another item's failure — every later item stays unprocessed",
			core.SeverityMedium,
		),
		suggestion: "Collect the failure (errors.Join) and continue with the next item, or document why one item must stop the batch",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, nested := n.(*ast.FuncLit); nested {
				return false
			}
			loop, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			// One report per loop: its aborts share one fix.
			if aborts := batchAborts(scope.info, loop); len(aborts) > 0 {
				findings = append(findings, funcFinding{node: aborts[0], message: "A batch that skips some failed items returns its progress on another item's failure — every later item stays unprocessed"})
			}
			return true
		})
		return findings
	}
	return r
}

// batchAborts returns the returns of a loop's progress on an item's failure,
// for a loop that skips other failed items.
func batchAborts(info *types.Info, loop *ast.RangeStmt) []*ast.ReturnStmt {
	accumulated := loopAccumulators(info, loop)
	if len(accumulated) == 0 {
		return nil
	}
	skips := false
	var aborts []*ast.ReturnStmt
	inspectOwnLoopBody(loop.Body, func(check *ast.IfStmt) {
		if len(check.Body.List) == 0 {
			return
		}
		switch last := check.Body.List[len(check.Body.List)-1].(type) {
		case *ast.BranchStmt:
			if last.Tok == token.CONTINUE && last.Label == nil && conditionOnError(info, check.Cond) {
				skips = true
			}
		case *ast.ReturnStmt:
			if _, isCheck := errNotNilName(check.Cond); isCheck && returnsProgress(info, last, accumulated) && !returnsJoined(info, last) {
				aborts = append(aborts, last)
			}
		}
	})
	if !skips {
		return nil
	}
	return aborts
}

// inspectOwnLoopBody visits the if statements of a loop body outside nested
// loops and function literals: those belong to another iteration.
func inspectOwnLoopBody(body *ast.BlockStmt, visit func(*ast.IfStmt)) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit, *ast.RangeStmt, *ast.ForStmt:
			return false
		case *ast.IfStmt:
			visit(node)
		}
		return true
	})
}

// conditionOnError reports a condition about an error: it reads a value of
// error type (err != nil, errors.Is(err, ErrX)).
func conditionOnError(info *types.Info, cond ast.Expr) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			if v, isVar := info.ObjectOf(ident).(*types.Var); isVar && implementsError(v.Type()) {
				found = true
			}
		}
		return !found
	})
	return found
}

// loopAccumulators returns the variables declared before a loop that its
// body accumulates: x++, x += y, x = append(x, ...).
func loopAccumulators(info *types.Info, loop *ast.RangeStmt) map[types.Object]bool {
	accumulated := make(map[types.Object]bool)
	outer := func(expr ast.Expr) types.Object {
		ident, ok := expr.(*ast.Ident)
		if !ok {
			return nil
		}
		obj := info.ObjectOf(ident)
		if obj == nil || obj.Pos() >= loop.Pos() {
			return nil
		}
		return obj
	}
	ast.Inspect(loop.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IncDecStmt:
			if obj := outer(node.X); obj != nil && node.Tok == token.INC {
				accumulated[obj] = true
			}
		case *ast.AssignStmt:
			if len(node.Lhs) != 1 || len(node.Rhs) != 1 {
				return true
			}
			obj := outer(node.Lhs[0])
			if obj == nil {
				return true
			}
			if node.Tok == token.ADD_ASSIGN {
				accumulated[obj] = true
			}
			if call, ok := node.Rhs[0].(*ast.CallExpr); ok && node.Tok == token.ASSIGN && isIdentNamed(call.Fun, "append") &&
				len(call.Args) > 0 && outer(call.Args[0]) == obj {
				accumulated[obj] = true
			}
		}
		return true
	})
	return accumulated
}

// returnsJoined reports a return whose error is errors.Join of the failures
// the batch collected: the abort reports every earlier failure with its own
// (a cancellation stopping the batch).
func returnsJoined(info *types.Info, ret *ast.ReturnStmt) bool {
	call, ok := ast.Unparen(ret.Results[len(ret.Results)-1]).(*ast.CallExpr)
	return ok && isErrorsJoin(info, call)
}

// returnsProgress reports a return of an accumulated value with an error.
func returnsProgress(info *types.Info, ret *ast.ReturnStmt, accumulated map[types.Object]bool) bool {
	if len(ret.Results) < 2 || isNilIdent(ret.Results[len(ret.Results)-1]) {
		return false
	}
	first, ok := ast.Unparen(ret.Results[0]).(*ast.Ident)
	return ok && accumulated[info.ObjectOf(first)]
}
