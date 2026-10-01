package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorSuccessByStateRule())
}

// ErrorSuccessByStateRule detects an error branch that answers success when
// some state holds, without ever asking what the error was:
//
//	if err := repo.Create(ctx, wallet); err != nil {
//		existing, _ := repo.ByAddress(ctx, wallet.Address)
//		if existing.UserID == wallet.UserID {
//			return nil // "already exists"
//		}
//		return err
//	}
//
// The branch was written for one failure (a duplicate) and recognizes it by
// a side condition; every other failure that meets the condition — a lost
// connection, a constraint on another column — now passes as success.
// Classify the error itself: errors.Is(err, ErrDuplicate), the driver's code.
//
// Not reported: a condition that looks at the error, a cancelled context
// (ctx.Err()), and a branch that logs the error at Warn or Error level — a
// failover put on record.
type ErrorSuccessByStateRule struct {
	*rules.BaseRule
}

// NewErrorSuccessByStateRule creates the rule
func NewErrorSuccessByStateRule() *ErrorSuccessByStateRule {
	return &ErrorSuccessByStateRule{BaseRule: rules.NewBaseRule(
		"error-success-by-state",
		"patterns",
		"Detects an error branch that returns success under a condition that never looks at the error — every failure meeting the condition passes",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports the success returns of error branches decided by state.
func (r *ErrorSuccessByStateRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	forEachFunction(ctx.GoAST, func(_ string, ftype *ast.FuncType, body *ast.BlockStmt) {
		if !lastResultIsErrorType(ftype.Results) {
			return
		}
		forEachOwnStatement(body, func(stmt ast.Stmt) {
			branch, ok := stmt.(*ast.IfStmt)
			if !ok {
				return
			}
			errName := errNilCheckName(branch.Cond)
			if errName == "" {
				return
			}
			failed := errSourceExpr(body, branch, errName)
			derived := map[string]bool{errName: true}
			for _, own := range branch.Body.List {
				markErrDerived(own, derived)
				inner, ok := own.(*ast.IfStmt)
				if !ok || inner.Init != nil || !decidesByState(inner.Cond, derived) || confirmsWrite(inner.Cond, failed) || logsCause(inner.Body, errName) {
					continue
				}
				ret := successReturn(inner.Body)
				if ret == nil {
					continue
				}
				line := ctx.PositionFor(ret).Line
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, line, "The error branch returns success when "+types.ExprString(inner.Cond)+" — the error itself is never examined, so any failure meeting the condition passes")
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Recognize the expected failure by the error (errors.Is, errors.As, the driver's code) and return every other one")
				violations = append(violations, v)
			}
		})
	})
	return violations
}

// markErrDerived adds the names a statement sets from the error, such as
// kind := classify(err): a condition on them examines the error.
func markErrDerived(stmt ast.Stmt, derived map[string]bool) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok {
		return
	}
	readsErr := false
	for name := range derived {
		for _, rhs := range assign.Rhs {
			readsErr = readsErr || nodeReadsIdent(rhs, name)
		}
	}
	if !readsErr {
		return
	}
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
			derived[ident.Name] = true
		}
	}
}

// confirmsWrite reports a condition that compares the re-read state with a
// value the failed call itself was writing: status == "cancelled" after
// Apply(id, "cancelling", "cancelled") finds the outcome asked for.
func confirmsWrite(cond ast.Expr, failed *ast.CallExpr) bool {
	if failed == nil {
		return false
	}
	args := map[string]bool{}
	for _, arg := range failed.Args {
		args[types.ExprString(arg)] = true
	}
	for _, operand := range flattenAnd(cond) {
		bin, ok := ast.Unparen(operand).(*ast.BinaryExpr)
		if ok && bin.Op == token.EQL && (args[types.ExprString(bin.X)] || args[types.ExprString(bin.Y)]) {
			return true
		}
	}
	return false
}

// decidesByState reports a condition that neither names the error (or a
// value derived from it) nor asks a context whether it is done.
func decidesByState(cond ast.Expr, derived map[string]bool) bool {
	state := true
	ast.Inspect(cond, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if derived[node.Name] {
				state = false
			}
		case *ast.SelectorExpr:
			if node.Sel.Name == "Err" || node.Sel.Name == "Done" {
				state = false
			}
		}
		return state
	})
	return state
}

// logsCause reports a block that logs the error at Error or Warn level.
func logsCause(body *ast.BlockStmt, errName string) bool {
	for _, stmt := range body.List {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		if call, ok := exprStmt.X.(*ast.CallExpr); ok && isErrorLevelLogCall(call) && nodeReadsIdent(call, errName) {
			return true
		}
	}
	return false
}

// successReturn returns the block's own return with a nil error.
func successReturn(body *ast.BlockStmt) *ast.ReturnStmt {
	for _, stmt := range body.List {
		if ret, ok := stmt.(*ast.ReturnStmt); ok && len(ret.Results) > 0 && isNilIdent(ret.Results[len(ret.Results)-1]) {
			return ret
		}
	}
	return nil
}
