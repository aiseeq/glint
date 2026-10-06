package patterns

import (
	"go/ast"
	"regexp"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewAuditWrittenAfterTransactionRule())
}

// txRunner names a call that runs a closure in a transaction or under a
// lock: RunInTx, WithTx, InTransaction, WithAccountLock.
var txRunner = regexp.MustCompile(`(?:InTx|WithTx|Tx$|Transaction|Transact|Atomic|Lock$)`)

// NewAuditWrittenAfterTransactionRule creates audit-written-after-transaction:
// the audit record of an action written after the transaction of the action
// commits, with a failure that only reaches the log, leaves the action done
// and unaudited:
//
//	if err := repos.RunInTx(ctx, func(ctx context.Context) error {
//		return s.completeWrites(ctx, req)
//	}); err != nil {
//		return err
//	}
//	s.writeAudit(ctx, req.AdminID, "completed", ...)   // no error result: a failure is logged
//
// The audit row belongs in the transaction of the action, so that a failed
// audit write rolls the action back.
func NewAuditWrittenAfterTransactionRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"audit-written-after-transaction",
			"patterns",
			"Detects the audit record of an action written after the action's transaction commits, with its failure only logged — the action stays committed without its audit entry",
			core.SeverityMedium,
		),
		suggestion: "Write the audit row inside the transaction of the action and return its error, so a failed audit write rolls the action back",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, stmt := range block.List {
				runner := txRunnerCall(stmt)
				if runner == nil || callsAudit(runner) {
					continue
				}
				for _, later := range block.List[i+1:] {
					if audit := uncheckedAudit(scope, later); audit != nil {
						findings = append(findings, funcFinding{node: audit, message: callName(audit) + " writes the audit record after " + callName(runner) + " has committed the action, and its failure only reaches the log — the action stays done without its audit entry"})
					}
				}
			}
			return true
		})
		return findings
	}
	return r
}

// txRunnerCall returns the transaction runner a statement calls with a
// closure: itself, its assignment or the init of an if.
func txRunnerCall(stmt ast.Stmt) *ast.CallExpr {
	var expr ast.Expr
	switch node := stmt.(type) {
	case *ast.ExprStmt:
		expr = node.X
	case *ast.AssignStmt:
		if len(node.Rhs) == 1 {
			expr = node.Rhs[0]
		}
	case *ast.IfStmt:
		if node.Init != nil {
			return txRunnerCall(node.Init)
		}
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) == 0 || !txRunner.MatchString(callName(call)) {
		return nil
	}
	if _, closure := call.Args[len(call.Args)-1].(*ast.FuncLit); !closure {
		return nil
	}
	return call
}

// callsAudit reports a node calling something named for an audit.
func callsAudit(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && namesAudit(callName(call)) {
			found = true
		}
		return !found
	})
	return found
}

// namesAudit reports a name with the word audit: recordLedgerAudit, auditEvent.
func namesAudit(name string) bool {
	return slices.Contains(helpers.IdentifierWords(name), "audit")
}

// uncheckedAudit returns the audit call a statement makes with its error
// out of reach: a bare call of a function without an error result, or one
// whose result is dropped.
func uncheckedAudit(scope funcScope, stmt ast.Stmt) *ast.CallExpr {
	var call *ast.CallExpr
	switch node := stmt.(type) {
	case *ast.ExprStmt:
		call, _ = ast.Unparen(node.X).(*ast.CallExpr)
	case *ast.AssignStmt:
		if len(node.Rhs) == 1 && slices.ContainsFunc(node.Lhs, func(lhs ast.Expr) bool { return isIdentNamed(lhs, "_") }) && len(node.Lhs) == 1 {
			call, _ = ast.Unparen(node.Rhs[0]).(*ast.CallExpr)
		}
	}
	if call == nil || !namesAudit(callName(call)) || !takesContext(scope.info, call) {
		return nil
	}
	return call
}
