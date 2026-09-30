package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTxWriteAfterCommitRule())
}

// TxWriteAfterCommitRule detects a write that follows the commit of a
// transaction in the same function and fails the function when it fails:
//
//	if err := tx.Commit(); err != nil {
//		return nil, err
//	}
//	if err := s.repo.AddOwnedAddress(ctx, user.ID, address); err != nil {
//		return nil, fmt.Errorf("user created without a wallet: %w", err)
//	}
//
// The caller gets an error, but the first part is already committed: the
// data stays half written, and a retry creates the first part again or
// fails on it. A transaction is one begun in the function (Begin, BeginTx,
// Beginx); a write is a call whose method starts with a verb that changes
// data (Insert, Create, Add, Update, Save, Exec...).
type TxWriteAfterCommitRule struct {
	*rules.BaseRule
}

// NewTxWriteAfterCommitRule creates the rule
func NewTxWriteAfterCommitRule() *TxWriteAfterCommitRule {
	return &TxWriteAfterCommitRule{BaseRule: rules.NewBaseRule(
		"tx-write-after-commit",
		"patterns",
		"Detects a write after a transaction's commit whose failure fails the function — the committed part stays half done",
		core.SeverityHigh,
	)}
}

var writeMethod = regexp.MustCompile(`^(?:Insert|Create|Add|Update|Delete|Remove|Save|Upsert|Exec|Attach|Link|Assign|Store|Put|Mark|Record|Register|Write)`)

// AnalyzeFile reports the failing writes after a commit in each function.
func (r *TxWriteAfterCommitRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, body := range functionBodies(ctx.GoAST) {
		txs := begunTransactions(body)
		if len(txs) == 0 {
			continue
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if _, nested := n.(*ast.FuncLit); nested {
				return false // its own body is checked on its own
			}
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			committed := false
			for i, stmt := range block.List {
				if !committed {
					committed = commitsTransaction(stmt, txs)
					continue
				}
				call := failingWrite(block.List, i)
				if call == nil {
					continue
				}
				line := ctx.LineFor(call)
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, line, "Write after the transaction's commit fails the function — the committed part stays, and the caller gets an error for an operation half done")
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Make the write inside the transaction, before Commit; or, when it may lag behind, log its failure and retry it without failing the operation")
				violations = append(violations, v)
			}
			return true
		})
	}
	return violations
}

// begunTransactions returns the names assigned a transaction begun in the
// body: tx, err := db.BeginTx(ctx, nil).
func begunTransactions(body *ast.BlockStmt) map[string]bool {
	txs := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "Begin") {
			if id, ok := assign.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
				txs[id.Name] = true
			}
		}
		return true
	})
	return txs
}

// commitsTransaction reports a statement calling Commit on one of the
// transactions: tx.Commit(), err = tx.Commit(), if err := tx.Commit(); ...
func commitsTransaction(stmt ast.Stmt, txs map[string]bool) bool {
	call := statementCall(stmt)
	if call == nil || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Commit" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && txs[id.Name]
}

// statementCall is the call a statement makes at its top: an expression
// statement, the right side of an assignment, the init of an if.
func statementCall(stmt ast.Stmt) *ast.CallExpr {
	switch s := stmt.(type) {
	case *ast.ExprStmt:
		call, _ := s.X.(*ast.CallExpr)
		return call
	case *ast.AssignStmt:
		if len(s.Rhs) == 1 {
			call, _ := s.Rhs[0].(*ast.CallExpr)
			return call
		}
	case *ast.IfStmt:
		if s.Init != nil {
			return statementCall(s.Init)
		}
	}
	return nil
}

// failingWrite returns the write the i-th statement makes when an error of
// it returns an error from the function: in the if's init, or assigned and
// checked by the next statement.
func failingWrite(list []ast.Stmt, i int) *ast.CallExpr {
	call := statementCall(list[i])
	if call == nil {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !writeMethod.MatchString(sel.Sel.Name) {
		return nil
	}
	check, ok := list[i].(*ast.IfStmt)
	if !ok {
		if _, assigned := list[i].(*ast.AssignStmt); !assigned || i+1 == len(list) {
			return nil
		}
		if check, ok = list[i+1].(*ast.IfStmt); !ok || check.Init != nil {
			return nil
		}
	}
	if _, ok := errNotNilName(check.Cond); !ok || !blockReturnsError(check.Body) {
		return nil
	}
	return call
}

// blockReturnsError reports a block returning a non-nil last result.
func blockReturnsError(body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			continue
		}
		if id, ok := ret.Results[len(ret.Results)-1].(*ast.Ident); !ok || id.Name != "nil" {
			return true
		}
	}
	return false
}
