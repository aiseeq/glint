package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLConflictErrorTakenAsConflictRule())
}

// SQLConflictErrorTakenAsConflictRule detects a single-row read of an
// INSERT ... ON CONFLICT DO NOTHING RETURNING whose error branch takes every
// error for the conflict:
//
//	err := r.db.GetContext(ctx, status, `INSERT ... ON CONFLICT (wallet) DO NOTHING RETURNING *`, ...)
//	if err != nil {
//	    return r.Get(ctx, wallet) // the row "already exists"
//	}
//
// The conflict comes back as the driver's no-rows error; a lost connection,
// a violated constraint or a type error comes back as an error too, and the
// branch answers it with the fallback read - the failed insert is never
// seen. The same holds for DO UPDATE ... WHERE ... RETURNING. Reported: the
// branch right after the read neither tests for no rows nor returns the
// error.
type SQLConflictErrorTakenAsConflictRule struct {
	*rules.BaseRule
}

// NewSQLConflictErrorTakenAsConflictRule creates the rule
func NewSQLConflictErrorTakenAsConflictRule() *SQLConflictErrorTakenAsConflictRule {
	return &SQLConflictErrorTakenAsConflictRule{BaseRule: rules.NewBaseRule(
		"sql-conflict-error-taken-as-conflict",
		"patterns",
		"Detects an INSERT ... ON CONFLICT DO NOTHING RETURNING read as one row whose error branch takes every error for the conflict — a failed insert passes as an existing row",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports the error branches of conflict-skipping inserts that
// do not tell the conflict from a failure.
func (r *SQLConflictErrorTakenAsConflictRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	reads := make(map[*ast.CallExpr]bool)
	for _, call := range sqlCalls(ctx.GoAST) {
		if sqlschema.ReturningMayBeEmpty(call.literal.text) {
			reads[call.call] = true
		}
	}
	if len(reads) == 0 {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List {
			check := conflictErrorBranch(block.List, i, stmt, reads)
			if check == nil || tellsConflict(check.Body) {
				continue
			}
			line := ctx.LineFor(check)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line, "Every error of the INSERT ... ON CONFLICT ... RETURNING is taken for the conflict — a failed insert passes as an existing row")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Take only the no-rows error (errors.Is(err, sql.ErrNoRows)) for the conflict and return every other error")
			violations = append(violations, v)
		}
		return true
	})
	return violations
}

// conflictErrorBranch returns the `if err != nil` that handles the error of a
// conflict-skipping read made by the statement at index: in the statement's
// own init, or right after it.
func conflictErrorBranch(list []ast.Stmt, index int, stmt ast.Stmt, reads map[*ast.CallExpr]bool) *ast.IfStmt {
	if check, ok := stmt.(*ast.IfStmt); ok && check.Init != nil && containsRead(check.Init, reads) {
		if _, ok := errNotNilName(ast.Unparen(check.Cond)); ok {
			return check
		}
		return nil
	}
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || !containsRead(assign, reads) || index+1 >= len(list) {
		return nil
	}
	check, ok := list[index+1].(*ast.IfStmt)
	if !ok || check.Init != nil {
		return nil
	}
	name, ok := errNotNilName(ast.Unparen(check.Cond))
	if !ok {
		return nil
	}
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name == name {
			return check
		}
	}
	return nil
}

func containsRead(node ast.Node, reads map[*ast.CallExpr]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && reads[call] {
			found = true
		}
		return !found
	})
	return found
}

// tellsConflict reports a branch that tells the conflict from a failure: it
// tests for no rows, or returns the error.
func tellsConflict(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			found = found || node.Name == "ErrNoRows"
		case *ast.ReturnStmt:
			for _, result := range node.Results {
				ast.Inspect(result, func(m ast.Node) bool {
					if ident, ok := m.(*ast.Ident); ok && isErrorVarName(ident.Name) {
						found = true
					}
					return !found
				})
			}
		}
		return !found
	})
	return found
}
