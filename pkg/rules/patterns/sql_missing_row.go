package patterns

import (
	"go/ast"
	"regexp"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLMissingRowUncheckedRule())
}

// SQLMissingRowUncheckedRule detects an UPDATE or DELETE of one row, by its
// id or a unique key, in a function returning an error that never learns
// whether the row was there:
//
//	func (r *Repo) UpdateInvestment(ctx context.Context, inv *Investment) error {
//		_, err := r.db.ExecContext(ctx, `UPDATE investments SET amount = $2 WHERE id = $1`, inv.ID, inv.Amount)
//		return err
//	}
//
// With no such row the statement succeeds having changed nothing, and the
// caller goes on as if it had: a stale id, a row another request deleted.
// Reported: the result dropped, RowsAffected never read, or its zero only
// logged, in a function whose only statement to the database is the write.
// Not reported: RETURNING (the scan finds no rows), a function without an
// error to return, a function that reads or locks rows too (the row is
// known to exist).
type SQLMissingRowUncheckedRule struct {
	*rules.BaseRule
}

// NewSQLMissingRowUncheckedRule creates the rule
func NewSQLMissingRowUncheckedRule() *SQLMissingRowUncheckedRule {
	return &SQLMissingRowUncheckedRule{BaseRule: rules.NewBaseRule(
		"sql-missing-row-unchecked",
		"patterns",
		"Detects an UPDATE or DELETE of one row whose affected count nobody checks — a missing row passes as success",
		core.SeverityMedium,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations' unique keys.
func (r *SQLMissingRowUncheckedRule) ReadsOtherFiles() bool { return true }

var execMethods = map[string]bool{"Exec": true, "ExecContext": true, "NamedExec": true, "NamedExecContext": true}

// AnalyzeFile reports the one-row writes whose affected count is not checked.
func (r *SQLMissingRowUncheckedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok {
		return nil
	}
	writes := make(map[*ast.CallExpr]bool)
	for _, call := range sqlCalls(ctx.GoAST) {
		sel, ok := call.call.Fun.(*ast.SelectorExpr)
		if ok && execMethods[sel.Sel.Name] && schema.RowWrite(call.literal.text) {
			writes[call.call] = true
		}
	}
	if len(writes) == 0 {
		return nil
	}
	var violations []*core.Violation
	for _, fn := range errorFunctions(ctx.GoAST) {
		ast.Inspect(fn, func(n ast.Node) bool {
			if _, nested := n.(*ast.FuncLit); nested {
				return false // checked with its own results
			}
			stmt, ok := n.(ast.Stmt)
			if !ok {
				return true
			}
			call := statementCall(stmt)
			if call == nil || !writes[call] || countChecked(stmt, fn) || databaseCalls(fn) > 1 {
				return true
			}
			line := ctx.LineFor(call)
			if !ctx.IsSuppressed(line, r.Name()) {
				violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
					"One-row UPDATE/DELETE whose affected count nobody checks — with no such row it succeeds having changed nothing",
					"Check RowsAffected and return a not-found error when it is 0, or add RETURNING and scan it"))
			}
			return true
		})
	}
	return violations
}

var databaseMethods = regexp.MustCompile(`^(?:Named)?(?:Exec|Query|QueryRow|Get|Select)(?:x|Context|xContext)?$`)

// databaseCalls counts the statements a function sends to the database. A
// row the function read or locked before writing is known to exist: only a
// function writing a row it has not seen is reported.
func databaseCalls(body *ast.BlockStmt) int {
	count := 0
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && databaseMethods.MatchString(sel.Sel.Name) {
				count++
			}
		}
		return true
	})
	return count
}

// errorFunctions returns the bodies of the file's functions whose last
// result is an error.
func errorFunctions(file *ast.File) []*ast.BlockStmt {
	var bodies []*ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		var typ *ast.FuncType
		var body *ast.BlockStmt
		switch f := n.(type) {
		case *ast.FuncDecl:
			typ, body = f.Type, f.Body
		case *ast.FuncLit:
			typ, body = f.Type, f.Body
		default:
			return true
		}
		if body == nil || typ.Results == nil || len(typ.Results.List) == 0 {
			return true
		}
		if id, ok := typ.Results.List[len(typ.Results.List)-1].Type.(*ast.Ident); ok && id.Name == "error" {
			bodies = append(bodies, body)
		}
		return true
	})
	return bodies
}

// countChecked reports a write statement whose result the function asks
// RowsAffected and acts on the count: tests it in an if that returns or
// jumps, returns it or passes it on, right away or through a variable.
func countChecked(stmt ast.Stmt, body *ast.BlockStmt) bool {
	result := resultName(stmt)
	if result == "" {
		return false
	}
	isCount := func(expr ast.Expr) bool {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RowsAffected" {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == result
	}
	// The result handed on (a helper checking the count), the count itself,
	// and the variables it is stored in.
	holders := []func(ast.Expr) bool{
		func(expr ast.Expr) bool {
			id, ok := ast.Unparen(expr).(*ast.Ident)
			return ok && id.Name == result
		},
		func(expr ast.Expr) bool { return containsExpr(expr, isCount) },
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Rhs) == 1 && isCount(assign.Rhs[0]) {
			if count, ok := assign.Lhs[0].(*ast.Ident); ok && count.Name != "_" {
				holders = append(holders, func(expr ast.Expr) bool { return mentions(expr, count.Name) })
			}
		}
		return true
	})
	for _, holds := range holders {
		if countActedOn(holds, body) {
			return true
		}
	}
	return false
}

// containsExpr reports an expression with a part the predicate accepts.
func containsExpr(expr ast.Expr, match func(ast.Expr) bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok && match(e) {
			found = true
		}
		return !found
	})
	return found
}

// resultName is the variable a write statement stores its result in, ""
// when it drops it.
func resultName(stmt ast.Stmt) string {
	if ifStmt, ok := stmt.(*ast.IfStmt); ok {
		stmt = ifStmt.Init
	}
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) == 0 {
		return ""
	}
	if id, ok := assign.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
		return id.Name
	}
	return ""
}

// countActedOn reports a count that an if returning or jumping tests, that
// is returned, or that is passed to a call.
func countActedOn(holds func(ast.Expr) bool, body *ast.BlockStmt) bool {
	acted := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			if holds(node.Cond) && (blockLeaves(node.Body) || elseLeaves(node.Else)) {
				acted = true
			}
		case *ast.ReturnStmt:
			for _, result := range node.Results {
				acted = acted || holds(result)
			}
		case *ast.CallExpr:
			for _, arg := range node.Args {
				acted = acted || holds(arg)
			}
		}
		return !acted
	})
	return acted
}

// blockLeaves reports a block that returns or jumps: the flow after it
// depends on the count.
func blockLeaves(body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		switch stmt.(type) {
		case *ast.ReturnStmt, *ast.BranchStmt:
			return true
		}
	}
	return false
}

func elseLeaves(stmt ast.Stmt) bool {
	block, ok := stmt.(*ast.BlockStmt)
	return ok && blockLeaves(block)
}
