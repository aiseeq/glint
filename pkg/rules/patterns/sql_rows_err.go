package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLRowsErrUncheckedRule())
}

// SQLRowsErrUncheckedRule detects a loop over SQL rows with no rows.Err()
// in the function:
//
//	for rows.Next() {
//		...
//	}
//	return deposits, nil
//
// rows.Next returns false both at the end of the rows and on an error mid
// way - a dropped connection, a row that fails to decode - and the function
// returns what it read as the whole list. Rows are *database/sql.Rows or a
// cursor with the same methods (sqlx, pgx).
type SQLRowsErrUncheckedRule struct {
	*rules.BaseRule
}

// NewSQLRowsErrUncheckedRule creates the rule
func NewSQLRowsErrUncheckedRule() *SQLRowsErrUncheckedRule {
	return &SQLRowsErrUncheckedRule{BaseRule: rules.NewBaseRule(
		"sql-rows-err-unchecked",
		"patterns",
		"Detects a loop over SQL rows with no rows.Err() check — an error mid-way ends the loop like the last row",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: rows are known by their type.
func (r *SQLRowsErrUncheckedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLRowsErrUncheckedRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the loops over rows whose error nobody reads.
func (r *SQLRowsErrUncheckedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if fileCtx.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		for _, body := range functionBodies(fileCtx.GoAST) {
			cursor := rowsCursor{info: info, queried: queriedNames(body)}
			checked := make(map[any]bool)
			var loops []*ast.ForStmt
			ast.Inspect(body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit:
					return false // its own body
				case *ast.ForStmt:
					if cursor.call(n.Cond, "Next") != nil {
						loops = append(loops, n)
					}
				case *ast.CallExpr:
					if obj := cursor.call(n, "Err"); obj != nil {
						checked[obj] = true
					}
				}
				return true
			})
			for _, loop := range loops {
				if checked[cursor.call(loop.Cond, "Next")] {
					continue
				}
				line := fileCtx.LineFor(loop)
				if fileCtx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(fileCtx.RelPath, line, "Loop over SQL rows with no rows.Err() — an error mid-way ends the loop like the last row, and the partial list passes for the whole")
				v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
				v.WithSuggestion("After the loop: if err := rows.Err(); err != nil { return nil, err }")
				violations = append(violations, v)
			}
		}
		return violations
	})
}

// rowsCursor finds the calls on SQL rows in one function: by type, or in a
// file of a package that does not type-check, by a variable assigned from a
// Query call.
type rowsCursor struct {
	info    *types.Info
	queried map[string]bool
}

// call returns what identifies the rows of a call rows.<method>(), or nil.
func (c rowsCursor) call(expr ast.Expr, method string) any {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return nil
	}
	if c.info == nil {
		if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok && c.queried[id.Name] {
			return id.Name
		}
		return nil
	}
	if !isRowsType(c.info.TypeOf(sel.X)) {
		return nil
	}
	if obj := variableOf(c.info, ast.Unparen(sel.X)); obj != nil {
		return obj
	}
	return nil
}

// queriedNames are the variables a function assigns from a Query call
// (Query, QueryContext, Queryx, QueryxContext, NamedQuery...).
func queriedNames(body *ast.BlockStmt) map[string]bool {
	names := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !strings.Contains(sel.Sel.Name, "Query") || strings.Contains(sel.Sel.Name, "QueryRow") {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok {
			names[id.Name] = true
		}
		return true
	})
	return names
}

// functionBodies returns the bodies of a file's functions and function
// literals; each is analyzed on its own.
func functionBodies(file *ast.File) []*ast.BlockStmt {
	var bodies []*ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncDecl:
			if n.Body != nil {
				bodies = append(bodies, n.Body)
			}
		case *ast.FuncLit:
			bodies = append(bodies, n.Body)
		}
		return true
	})
	return bodies
}
