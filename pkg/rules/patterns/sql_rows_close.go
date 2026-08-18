package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewSQLRowsCloseRule())
}

// SQLRowsCloseRule detects SQL rows not being closed
type SQLRowsCloseRule struct {
	*rules.BaseRule
}

// NewSQLRowsCloseRule creates the rule
func NewSQLRowsCloseRule() *SQLRowsCloseRule {
	return &SQLRowsCloseRule{
		BaseRule: rules.NewBaseRule(
			"sql-rows-close",
			"patterns",
			"Detects SQL rows not being closed (connection leak)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks for unclosed SQL rows
func (r *SQLRowsCloseRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}
	return helpers.AnalyzeFuncBodies(ctx, r.checkFunction)
}

func (r *SQLRowsCloseRule) checkFunction(ctx *core.FileContext, body *ast.BlockStmt, violations *[]*core.Violation) {
	// Track rows variable names
	rowsVars := make(map[string]int) // varName -> line

	ast.Inspect(body, func(n ast.Node) bool {
		// Skip nested function literals
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}

		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		// Check for rows, err := db.Query(...) or similar
		if len(assign.Lhs) >= 1 && len(assign.Rhs) == 1 {
			if r.isQueryCall(assign.Rhs[0]) {
				if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name != "_" {
					rowsVars[ident.Name] = r.getLineFromNode(ctx, assign)
				}
			}
		}

		return true
	})

	if len(rowsVars) == 0 {
		return
	}

	closedVars := r.closedOrHandedOff(ctx, body)

	// Report unclosed rows
	for varName, line := range rowsVars {
		if !closedVars[varName] {
			v := r.CreateViolation(ctx.RelPath, line, "SQL rows not closed - connection leak")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Add defer " + varName + ".Close() after error check")
			v.WithContext("pattern", "sql_rows_leak")
			v.WithContext("variable", varName)
			*violations = append(*violations, v)
		}
	}
}

// closedOrHandedOff returns the rows variables that body closes itself, or
// hands off: returned to the caller, or passed as an argument to a call. Once
// the rows are handed off, closing is the recipient's job. A recipient declared
// in the same file is checked: if it never closes its parameter, the rows are
// still reported here — the leak is real, only one call away.
func (r *SQLRowsCloseRule) closedOrHandedOff(ctx *core.FileContext, body *ast.BlockStmt) map[string]bool {
	closed := make(map[string]bool)

	// Check for defer rows.Close() or rows.Close()
	// Also check inside function literals like: defer func() { _ = rows.Close() }()
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if varName := r.getCloseVar(node); varName != "" {
				closed[varName] = true
			}
			for i, arg := range node.Args {
				ident, ok := arg.(*ast.Ident)
				if !ok {
					continue
				}
				if r.recipientCloses(ctx, node.Fun, i) {
					closed[ident.Name] = true
				}
			}
		case *ast.ReturnStmt:
			for _, res := range node.Results {
				if ident, ok := res.(*ast.Ident); ok {
					closed[ident.Name] = true
				}
			}
		}
		return true
	})
	return closed
}

// recipientCloses reports whether the callee closes its argIndex-th parameter.
// A callee that is not a plain function declared in this file cannot be
// inspected, so it is trusted with the rows it received.
func (r *SQLRowsCloseRule) recipientCloses(ctx *core.FileContext, fun ast.Expr, argIndex int) bool {
	ident, ok := fun.(*ast.Ident)
	if !ok {
		return true
	}
	decl := findFuncDecl(ctx.GoAST, ident.Name)
	if decl == nil || decl.Body == nil {
		return true
	}
	paramName := paramNameAt(decl.Type, argIndex)
	if paramName == "" {
		return true
	}
	closes := false
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if closes {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && r.getCloseVar(call) == paramName {
			closes = true
		}
		return true
	})
	return closes
}

// findFuncDecl returns the package-level function named name, or nil.
func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	if file == nil {
		return nil
	}
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// paramNameAt returns the name of the index-th parameter, counting grouped
// names (a, b T) separately; "" when the parameter is unnamed or absent.
func paramNameAt(ft *ast.FuncType, index int) string {
	if ft == nil || ft.Params == nil {
		return ""
	}
	i := 0
	for _, field := range ft.Params.List {
		if len(field.Names) == 0 {
			if i == index {
				return ""
			}
			i++
			continue
		}
		for _, n := range field.Names {
			if i == index {
				return n.Name
			}
			i++
		}
	}
	return ""
}

func (r *SQLRowsCloseRule) isQueryCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	method := sel.Sel.Name

	// Check for db.Query, db.QueryContext, db.QueryRow is NOT included (returns *Row, not *Rows)
	sqlMethods := map[string]bool{
		"Query": true, "QueryContext": true,
		"QueryxContext": true, "Queryx": true,
		"NamedQuery": true, "NamedQueryContext": true,
	}

	if !sqlMethods[method] {
		return false
	}

	// Check that receiver looks like a database connection
	// Exclude URL.Query() and similar non-database Query methods
	receiverName := r.getReceiverName(sel.X)
	if receiverName == "URL" || receiverName == "url" {
		return false // URL.Query() returns url.Values, not *sql.Rows
	}

	return true
}

func (r *SQLRowsCloseRule) getReceiverName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		// For chains like r.URL.Query(), get the last selector
		return e.Sel.Name
	}
	return ""
}

func (r *SQLRowsCloseRule) getCloseVar(call *ast.CallExpr) string {
	// Looking for rows.Close()
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Close" {
		return ""
	}

	// Get the variable name
	if ident, ok := sel.X.(*ast.Ident); ok {
		return ident.Name
	}

	return ""
}

func (r *SQLRowsCloseRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
	return ctx.LineFor(node)
}
