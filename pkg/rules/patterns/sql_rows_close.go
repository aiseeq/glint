package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		r.checkFunction(ctx, fn.Body, &violations)

		return true
	})

	return violations
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

	// Check for defer rows.Close() or rows.Close()
	// Also check inside function literals like: defer func() { _ = rows.Close() }()
	closedVars := make(map[string]bool)

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		if varName := r.getCloseVar(call); varName != "" {
			closedVars[varName] = true
		}

		return true
	})

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
	if node == nil {
		return 1
	}

	pos := node.Pos()
	if pos == 0 {
		return 1
	}

	offset := int(pos) - 1
	if offset < 0 || offset >= len(ctx.Content) {
		return 1
	}

	line := 1
	for i := 0; i < offset && i < len(ctx.Content); i++ {
		if ctx.Content[i] == '\n' {
			line++
		}
	}
	return line
}
