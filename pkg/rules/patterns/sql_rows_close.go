package patterns

import (
	"go/ast"
	"go/types"

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

// AnalyzeFile is a no-op: whether a Query call yields rows is a question about
// its result type — url.Values and a query-string getter are spelled the same.
func (r *SQLRowsCloseRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLRowsCloseRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports rows no path closes or hands on.
func (r *SQLRowsCloseRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), r.analyzeFile)
}

// analyzeFile checks every function of the file, function literals included.
// Rows are any value a call returns whose type is *database/sql.Rows or has
// the cursor methods Close, Next, Scan and Err (sqlx, pgx and the like).
func (r *SQLRowsCloseRule) analyzeFile(ctx *core.FileContext, info *types.Info) []*core.Violation {
	check := &resourceLeakCheck{
		file: ctx.GoAST,
		info: info,
		opens: func(expr ast.Expr) bool {
			_, isCall := ast.Unparen(expr).(*ast.CallExpr)
			return isCall && isRowsType(firstResultType(info, expr))
		},
		releases: func(call *ast.CallExpr) types.Object {
			// rows.Close()
			sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Close" {
				return nil
			}
			return variableOf(info, ast.Unparen(sel.X))
		},
		carries: func(expr ast.Expr) types.Object {
			return variableOf(info, expr)
		},
	}

	var violations []*core.Violation
	for _, leak := range check.leaks() {
		line := ctx.LineFor(leak.at)
		v := r.CreateViolation(ctx.RelPath, line, "SQL rows not closed - connection leak")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Add defer " + leak.name + ".Close() after error check")
		v.WithContext("pattern", "sql_rows_leak")
		v.WithContext("variable", leak.name)
		violations = append(violations, v)
	}
	return violations
}

// rowsCursorMethods are the methods every SQL row cursor has; *sql.Row lacks
// Close and Next, url.Values lacks them all.
var rowsCursorMethods = []string{"Close", "Next", "Scan", "Err"}

// isRowsType reports whether t is *database/sql.Rows or a cursor type with
// the same methods.
func isRowsType(t types.Type) bool {
	if t == nil {
		return false
	}
	if isPointerToNamedType(t, "database/sql", "Rows") {
		return true
	}
	for _, method := range rowsCursorMethods {
		obj, _, _ := types.LookupFieldOrMethod(t, true, nil, method)
		if _, isMethod := obj.(*types.Func); !isMethod {
			return false
		}
	}
	return true
}
