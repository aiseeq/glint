package security

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLInjectionRule())
}

// SQLInjectionRule detects potential SQL injection vulnerabilities
type SQLInjectionRule struct {
	*rules.BaseRule
}

// NewSQLInjectionRule creates the rule
func NewSQLInjectionRule() *SQLInjectionRule {
	return &SQLInjectionRule{
		BaseRule: rules.NewBaseRule(
			"sql-injection",
			"security",
			"Detects potential SQL injection through string concatenation in queries",
			core.SeverityCritical,
		),
	}
}

// AnalyzeFile checks for SQL injection patterns
func (r *SQLInjectionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Look for function calls to database methods
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check if it's a database query method
		if !r.isDBQueryMethod(call) {
			return true
		}

		// Check if first string argument uses concatenation or Sprintf
		if len(call.Args) == 0 {
			return true
		}

		arg := call.Args[0]

		// Check for string concatenation
		if binary, ok := arg.(*ast.BinaryExpr); ok {
			if r.isSQLConcatenation(binary) {
				pos := ctx.PositionFor(call)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Potential SQL injection: query built with string concatenation")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Use parameterized queries with $1, $2 or ? placeholders")
				v.WithContext("pattern", "concatenation")
				violations = append(violations, v)
			}
		}

		// Check for fmt.Sprintf
		if r.isFmtSprintfCall(arg) {
			pos := ctx.PositionFor(call)
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Potential SQL injection: query built with fmt.Sprintf")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Use parameterized queries instead of string formatting")
			v.WithContext("pattern", "sprintf")
			violations = append(violations, v)
		}

		return true
	})

	return violations
}

func (r *SQLInjectionRule) isDBQueryMethod(call *ast.CallExpr) bool {
	// Handle selector expressions like db.Query, tx.Exec
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	methodName := sel.Sel.Name
	dbMethods := []string{
		"Query", "QueryRow", "QueryContext", "QueryRowContext",
		"Exec", "ExecContext",
		"Prepare", "PrepareContext",
		"Get", "Select", "NamedExec", "NamedQuery",
		"Queryx", "QueryRowx", "MustExec",
	}

	for _, m := range dbMethods {
		if methodName == m {
			return true
		}
	}

	return false
}

func (r *SQLInjectionRule) isSQLConcatenation(binary *ast.BinaryExpr) bool {
	// Check if this is string concatenation (+)
	if binary.Op.String() != "+" {
		return false
	}

	// Check if either side looks like a SQL query
	return r.looksLikeSQL(binary.X) || r.looksLikeSQL(binary.Y)
}

func (r *SQLInjectionRule) looksLikeSQL(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return false
	}

	value := strings.ToUpper(lit.Value)
	sqlKeywords := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE",
		"JOIN", "ORDER BY", "GROUP BY", "HAVING", "UNION",
	}

	for _, keyword := range sqlKeywords {
		if strings.Contains(value, keyword) {
			return true
		}
	}

	return false
}

func (r *SQLInjectionRule) isFmtSprintfCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}

	// Check for fmt.Sprintf
	if ident.Name == "fmt" && sel.Sel.Name == "Sprintf" {
		// Check if first argument looks like SQL
		if len(call.Args) > 0 {
			if lit, ok := call.Args[0].(*ast.BasicLit); ok {
				return r.looksLikeSQLFromLit(lit)
			}
		}
	}

	return false
}

func (r *SQLInjectionRule) looksLikeSQLFromLit(lit *ast.BasicLit) bool {
	value := strings.ToUpper(lit.Value)
	sqlKeywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"}

	for _, keyword := range sqlKeywords {
		if strings.Contains(value, keyword) {
			return true
		}
	}

	return false
}
