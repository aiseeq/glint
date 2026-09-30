package security

import (
	"go/ast"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLInjectionRule())
}

// SQLInjectionRule detects SQL queries whose text, by string concatenation or
// fmt.Sprintf, takes in a string that came from outside the function - a
// parameter, a field of one, an element ranged from one - without a whitelist
// check, and is handed to a database call.
//
// The query argument is found by the callee's signature, not by position: it
// is the string parameter named query or sql of a method declared in a known
// database package (database/sql, sqlx, pgx), or of a method with a database
// method name (Query, ExecContext, Get, ...) declared elsewhere - a wrapper or
// a DBTX-style interface. Where the text comes from is judged by
// sqlTaintCheck: constants, numbers, placeholders built from counters and
// fragments returned by helpers carry no outside string.
type SQLInjectionRule struct {
	*rules.BaseRule
}

// NewSQLInjectionRule creates the rule
func NewSQLInjectionRule() *SQLInjectionRule {
	return &SQLInjectionRule{
		BaseRule: rules.NewBaseRule(
			"sql-injection",
			"security",
			"Detects SQL text built by string concatenation or fmt.Sprintf (directly or through local variables and slices) from a string parameter of the enclosing function, a field of one or an element ranged from one, not checked against a whitelist, and passed as the query parameter of a database/sql, sqlx or pgx call or of a wrapper method with a query/sql parameter",
			core.SeverityCritical,
		),
	}
}

// sqlDatabasePackages are the import path prefixes whose methods take a query.
var sqlDatabasePackages = []string{
	"database/sql",
	"github.com/jmoiron/sqlx",
	"github.com/jackc/pgx",
}

// sqlQueryMethods are the method names that run or prepare a query. A method
// outside sqlDatabasePackages is a database call only under one of these names.
var sqlQueryMethods = map[string]bool{
	"Query": true, "QueryRow": true, "QueryContext": true, "QueryRowContext": true,
	"Exec": true, "ExecContext": true,
	"Prepare": true, "PrepareContext": true,
	"Get": true, "GetContext": true, "Select": true, "SelectContext": true,
	"NamedExec": true, "NamedExecContext": true, "NamedQuery": true, "NamedQueryContext": true,
	"Queryx": true, "QueryxContext": true, "QueryRowx": true, "QueryRowxContext": true,
	"MustExec": true, "MustExecContext": true,
	"Preparex": true, "PreparexContext": true, "PrepareNamed": true, "PrepareNamedContext": true,
	"Queue": true,
}

// sqlQueryParamNames are the parameter names database APIs give the query.
var sqlQueryParamNames = map[string]bool{"query": true, "sql": true}

// sqlKeyword finds an SQL keyword as a whole word: "lastUpdated:" holds no
// UPDATE.
var sqlKeyword = regexp.MustCompile(`(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|ORDER\s+BY|GROUP\s+BY|HAVING|UNION)\b`)

// AnalyzeFile has no type information and so cannot tell a database call from
// any other method with the same name: it reports nothing.
func (r *SQLInjectionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLInjectionRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every type-checked file.
func (r *SQLInjectionRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks the database calls of one file. Without type information the
// callee is unknown, and the rule stays silent.
func (r *SQLInjectionRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if info == nil || !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}
	// Test files and test infrastructure build DDL, which takes no parameters.
	if ctx.IsTestFile() || strings.Contains(ctx.RelPath, "/testing/") {
		return nil
	}

	check := newSQLTaintCheck(ctx.GoAST, info)
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		query := sqlQueryArgument(call, info)
		if query == nil {
			return true
		}
		pattern := check.injectedPattern(query)
		if pattern == "" {
			return true
		}
		pos := ctx.PositionFor(call)
		message := "Potential SQL injection: query built with string concatenation"
		suggestion := "Use parameterized queries with $1, $2 or ? placeholders"
		if pattern == "sprintf" {
			message = "Potential SQL injection: query built with fmt.Sprintf"
			suggestion = "Use parameterized queries instead of string formatting"
		}
		v := r.CreateViolation(ctx.RelPath, pos.Line, message)
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion(suggestion)
		v.WithContext("pattern", pattern)
		violations = append(violations, v)
		return true
	})
	return violations
}

// sqlQueryArgument returns the argument a call passes as its query parameter,
// or nil when the callee is not a database call.
func sqlQueryArgument(call *ast.CallExpr, info *types.Info) ast.Expr {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return nil
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	if !sqlQueryMethods[fn.Name()] && !isSQLDatabasePackage(fn.Pkg().Path()) {
		return nil
	}
	params := sig.Params()
	for i := 0; i < params.Len() && i < len(call.Args); i++ {
		param := params.At(i)
		if sig.Variadic() && i == params.Len()-1 {
			break
		}
		if !sqlQueryParamNames[param.Name()] {
			continue
		}
		if basic, ok := param.Type().Underlying().(*types.Basic); ok && basic.Info()&types.IsString != 0 {
			return call.Args[i]
		}
	}
	return nil
}

func isSQLDatabasePackage(path string) bool {
	for _, prefix := range sqlDatabasePackages {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}
