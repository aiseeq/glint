package security

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLInjectionRule())
}

// SQLInjectionRule detects SQL queries assembled from runtime values by
// string concatenation or fmt.Sprintf and handed to a database call.
//
// The query argument is found by the callee's signature, not by position: it
// is the string parameter named query or sql of a method declared in a known
// database package (database/sql, sqlx, pgx), or of a method with a database
// method name (Query, ExecContext, Get, ...) declared elsewhere - a wrapper or
// a DBTX-style interface. Operands that are Go constants are not runtime
// values: "SELECT * FROM " + usersTable with a constant table is safe.
type SQLInjectionRule struct {
	*rules.BaseRule
}

// NewSQLInjectionRule creates the rule
func NewSQLInjectionRule() *SQLInjectionRule {
	return &SQLInjectionRule{
		BaseRule: rules.NewBaseRule(
			"sql-injection",
			"security",
			"Detects SQL queries built from non-constant values by string concatenation or fmt.Sprintf (directly or through a local variable) and passed as the query parameter of a database/sql, sqlx or pgx call or of a wrapper method with a query/sql parameter",
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

	check := sqlQueryCheck{info: info, assigned: localAssignments(ctx.GoAST, info)}
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
		pattern := check.unsafe(query, map[*types.Var]bool{})
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

// localAssignments maps each variable of the file to the values assigned to
// it, so a query held in a variable is judged by what was put there. A
// compound assignment q += x is recorded as the concatenation it performs. A
// nil value stands for a source the rule does not model: a parameter, a range
// variable, one result of a multi-value call.
func localAssignments(file *ast.File, info *types.Info) map[*types.Var][]ast.Expr {
	assigned := make(map[*types.Var][]ast.Expr)
	record := func(ident *ast.Ident, value ast.Expr) {
		obj := info.ObjectOf(ident)
		if v, ok := obj.(*types.Var); ok && !v.IsField() {
			assigned[v] = append(assigned[v], value)
		}
	}
	recordFields := func(fields *ast.FieldList) {
		if fields == nil {
			return
		}
		for _, field := range fields.List {
			for _, name := range field.Names {
				record(name, nil)
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncType:
			recordFields(node.Params)
			recordFields(node.Results)
		case *ast.RangeStmt:
			for _, target := range []ast.Expr{node.Key, node.Value} {
				if ident, ok := target.(*ast.Ident); ok {
					record(ident, nil)
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				var value ast.Expr
				if len(node.Lhs) == len(node.Rhs) {
					value = node.Rhs[i]
					if node.Tok == token.ADD_ASSIGN {
						value = &ast.BinaryExpr{X: ident, OpPos: node.TokPos, Op: token.ADD, Y: node.Rhs[i]}
					}
				}
				record(ident, value)
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				var value ast.Expr
				switch {
				case len(node.Names) == len(node.Values):
					value = node.Values[i]
				case len(node.Values) == 0:
					// var q string: the zero value is a constant "".
					value = &ast.BasicLit{ValuePos: name.Pos(), Kind: token.STRING, Value: `""`}
				}
				record(name, value)
			}
		}
		return true
	})
	return assigned
}

type sqlQueryCheck struct {
	info     *types.Info
	assigned map[*types.Var][]ast.Expr
}

// unsafe reports how a query expression mixes runtime values into SQL text:
// "concatenation", "sprintf", or "" when it does not. visiting guards against
// a variable assigned from itself.
func (c sqlQueryCheck) unsafe(expr ast.Expr, visiting map[*types.Var]bool) string {
	expr = ast.Unparen(expr)
	if c.isConstant(expr) {
		return ""
	}
	switch node := expr.(type) {
	case *ast.BinaryExpr:
		if node.Op == token.ADD && c.isDynamicSQLConcatenation(node, visiting) {
			return "concatenation"
		}
	case *ast.CallExpr:
		if c.isDynamicSQLSprintf(node) {
			return "sprintf"
		}
	case *ast.Ident:
		v, ok := c.info.Uses[node].(*types.Var)
		if !ok || visiting[v] {
			return ""
		}
		visiting[v] = true
		defer delete(visiting, v)
		for _, value := range c.assigned[v] {
			if value == nil {
				continue
			}
			if pattern := c.unsafe(value, visiting); pattern != "" {
				return pattern
			}
		}
	}
	return ""
}

// isStatic reports whether an expression holds only constant text: a Go
// constant, a concatenation of static parts, or a variable of this file every
// assignment of which is static. A variable of unknown source is not static.
func (c sqlQueryCheck) isStatic(expr ast.Expr, visiting map[*types.Var]bool) bool {
	expr = ast.Unparen(expr)
	if c.isConstant(expr) {
		return true
	}
	switch node := expr.(type) {
	case *ast.BasicLit:
		// The zero value localAssignments stands in for var q string.
		return node.Kind == token.STRING
	case *ast.BinaryExpr:
		return node.Op == token.ADD && c.isStatic(node.X, visiting) && c.isStatic(node.Y, visiting)
	case *ast.Ident:
		v, ok := c.info.Uses[node].(*types.Var)
		if !ok {
			return false
		}
		if visiting[v] {
			// A cycle adds no source beyond the assignments already checked.
			return true
		}
		values := c.assigned[v]
		if len(values) == 0 {
			return false
		}
		visiting[v] = true
		defer delete(visiting, v)
		for _, value := range values {
			if value == nil || !c.isStatic(value, visiting) {
				return false
			}
		}
		return true
	}
	return false
}

// isDynamicSQLConcatenation reports whether a chain of + joins SQL text with
// at least one runtime value. SQL text is a keyword in constant text the chain
// holds, directly or through a variable; an operand that itself holds an
// unsafe query (q + " LIMIT 1") makes the whole chain unsafe.
func (c sqlQueryCheck) isDynamicSQLConcatenation(binary *ast.BinaryExpr, visiting map[*types.Var]bool) bool {
	hasSQL, hasDynamic := false, false
	for _, operand := range concatOperands(binary) {
		if c.unsafe(operand, visiting) != "" {
			return true
		}
		if !hasSQL && c.mentionsSQL(operand, map[*types.Var]bool{}) {
			hasSQL = true
		}
		if !hasDynamic && !c.isStatic(operand, map[*types.Var]bool{}) {
			hasDynamic = true
		}
	}
	return hasSQL && hasDynamic
}

// mentionsSQL reports whether constant text an expression is built from holds
// an SQL keyword.
func (c sqlQueryCheck) mentionsSQL(expr ast.Expr, visiting map[*types.Var]bool) bool {
	expr = ast.Unparen(expr)
	if text, ok := c.constantString(expr); ok {
		return sqlKeyword.MatchString(text)
	}
	switch node := expr.(type) {
	case *ast.BinaryExpr:
		return node.Op == token.ADD && (c.mentionsSQL(node.X, visiting) || c.mentionsSQL(node.Y, visiting))
	case *ast.Ident:
		v, ok := c.info.Uses[node].(*types.Var)
		if !ok || visiting[v] {
			return false
		}
		visiting[v] = true
		for _, value := range c.assigned[v] {
			if value != nil && c.mentionsSQL(value, visiting) {
				return true
			}
		}
	}
	return false
}

// isDynamicSQLSprintf reports whether a call is fmt.Sprintf with a constant
// SQL format and at least one runtime argument.
func (c sqlQueryCheck) isDynamicSQLSprintf(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) < 2 {
		return false
	}
	fn, ok := c.info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "fmt" || fn.Name() != "Sprintf" {
		return false
	}
	format, ok := c.constantString(call.Args[0])
	if !ok || !sqlKeyword.MatchString(format) {
		return false
	}
	for _, arg := range call.Args[1:] {
		if !c.isConstant(arg) {
			return true
		}
	}
	return false
}

func (c sqlQueryCheck) isConstant(expr ast.Expr) bool {
	tv, ok := c.info.Types[expr]
	return ok && tv.Value != nil
}

func (c sqlQueryCheck) constantString(expr ast.Expr) (string, bool) {
	tv, ok := c.info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

// concatOperands flattens a + chain into its operands.
func concatOperands(expr ast.Expr) []ast.Expr {
	expr = ast.Unparen(expr)
	if binary, ok := expr.(*ast.BinaryExpr); ok && binary.Op == token.ADD {
		return append(concatOperands(binary.X), concatOperands(binary.Y)...)
	}
	return []ast.Expr{expr}
}
