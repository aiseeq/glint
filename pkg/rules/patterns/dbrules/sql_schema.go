package dbrules

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLUnknownColumnRule())
	rules.Register(NewSQLInsertMissingNotNullRule())
}

// SQLUnknownColumnRule detects SQL written in Go string literals that names a
// table or a column the project's migrations never created:
//
//	SELECT 1 FROM orders WHERE chain_ref = $1                -- the column is ref
//	SELECT COUNT(*) FROM holdings WHERE status = 'active'    -- holdings has no status
//
// The query compiles and fails on its first run — often inside an error
// branch that turns the failure into an empty result. The schema is the one
// the up migrations leave (directories named migrations, or the migrations
// setting, comma-separated, relative to the project root). A literal is
// checked when it parses as a whole statement; fmt verbs count as parameters;
// a table the file itself creates, a temporary one, is known. A migration
// that does not parse is reported on the migration, and so is an ALTER of a
// table only a later migration creates: a fresh database fails there.
type SQLUnknownColumnRule struct {
	*rules.BaseRule
}

func migrationSettingSpec() rules.SettingSpec {
	return rules.NewSettingSpec("migrations", "string", "", "Comma-separated migration directories used to build the SQL schema.", "db/migrations")
}

// NewSQLUnknownColumnRule creates the rule
func NewSQLUnknownColumnRule() *SQLUnknownColumnRule {
	return &SQLUnknownColumnRule{BaseRule: rules.NewBaseRule(
		"sql-unknown-column",
		"patterns",
		"Detects SQL in Go string literals naming a table or a column the migrations never created",
		core.SeverityHigh,
	).DeclareSettings(rules.NewSettingSpec("migrations", "string", "", "Comma-separated migration directories used to build the SQL schema.", "db/migrations"))}
}

// ReadsOtherFiles reports that the findings depend on the migrations.
func (r *SQLUnknownColumnRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile checks the SQL literals of a Go file against the schema.
func (r *SQLUnknownColumnRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return analyzeSQLAgainstSchema(ctx, r.BaseRule, map[string]string{
		"unknown_table":       "Table %[1]s is not created by any migration — the query fails on its first run",
		"unknown_column":      "Column %[1]s is not in %[2]s as the migrations leave it — the query fails on its first run",
		"alter_before_create": "",
	}, "Name the column or the table the schema has, or add the migration that creates it", nil)
}

// SQLInsertMissingNotNullRule detects an INSERT in a Go string literal whose
// column list leaves out a NOT NULL column without a default:
//
//	INSERT INTO orders (id, user_id, amount, created_at) VALUES ($1, $2, $3, $4)
//	-- updated_at is NOT NULL and has no default
//
// The statement fails with a not-null violation on every run. A listed NOT
// NULL column bound through a conversion that makes an empty string NULL
// (nullStr(s), sql.NullString{Valid: s != ""}) fails for every empty value.
type SQLInsertMissingNotNullRule struct {
	*rules.BaseRule
}

// NewSQLInsertMissingNotNullRule creates the rule
func NewSQLInsertMissingNotNullRule() *SQLInsertMissingNotNullRule {
	return &SQLInsertMissingNotNullRule{BaseRule: rules.NewBaseRule(
		"sql-insert-missing-not-null",
		"patterns",
		"Detects an INSERT whose column list leaves out a NOT NULL column that has no default, or a NOT NULL column bound through a conversion that makes an empty string NULL",
		core.SeverityHigh,
	).DeclareSettings(rules.NewSettingSpec("migrations", "string", "", "Comma-separated migration directories used to build the SQL schema.", "db/migrations"))}
}

// ReadsOtherFiles reports that the findings depend on the migrations.
func (r *SQLInsertMissingNotNullRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile checks the INSERT literals of a Go file against the schema.
func (r *SQLInsertMissingNotNullRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return analyzeSQLAgainstSchema(ctx, r.BaseRule, map[string]string{
		"missing_not_null": "INSERT into %[2]s leaves out %[1]s, NOT NULL without a default — the statement fails on every run",
	}, "List the column with a value, or give it a default in a migration", func(schema *sqlschema.Schema) []*core.Violation {
		return r.nullForEmptyBinds(ctx, schema)
	})
}

// nullForEmptyBinds reports a NOT NULL column an INSERT or an UPDATE binds
// through a helper that turns an empty string into NULL (nullStr(s),
// sql.NullString{Valid: s != ""}): the column is listed, and the statement
// still fails for every empty value.
func (r *SQLInsertMissingNotNullRule) nullForEmptyBinds(ctx *core.FileContext, schema *sqlschema.Schema) []*core.Violation {
	helpers := nullForEmptyHelpers(ctx.GoAST)
	fileQueries := namedStrings(ctx.GoAST)
	var violations []*core.Violation
	var queries map[string]ast.Expr
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			// A query variable is resolved within its function: every
			// repository method has its own query := `...`.
			queries = namedStrings(fn)
			return true
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for i, arg := range call.Args {
			if ident, ok := arg.(*ast.Ident); ok {
				if value := queries[ident.Name]; value != nil {
					arg = value
				} else if value := fileQueries[ident.Name]; value != nil {
					arg = value
				}
			}
			if !patternkit.IsStringOrConcat(arg) {
				continue
			}
			literals := patternkit.SqlLiterals(arg)
			if len(literals) != 1 {
				continue
			}
			text := literals[0].Text
			if literals[0].Bare != "" {
				text = literals[0].Bare
			}
			binds := schema.NotNullBinds(text)
			for _, param := range slices.Sorted(maps.Keys(binds)) {
				if i+param >= len(call.Args) {
					continue
				}
				column, bound := binds[param], call.Args[i+param]
				if !nullForEmpty(bound, helpers) {
					continue
				}
				line := ctx.LineFor(bound)
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, line, "Column "+column+" is NOT NULL, but its value is bound through a conversion that makes an empty string NULL — the statement fails for every empty "+column)
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Bind the string as it is (the column takes '' or its default), or make the column nullable if absence is meant")
				v.WithContext("pattern", "null_for_empty_bind")
				violations = append(violations, v)
			}
			break
		}
		return true
	})
	return violations
}

// namedStrings maps the names a node gives to one string value (a const, or
// a variable assigned once: query := `INSERT ...`) to that value; a name
// assigned more than once is left out.
func namedStrings(root ast.Node) map[string]ast.Expr {
	values := make(map[string]ast.Expr)
	counts := make(map[string]int)
	record := func(name *ast.Ident, value ast.Expr) {
		counts[name.Name]++
		if patternkit.IsStringOrConcat(value) {
			values[name.Name] = value
		}
	}
	ast.Inspect(root, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						record(ident, node.Rhs[i])
					}
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) == len(node.Values) {
				for i, name := range node.Names {
					record(name, node.Values[i])
				}
			}
		}
		return true
	})
	for name, count := range counts {
		if count != 1 {
			delete(values, name)
		}
	}
	return values
}

// nullForEmptyHelpers returns the names of the file's functions of one string
// parameter that return nil for an empty string.
func nullForEmptyHelpers(file *ast.File) map[string]bool {
	helpers := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) != 1 {
			continue
		}
		if ident, ok := fn.Type.Params.List[0].Type.(*ast.Ident); !ok || ident.Name != "string" {
			continue
		}
		param := fn.Type.Params.List[0].Names[0].Name
		for _, stmt := range fn.Body.List {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if ok && comparesEmpty(ifStmt.Cond, param, token.EQL) && patternkit.BlockBranches(ifStmt.Body, returnsNil) {
				helpers[fn.Name.Name] = true
			}
		}
	}
	return helpers
}

// nullForEmpty reports a bound value that is NULL for an empty string: a
// call of such a helper, or sql.NullString{Valid: s != ""}.
func nullForEmpty(expr ast.Expr, helpers map[string]bool) bool {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		if ident, ok := expr.Fun.(*ast.Ident); ok {
			return helpers[ident.Name]
		}
	case *ast.CompositeLit:
		for _, elt := range expr.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if key, isIdent := kv.Key.(*ast.Ident); ok && isIdent && key.Name == "Valid" {
				return comparesEmpty(kv.Value, "", token.NEQ)
			}
		}
	}
	return false
}

// comparesEmpty reports a comparison of the named variable (any, for "")
// with "" by op.
func comparesEmpty(cond ast.Expr, name string, op token.Token) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != op {
		return false
	}
	lit, ok := bin.Y.(*ast.BasicLit)
	if !ok || lit.Value != `""` {
		return false
	}
	ident, ok := bin.X.(*ast.Ident)
	return ok && (name == "" || ident.Name == name)
}

// returnsNil reports a return statement whose only result is nil.
func returnsNil(stmt ast.Stmt) bool {
	ret, ok := stmt.(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	ident, ok := ret.Results[0].(*ast.Ident)
	return ok && ident.Name == "nil"
}

// analyzeSQLAgainstSchema checks the SQL of a file against the schema of its
// migrations; extra, when set, adds the checks of a rule that need the loaded
// schema and the Go syntax of the file.
func analyzeSQLAgainstSchema(ctx *core.FileContext, rule *rules.BaseRule, messages map[string]string, suggestion string, extra func(*sqlschema.Schema) []*core.Violation) []*core.Violation {
	if ctx.IsTestFile() || ctx.ProjectRoot == "" {
		return nil
	}
	schema, err := sqlschema.LoadCached(ctx.ProjectRoot, patternkit.MigrationDirs(rule))
	if strings.EqualFold(filepath.Ext(ctx.RelPath), ".sql") {
		_, reportFaults := messages["alter_before_create"]
		return migrationViolations(ctx, rule, schema, err, reportFaults)
	}
	var migrationErr *sqlschema.MigrationError
	if errors.As(err, &migrationErr) {
		return nil // reported on the migration by migrationViolations; nothing to check against
	}
	if err != nil {
		v := rule.CreateViolation(ctx.RelPath, 1, "The migrations cannot be listed, so the SQL was not checked against the schema: "+err.Error())
		v.Severity = core.SeverityCritical
		v.WithSuggestion("Point the migrations setting at the directories that hold the schema")
		return []*core.Violation{v}
	}
	if schema == nil || !ctx.HasGoAST() {
		return nil
	}
	var violations []*core.Violation
	if extra != nil {
		violations = extra(schema)
	}
	literals := patternkit.SqlLiterals(ctx.GoAST)
	var created []string
	for _, literal := range literals {
		if sqlCreate.MatchString(literal.Text) {
			created = append(created, literal.Text)
		}
	}
	if len(created) > 0 {
		schema = schema.With(created)
	}
	for _, literal := range literals {
		problems, ok := schema.CheckQuery(literal.Text)
		if !ok {
			continue
		}
		for _, problem := range problems {
			format, wanted := messages[problem.Kind]
			if !wanted {
				continue
			}
			line := literal.LineAt(ctx, problem.Offset)
			if ctx.IsSuppressed(line, rule.Name()) {
				continue
			}
			v := rule.CreateViolation(ctx.RelPath, line, fmt.Sprintf(format, problem.Name, problem.Table))
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion(suggestion)
			v.WithContext("pattern", problem.Kind)
			violations = append(violations, v)
		}
	}
	return violations
}

// migrationViolations reports what is wrong with a migration file itself:
// that it does not parse, so no SQL was checked, and — with reportFaults —
// the ALTERs of tables a later migration creates.
func migrationViolations(ctx *core.FileContext, rule *rules.BaseRule, schema *sqlschema.Schema, err error, reportFaults bool) []*core.Violation {
	var migrationErr *sqlschema.MigrationError
	if errors.As(err, &migrationErr) {
		if patternkit.ProjectRelPath(ctx.ProjectRoot, migrationErr.Path) != ctx.RelPath {
			return nil
		}
		v := rule.CreateViolation(ctx.RelPath, 1, "The migration cannot be read, so the SQL was not checked against the schema: "+migrationErr.Err.Error())
		v.Severity = core.SeverityCritical
		v.WithSuggestion("Fix the migration, or point the migrations setting at the directories that hold the schema")
		return []*core.Violation{v}
	}
	if schema == nil || !reportFaults {
		return nil
	}
	var violations []*core.Violation
	for _, fault := range schema.Faults {
		if patternkit.ProjectRelPath(ctx.ProjectRoot, fault.Path) != ctx.RelPath || ctx.IsSuppressed(fault.Line, rule.Name()) {
			continue
		}
		v := rule.CreateViolation(ctx.RelPath, fault.Line, fmt.Sprintf(
			"ALTER TABLE %s runs before any migration creates the table — migrating a fresh database fails here", fault.Table))
		v.WithCode(strings.TrimSpace(ctx.GetLine(fault.Line)))
		v.WithSuggestion("Move the change into a migration numbered after the one that creates the table")
		v.WithContext("pattern", "alter_before_create")
		violations = append(violations, v)
	}
	return violations
}

// sqlCreate is a statement creating a table in the code.
var sqlCreate = regexp.MustCompile(`(?i)^\s*create\s+(?:(?:global|local)\s+)?(?:temp|temporary|unlogged\s+)?\s*table\s`)

// sqlQueryPart is text that holds a query or a part of one: a condition
// written apart from its statement (EXISTS (SELECT ...)).
var sqlQueryPart = regexp.MustCompile(`(?i)\bselect\b|\bjoin\b`)

// sqlFragments returns the string literals and concatenations of literals
// under a node that hold a query or a part of one, wherever it begins.
func sqlFragments(root ast.Node) []patternkit.SqlLiteral {
	return patternkit.SqlTexts(root, sqlQueryPart.MatchString)
}
