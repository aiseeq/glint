package patterns

import (
	"go/ast"
	"go/token"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLLimitWithoutOrderRule())
	rules.Register(NewSQLRuntimeDDLRule())
	rules.Register(NewSQLGroupBySingleRowRule())
	rules.Register(NewSQLUpsertFreshKeyRule())
	rules.Register(NewSQLConstantShadowsColumnRule())
	rules.Register(NewSQLTestDDLDuplicatesMigrationRule())
}

// productionGoFile is a Go file the SQL rules read: parsed, not a test.
func productionGoFile(ctx *core.FileContext) bool {
	return ctx.IsGoFile() && ctx.HasGoAST() && !ctx.IsTestFile()
}

// fileSchema returns the schema the migrations leave, nil for a project
// without migrations; false when the migrations do not load - the SQL rules
// report that on the migration, and nothing here can be checked.
func fileSchema(ctx *core.FileContext, rule *rules.BaseRule) (*sqlschema.Schema, bool) {
	if ctx.ProjectRoot == "" {
		return nil, true
	}
	schema, err := sqlschema.LoadCached(ctx.ProjectRoot, migrationDirs(rule))
	return schema, err == nil
}

func sqlViolation(rule *rules.BaseRule, ctx *core.FileContext, line int, message, suggestion string) *core.Violation {
	v := rule.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(suggestion)
	return v
}

// SQLLimitWithoutOrderRule detects a SELECT that takes its first rows by
// LIMIT with no ORDER BY:
//
//	COALESCE(t.to_address, (SELECT address FROM wallets WHERE user_id = t.user_id LIMIT 1))
//
// Which row comes first is up to the plan: a user with two wallets gets
// either address, and a page without an order repeats and skips rows.
// Not reported: a SELECT under EXISTS, one returning only aggregates, one
// locking its rows (FOR UPDATE SKIP LOCKED takes any free rows on purpose),
// one whose WHERE fixes a row of its only table (an id, a unique key of the
// migrations), one reading a migration tool's table.
//
// An ORDER BY on date columns alone, over a table whose unique keys the sort
// and the WHERE do not cover, is reported too: rows of one day come in plan
// order, and a consumer burning them first-in first-out takes another one.
type SQLLimitWithoutOrderRule struct {
	*rules.BaseRule
}

// NewSQLLimitWithoutOrderRule creates the rule
func NewSQLLimitWithoutOrderRule() *SQLLimitWithoutOrderRule {
	return &SQLLimitWithoutOrderRule{BaseRule: rules.NewBaseRule(
		"sql-limit-without-order",
		"patterns",
		"Detects a SELECT whose row order is up to the plan: LIMIT with no ORDER BY, or ORDER BY a date column alone",
		core.SeverityMedium,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations' unique keys.
func (r *SQLLimitWithoutOrderRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports the unordered LIMITs of a file's SQL.
func (r *SQLLimitWithoutOrderRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok {
		return nil
	}
	var violations []*core.Violation
	for _, literal := range sqlLiterals(ctx.GoAST) {
		for _, offset := range schema.UnorderedLimits(literal.text) {
			line := literal.lineAt(ctx, offset)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"LIMIT with no ORDER BY — which rows come first is up to the query plan, and it changes with the data",
				"Order by what decides which row is wanted (ORDER BY created_at DESC, id), or aggregate if any row will do"))
		}
		for _, offset := range schema.DateOnlyOrders(literal.text) {
			line := literal.lineAt(ctx, offset)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"ORDER BY a date alone — rows of one day come in plan order, and whoever takes them first-in first-out takes another row when the plan changes",
				"Add a unique tiebreaker after the date (created_at, id)"))
		}
	}
	return violations
}

// SQLConstantShadowsColumnRule detects a constant a SELECT names as a column
// of a table it reads:
//
//	SELECT t.id, t.amount, 'completed' AS status FROM transfers t WHERE t.user_id = $1
//
// The result reads like the table's status, but every row shows the
// constant: a pending or failed row is reported as completed. Not reported:
// NULL, a column the WHERE pins to a value, and the SELECT of an INSERT.
type SQLConstantShadowsColumnRule struct {
	*rules.BaseRule
}

// NewSQLConstantShadowsColumnRule creates the rule
func NewSQLConstantShadowsColumnRule() *SQLConstantShadowsColumnRule {
	return &SQLConstantShadowsColumnRule{BaseRule: rules.NewBaseRule(
		"sql-constant-shadows-column",
		"patterns",
		"Detects a SELECT naming a constant as a column of the table it reads ('completed' AS status) — every row shows the constant, not its value",
		core.SeverityHigh,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations' columns.
func (r *SQLConstantShadowsColumnRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports the constants of a file's SQL named as table columns.
func (r *SQLConstantShadowsColumnRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok || schema == nil {
		return nil
	}
	var violations []*core.Violation
	for _, literal := range sqlLiterals(ctx.GoAST) {
		for _, offset := range schema.ConstantColumns(literal.text) {
			line := literal.lineAt(ctx, offset)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"Constant named as a column of the table the SELECT reads — every row shows the constant, not the row's value",
				"Select the column itself (t.status), or name the constant so it does not pass for the column"))
		}
	}
	return violations
}

// SQLTestDDLDuplicatesMigrationRule detects a test creating a table the
// migrations define:
//
//	db.Exec(`CREATE TABLE IF NOT EXISTS payout_orders (id UUID PRIMARY KEY, amount NUMERIC)`)
//
// The test runs against its own copy of the definition: on a database the
// migrations built the statement does nothing, on a fresh one it builds the
// old shape, and the test passes against columns the code no longer has, or
// fails against columns the migrations added. Apply the migrations instead.
// Temporary tables are not reported.
type SQLTestDDLDuplicatesMigrationRule struct {
	*rules.BaseRule
}

// NewSQLTestDDLDuplicatesMigrationRule creates the rule
func NewSQLTestDDLDuplicatesMigrationRule() *SQLTestDDLDuplicatesMigrationRule {
	return &SQLTestDDLDuplicatesMigrationRule{BaseRule: rules.NewBaseRule(
		"sql-test-ddl-duplicates-migration",
		"patterns",
		"Detects a test creating a table the migrations define — its copy of the schema drifts from the real one",
		core.SeverityMedium,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations' tables.
func (r *SQLTestDDLDuplicatesMigrationRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports the CREATE TABLE of migrated tables in a test file.
func (r *SQLTestDDLDuplicatesMigrationRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || !ctx.IsTestFile() {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok || schema == nil {
		return nil
	}
	var violations []*core.Violation
	for _, literal := range sqlLiterals(ctx.GoAST) {
		for _, offset := range schema.MigratedTables(literal.text) {
			line := literal.lineAt(ctx, offset)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"Test creates a table the migrations define — it tests against its own copy of the schema, which drifts from the migrations",
				"Build the test database by applying the migrations, and drop the CREATE TABLE from the test"))
		}
	}
	return violations
}

// SQLRuntimeDDLRule detects schema created or changed by the application's
// code instead of a migration:
//
//	CREATE SEQUENCE IF NOT EXISTS address_index_seq START WITH 1
//
// The schema then depends on which code path ran first, a migration and the
// statement can disagree, and the application's database user needs rights
// to change the schema. Code under a migrations directory and temporary
// tables are not reported.
type SQLRuntimeDDLRule struct {
	*rules.BaseRule
}

// NewSQLRuntimeDDLRule creates the rule
func NewSQLRuntimeDDLRule() *SQLRuntimeDDLRule {
	return &SQLRuntimeDDLRule{BaseRule: rules.NewBaseRule(
		"sql-runtime-ddl",
		"patterns",
		"Detects CREATE/ALTER/DROP of tables, sequences and indexes run by application code instead of a migration",
		core.SeverityMedium,
	)}
}

var migrationPath = regexp.MustCompile(`(?i)(?:^|/)[^/]*migrat[^/]*(?:/|\.go$)`)

// AnalyzeFile reports the schema statements of a file outside migrations.
func (r *SQLRuntimeDDLRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) || migrationPath.MatchString(ctx.RelPath) {
		return nil
	}
	var violations []*core.Violation
	for _, literal := range sqlLiterals(ctx.GoAST) {
		if !sqlschema.DefinesSchema(literal.text) {
			continue
		}
		line := literal.lineAt(ctx, 0)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
			"Schema changed by application code — the schema depends on which code path ran first, and a migration can disagree with it",
			"Move the statement into a migration"))
	}
	return violations
}

// SQLGroupBySingleRowRule detects a grouped query read through a single-row
// call:
//
//	db.GetContext(ctx, &active, `SELECT COUNT(DISTINCT user_id) FROM orders GROUP BY user_id HAVING ...`)
//
// GROUP BY returns a row per group; QueryRow and Get read the first and drop
// the rest, so the "total" is the count of one arbitrary group. A GROUP BY
// whose keys the WHERE fixes - directly, or through a unique key of the
// migrations - is one group and is not reported.
type SQLGroupBySingleRowRule struct {
	*rules.BaseRule
}

// NewSQLGroupBySingleRowRule creates the rule
func NewSQLGroupBySingleRowRule() *SQLGroupBySingleRowRule {
	return &SQLGroupBySingleRowRule{BaseRule: rules.NewBaseRule(
		"sql-group-by-single-row",
		"patterns",
		"Detects a GROUP BY query read by QueryRow or Get — the first group is taken for the whole result",
		core.SeverityHigh,
	)}
}

var singleRowCalls = map[string]bool{
	"QueryRow": true, "QueryRowContext": true, "QueryRowx": true, "QueryRowxContext": true,
	"Get": true, "GetContext": true,
}

// ReadsOtherFiles reports that the findings depend on the migrations' unique keys.
func (r *SQLGroupBySingleRowRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports the grouped queries read as one row.
func (r *SQLGroupBySingleRowRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok {
		return nil
	}
	var violations []*core.Violation
	for _, call := range sqlCalls(ctx.GoAST) {
		sel, ok := call.call.Fun.(*ast.SelectorExpr)
		if !ok || !singleRowCalls[sel.Sel.Name] || !schema.GroupedRows(call.literal.text) {
			continue
		}
		line := ctx.LineFor(call.call)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
			"GROUP BY query read by "+sel.Sel.Name+" — it returns a row per group, and only the first is read",
			"Aggregate over the groups in an outer query (SELECT COUNT(*) FROM (... GROUP BY ...) g), or read every row"))
	}
	return violations
}

// SQLUpsertFreshKeyRule detects an upsert whose conflict key is a value made
// fresh for the call:
//
//	db.ExecContext(ctx, `INSERT INTO transfers (id, tx_hash, status) VALUES ($1, $2, $3)
//		ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status`, uuid.New(), hash, status)
//
// A new id never conflicts: the update branch never runs, and every call
// inserts another row for the same transfer. The conflict key is the value
// that identifies the thing - the hash, the external reference.
type SQLUpsertFreshKeyRule struct {
	*rules.BaseRule
}

// NewSQLUpsertFreshKeyRule creates the rule
func NewSQLUpsertFreshKeyRule() *SQLUpsertFreshKeyRule {
	return &SQLUpsertFreshKeyRule{BaseRule: rules.NewBaseRule(
		"sql-upsert-fresh-key",
		"patterns",
		"Detects INSERT ... ON CONFLICT (key) DO UPDATE whose key is a fresh uuid — it never conflicts, every call inserts",
		core.SeverityHigh,
	)}
}

// freshID is a call that makes a new identifier.
var freshID = regexp.MustCompile(`^(?:uuid|ksuid|xid|ulid)\.New\w*$`)

// AnalyzeFile reports the upserts keyed by a fresh value.
func (r *SQLUpsertFreshKeyRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, call := range sqlCalls(ctx.GoAST) {
		params, offset, ok := sqlschema.ConflictParams(call.literal.text)
		if !ok {
			continue
		}
		for _, column := range slices.Sorted(maps.Keys(params)) {
			i := call.queryArg + params[column]
			if i >= len(call.call.Args) || !isFreshID(call.call.Args[i]) {
				continue
			}
			// The ON CONFLICT line when the statement is written for this
			// call; the call when it passes a statement shared by several.
			line := ctx.LineFor(call.call)
			if _, shared := sharedDeclaration(call.call.Args[call.queryArg]); !shared {
				line = call.literal.lineAt(ctx, offset)
			}
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"ON CONFLICT ("+column+") gets a fresh identifier — it never conflicts, so the update never runs and every call inserts a row",
				"Put the conflict on the value that identifies the thing (a hash, an external reference) with a unique index"))
		}
	}
	return violations
}

// sharedDeclaration reports an argument naming a constant or a variable
// declared with var: text other calls can pass too.
func sharedDeclaration(arg ast.Expr) (*ast.ValueSpec, bool) {
	id, ok := ast.Unparen(arg).(*ast.Ident)
	if !ok || id.Obj == nil {
		return nil, false
	}
	spec, ok := id.Obj.Decl.(*ast.ValueSpec)
	return spec, ok
}

// isFreshID reports uuid.New(), uuid.New().String() and the like, directly,
// through the variable they were assigned to, or through the field of a
// struct literal they were written into (tx := &Tx{ID: uuid.New()}; tx.ID).
func isFreshID(expr ast.Expr) bool {
	value := declaredValue(expr)
	if sel, ok := value.(*ast.SelectorExpr); ok {
		value = fieldValue(sel)
	}
	call, ok := value.(*ast.CallExpr)
	if !ok {
		return false
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "String" {
		if inner, ok := sel.X.(*ast.CallExpr); ok {
			call = inner
		}
	}
	return freshID.MatchString(helpers.ExprText(call.Fun))
}

// fieldValue returns the value a struct literal gave the field x.F, when x is
// declared from that literal in the file; nil otherwise.
func fieldValue(sel *ast.SelectorExpr) ast.Expr {
	value := declaredValue(sel.X)
	if unary, ok := value.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		value = unary.X
	}
	literal, ok := value.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	for _, elt := range literal.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == sel.Sel.Name {
				return ast.Unparen(kv.Value)
			}
		}
	}
	return nil
}
