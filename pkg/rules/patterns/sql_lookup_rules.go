package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLColumnComparedWithItselfRule())
	rules.Register(NewSQLLinkUpdateIgnoresParentRule())
	rules.Register(NewSQLPartialKeyReadRule())
	rules.Register(NewSQLDeleteReferencedWithoutKeyRule())
	rules.Register(NewExternalReferenceLookupWithoutUniqueIndexRule())
}

// SQLColumnComparedWithItselfRule detects a comparison of a column with
// itself, written as a comparison with the outer row:
//
//	EXISTS (SELECT 1 FROM members m WHERE m.org_id = $1 AND m.email = email)
//
// The unqualified email binds to the nearest relation with that column, m
// itself: the condition is true for every row, and the filter it builds
// lets everything through. The outer column needs its alias (o.email).
type SQLColumnComparedWithItselfRule struct {
	*rules.BaseRule
}

// NewSQLColumnComparedWithItselfRule creates the rule
func NewSQLColumnComparedWithItselfRule() *SQLColumnComparedWithItselfRule {
	return &SQLColumnComparedWithItselfRule{BaseRule: rules.NewBaseRule(
		"sql-column-compared-with-itself",
		"patterns",
		"Detects alias.col = col where the alias is a relation of the same SELECT — the bare name binds to that relation, and the condition is true for every row",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports the self comparisons of a file's SQL.
func (r *SQLColumnComparedWithItselfRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	reported := make(map[int]bool)
	for _, literal := range sqlFragments(ctx.GoAST) {
		for _, offset := range sqlschema.SelfComparisons(literal.text) {
			line := literal.lineAt(ctx, offset)
			if reported[line] || ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			reported[line] = true
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"The unqualified column binds to the subquery's own relation, not the outer row — the comparison is the column with itself and is always true",
				"Qualify the outer column with its alias (outer.col)"))
		}
	}
	return violations
}

// SQLLinkUpdateIgnoresParentRule detects a link or unlink that sets a row's
// reference without testing what it references now:
//
//	func (r *Repo) UnlinkEntry(ctx context.Context, account string, seq int64) error {
//		_, err := r.db.ExecContext(ctx, `UPDATE entries SET batch_id = NULL WHERE account_id = $1 AND seq = $2`, account, seq)
//
// Unlinking from one batch's page clears the row's link to another batch,
// and a link moves a row another parent holds without a word. The WHERE
// tests the reference: batch_id = $n to unlink, batch_id IS NULL (or the
// same parent) to link. Only a reference to a table of the migrations counts:
// a column naming no table holds an outside identity of the row itself.
type SQLLinkUpdateIgnoresParentRule struct {
	*rules.BaseRule
}

// NewSQLLinkUpdateIgnoresParentRule creates the rule
func NewSQLLinkUpdateIgnoresParentRule() *SQLLinkUpdateIgnoresParentRule {
	return &SQLLinkUpdateIgnoresParentRule{BaseRule: rules.NewBaseRule(
		"sql-link-update-ignores-current-parent",
		"patterns",
		"Detects a link or unlink function whose UPDATE sets a *_id reference with a WHERE that never tests it — an unlink clears another parent's link, a link moves a row another parent holds",
		core.SeverityMedium,
	)}
}

// linkFunction is the name of a function that links a row to a parent or
// unlinks it.
var linkFunction = regexp.MustCompile(`^(?:[Ll]ink|[Uu]nlink|[Aa]ttach|[Dd]etach)(?:[A-Z_]|$)`)

// ReadsOtherFiles reports that the findings depend on the migrations' tables.
func (r *SQLLinkUpdateIgnoresParentRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports the unscoped reference updates of the link functions.
func (r *SQLLinkUpdateIgnoresParentRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok || schema == nil {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !linkFunction.MatchString(fn.Name.Name) {
			continue
		}
		for _, literal := range sqlLiterals(fn.Body) {
			for _, update := range sqlschema.UnscopedLinkUpdates(literal.text) {
				if !schema.NamesTable(update.Table, update.Column) {
					continue
				}
				line := literal.lineAt(ctx, update.Offset)
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				message := "The link sets " + update.Column + " with a WHERE that does not test it — a row another parent holds moves to this one silently"
				suggestion := "Link only a free row (AND " + update.Column + " IS NULL, or the same parent) and report a taken one"
				if update.Clears {
					message = "The unlink clears " + update.Column + " by the row's own key — it removes the row's link to whatever parent it has, not only this one"
					suggestion = "Take the parent and require it in the WHERE (AND " + update.Column + " = $n)"
				}
				violations = append(violations, sqlViolation(r.BaseRule, ctx, line, message, suggestion))
			}
		}
	}
	return violations
}

// SQLPartialKeyReadRule detects a read of one row by the columns of a
// partial unique index without its predicate:
//
//	CREATE UNIQUE INDEX ON payments (order_id) WHERE status <> 'void';
//	db.GetContext(ctx, &p, `SELECT * FROM payments WHERE order_id = $1`, orderID)
//
// The key is unique only among the rows the predicate admits: a void row
// and a live one share it, Get takes whichever comes first, and code acting
// on the live one acts on the void one.
type SQLPartialKeyReadRule struct {
	*rules.BaseRule
}

// NewSQLPartialKeyReadRule creates the rule
func NewSQLPartialKeyReadRule() *SQLPartialKeyReadRule {
	return &SQLPartialKeyReadRule{BaseRule: rules.NewBaseRule(
		"sql-partial-key-read-without-predicate",
		"patterns",
		"Detects one row read by the columns of a partial unique index without the index's WHERE — the key repeats outside the predicate, and the read takes any of those rows",
		core.SeverityMedium,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations' indexes.
func (r *SQLPartialKeyReadRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports the single-row reads by a partial key.
func (r *SQLPartialKeyReadRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok || schema == nil {
		return nil
	}
	var violations []*core.Violation
	for _, call := range sqlCalls(ctx.GoAST) {
		sel, ok := call.call.Fun.(*ast.SelectorExpr)
		if !ok || !singleRowCalls[sel.Sel.Name] {
			continue
		}
		for _, offset := range schema.PartialKeyReads(call.literal.text) {
			line := call.literal.lineAt(ctx, offset)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"One row is read by the columns of a partial unique index without its WHERE — rows outside the predicate share the key, and "+sel.Sel.Name+" takes any of them",
				"Repeat the index's predicate in the WHERE, or read every row of the key and decide"))
		}
	}
	return violations
}

// ExternalReferenceLookupWithoutUniqueIndexRule detects one row read by the
// identity another system gave it while the migrations make that column
// unique nowhere:
//
//	CREATE TABLE transfers (id uuid PRIMARY KEY, provider_reference text, ...);
//	db.QueryRow(ctx, `SELECT ... FROM transfers WHERE provider_reference = $1`, ref)
//
// Nothing keeps two rows from sharing the other system's id: a retried
// create or a replayed callback stores it twice, and the read takes either
// row — the update meant for one lands on the other. A unique index (partial
// over the non-empty values, if the column starts empty) makes the second
// write fail instead.
type ExternalReferenceLookupWithoutUniqueIndexRule struct {
	*rules.BaseRule
}

// NewExternalReferenceLookupWithoutUniqueIndexRule creates the rule
func NewExternalReferenceLookupWithoutUniqueIndexRule() *ExternalReferenceLookupWithoutUniqueIndexRule {
	return &ExternalReferenceLookupWithoutUniqueIndexRule{BaseRule: rules.NewBaseRule(
		"external-reference-lookup-without-unique-index",
		"patterns",
		"Detects one row read by another system's id (*_reference, external_id) that no unique index of the migrations covers — two rows can share it, and the read takes either",
		core.SeverityMedium,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations' indexes.
func (r *ExternalReferenceLookupWithoutUniqueIndexRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports the single-row reads by an unkeyed external id.
func (r *ExternalReferenceLookupWithoutUniqueIndexRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok || schema == nil {
		return nil
	}
	var violations []*core.Violation
	for _, call := range sqlCalls(ctx.GoAST) {
		sel, ok := call.call.Fun.(*ast.SelectorExpr)
		if !ok || !singleRowCalls[sel.Sel.Name] {
			continue
		}
		for _, key := range schema.UnkeyedExternalReads(call.literal.text) {
			line := call.literal.lineAt(ctx, key.Offset)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"One row of "+key.Table+" is read by "+key.Column+", another system's id, and no unique index covers it — two rows can share it, and "+sel.Sel.Name+" takes either",
				"Add a unique index on "+key.Table+" ("+key.Column+") — partial (WHERE "+key.Column+" <> '') if the column starts empty — or read every row of the id and refuse a duplicate"))
		}
	}
	return violations
}

// SQLDeleteReferencedWithoutKeyRule detects a DELETE of rows that columns of
// other tables point at by name, with no foreign key and no check:
//
//	DELETE FROM transactions WHERE wallet = $1 AND leg NOT IN (...)
//	-- ledger_entries.chain_tx_id holds a transactions id, no REFERENCES
//
// The database lets the rows go, and the rows pointing at them keep an id
// of nothing: a posting without its source, a decision about a row that is
// gone. A foreign key makes the delete fail; a query of the referencing
// table in the same function is a check.
type SQLDeleteReferencedWithoutKeyRule struct {
	*rules.BaseRule
}

// NewSQLDeleteReferencedWithoutKeyRule creates the rule
func NewSQLDeleteReferencedWithoutKeyRule() *SQLDeleteReferencedWithoutKeyRule {
	return &SQLDeleteReferencedWithoutKeyRule{BaseRule: rules.NewBaseRule(
		"sql-delete-referenced-without-key",
		"patterns",
		"Detects a DELETE of rows other tables point at by an id column with no foreign key, in a function that never checks them — the references are left dangling",
		core.SeverityMedium,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations' columns.
func (r *SQLDeleteReferencedWithoutKeyRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports the deletes of rows referenced without a key.
func (r *SQLDeleteReferencedWithoutKeyRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok || schema == nil {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		literals := sqlLiterals(fn.Body)
		for _, literal := range literals {
			for _, del := range sqlschema.Deletes(literal.text) {
				var dangling []string
				for _, ref := range schema.UnkeyedReferences(del.Table) {
					if !mentionsTable(literals, ref.Table) {
						dangling = append(dangling, ref.Table+"."+ref.Column)
					}
				}
				if len(dangling) == 0 {
					continue
				}
				line := literal.lineAt(ctx, del.Offset)
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
					"Rows of "+del.Table+" are deleted while "+strings.Join(dangling, ", ")+" point at them with no foreign key and nothing here checks them — those references are left dangling",
					"Add a foreign key (the delete then fails while the rows are referenced), or check the referencing rows before the delete"))
			}
		}
	}
	return violations
}

// mentionsTable reports SQL text of the literals naming the table as a word.
func mentionsTable(literals []sqlLiteral, table string) bool {
	word := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(table) + `\b`)
	for _, literal := range literals {
		if word.MatchString(literal.text) {
			return true
		}
	}
	return false
}
