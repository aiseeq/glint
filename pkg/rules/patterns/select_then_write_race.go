package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSelectThenWriteRaceRule())
}

// SelectThenWriteRaceRule detects a read-validate-write race inside one
// function: a SELECT of a column without FOR UPDATE followed by an UPDATE of
// the same column of the same table. Two concurrent calls read the same value,
// both pass the validation performed between the queries, and the second one
// silently overwrites the first.
//
// Real case (projectB, 2026-08-05): status transitions read `status`, ran a
// state-machine check on the value, then wrote `status` back. Concurrent
// sync-materializer and manual close both read the same status and both passed
// the transition validation.
//
// The rule is silent when the SELECT locks the row (FOR UPDATE / FOR NO KEY
// UPDATE / FOR SHARE) — that is exactly the fix.
type SelectThenWriteRaceRule struct {
	*rules.BaseRule

	selectQuery *regexp.Regexp
	updateQuery *regexp.Regexp
	rowLock     *regexp.Regexp
	whereClause *regexp.Regexp
	identifier  *regexp.Regexp
}

// NewSelectThenWriteRaceRule creates the rule.
func NewSelectThenWriteRaceRule() *SelectThenWriteRaceRule {
	return &SelectThenWriteRaceRule{
		BaseRule: rules.NewBaseRule(
			"select-then-write-race",
			"patterns",
			"Detects SELECT without FOR UPDATE followed by an UPDATE of the same column in one function (read-validate-write race)",
			core.SeverityMedium,
		),
		// Anchored at the start of the literal so subqueries inside a larger
		// statement are not mistaken for the read.
		selectQuery: regexp.MustCompile(`(?is)^\s*SELECT\s+(.+?)\s+FROM\s+([A-Za-z_][A-Za-z0-9_.]*)`),
		updateQuery: regexp.MustCompile(`(?is)^\s*UPDATE\s+([A-Za-z_][A-Za-z0-9_.]*)\s+SET\s+(.+)`),
		rowLock:     regexp.MustCompile(`(?i)\bFOR\s+(?:NO\s+KEY\s+)?UPDATE\b|\bFOR\s+(?:KEY\s+)?SHARE\b`),
		whereClause: regexp.MustCompile(`(?i)\bWHERE\b`),
		identifier:  regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`),
	}
}

// sqlRead is a SELECT literal without a row lock.
type sqlRead struct {
	table   string
	columns map[string]bool
	pos     token.Pos
	line    int
}

// AnalyzeFile checks each function's SQL literals for the read-then-write pattern.
func (r *SelectThenWriteRaceRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		violations = append(violations, r.checkFunction(ctx, fn)...)
	}
	return violations
}

func (r *SelectThenWriteRaceRule) checkFunction(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var reads []sqlRead
	var violations []*core.Violation

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		// A literal that does not unquote is not SQL; skipping it is the
		// success path here, not a masked failure.
		// error-masking: safe — non-string literal is skipped by design
		if query, err := strconv.Unquote(lit.Value); err == nil {
			reads = r.checkLiteral(ctx, fn, query, lit, reads, &violations)
		}
		return true
	})
	return violations
}

// checkLiteral classifies one SQL string literal, extending the list of
// unlocked reads or reporting a read-then-write pair.
func (r *SelectThenWriteRaceRule) checkLiteral(ctx *core.FileContext, fn *ast.FuncDecl, query string, lit *ast.BasicLit, reads []sqlRead, violations *[]*core.Violation) []sqlRead {
	if read, ok := r.parseSelect(query, lit, ctx); ok {
		return append(reads, read)
	}

	table, columns, ok := r.parseUpdate(query)
	if ok {
		for _, prior := range reads {
			if prior.table != table || prior.pos >= lit.Pos() {
				continue
			}
			shared := intersectColumn(prior.columns, columns)
			if shared == "" {
				continue
			}
			line := lineFromNode(ctx, lit)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line,
				"'"+table+"."+shared+"' is read without FOR UPDATE (line "+strconv.Itoa(prior.line)+") and then written back — concurrent calls read the same value and both pass the validation")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Lock the row with SELECT ... FOR UPDATE inside a transaction, or collapse the check into one conditional UPDATE ... WHERE " + shared + " IN (...)")
			v.WithContext("pattern", "select-then-write-race")
			v.WithContext("function", fn.Name.Name)
			v.WithContext("table", table)
			v.WithContext("column", shared)
			v.WithContext("select_line", prior.line)
			*violations = append(*violations, v)
			break
		}
	}
	return reads
}

// parseSelect recognizes a SELECT literal that reads concrete columns and does
// not lock the row. SELECT * is ignored: without an explicit column list the
// read-modify-write link cannot be proven and the rule prefers precision.
func (r *SelectThenWriteRaceRule) parseSelect(query string, lit *ast.BasicLit, ctx *core.FileContext) (sqlRead, bool) {
	match := r.selectQuery.FindStringSubmatch(query)
	if match == nil || r.rowLock.MatchString(query) {
		return sqlRead{}, false
	}
	columns := r.columnSet(match[1])
	if len(columns) == 0 {
		return sqlRead{}, false
	}
	return sqlRead{
		table:   strings.ToLower(match[2]),
		columns: columns,
		pos:     lit.Pos(),
		line:    lineFromNode(ctx, lit),
	}, true
}

// parseUpdate recognizes an UPDATE literal and returns the SET column set.
func (r *SelectThenWriteRaceRule) parseUpdate(query string) (string, map[string]bool, bool) {
	match := r.updateQuery.FindStringSubmatch(query)
	if match == nil {
		return "", nil, false
	}
	setClause := match[2]
	if loc := r.whereClause.FindStringIndex(setClause); loc != nil {
		setClause = setClause[:loc[0]]
	}
	columns := make(map[string]bool)
	for _, assignment := range strings.Split(setClause, ",") {
		name, _, found := strings.Cut(assignment, "=")
		if !found {
			continue
		}
		if column, ok := r.columnName(name); ok {
			columns[column] = true
		}
	}
	if len(columns) == 0 {
		return "", nil, false
	}
	return strings.ToLower(match[1]), columns, true
}

// columnSet parses a SELECT list into simple column names. Expressions,
// aggregates, and * are dropped: only a plainly named column proves that the
// later UPDATE rewrites what was read.
func (r *SelectThenWriteRaceRule) columnSet(selectList string) map[string]bool {
	columns := make(map[string]bool)
	for _, item := range strings.Split(selectList, ",") {
		if column, ok := r.columnName(item); ok {
			columns[column] = true
		}
	}
	return columns
}

// columnName normalizes one column reference ("status", "t.status") to its
// bare lowercase name, rejecting anything that is not a plain identifier.
func (r *SelectThenWriteRaceRule) columnName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		name = name[dot+1:]
	}
	if !r.identifier.MatchString(name) {
		return "", false
	}
	return strings.ToLower(name), true
}

// intersectColumn returns the alphabetically first shared column so the
// reported column does not depend on map iteration order.
func intersectColumn(read, written map[string]bool) string {
	shared := ""
	for column := range read {
		if !written[column] {
			continue
		}
		if shared == "" || column < shared {
			shared = column
		}
	}
	return shared
}
