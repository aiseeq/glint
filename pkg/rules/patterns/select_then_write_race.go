package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
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
// Typical case: a status transition reads `status`, runs a state-machine
// check on the value, then writes `status` back. A background job and a manual
// action read the same status concurrently and both pass the validation.
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
	// quotedText is a single-quoted SQL string: a word inside it is data,
	// not a column.
	quotedText *regexp.Regexp
	// columnReference is a column name, optionally table-qualified.
	columnReference *regexp.Regexp
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
		selectQuery:     regexp.MustCompile(`(?is)^\s*SELECT\s+(.+?)\s+FROM\s+([A-Za-z_][A-Za-z0-9_.]*)`),
		updateQuery:     regexp.MustCompile(`(?is)^\s*UPDATE\s+([A-Za-z_][A-Za-z0-9_.]*)\s+SET\s+(.+)`),
		rowLock:         regexp.MustCompile(`(?i)\bFOR\s+(?:NO\s+KEY\s+)?UPDATE\b|\bFOR\s+(?:KEY\s+)?SHARE\b`),
		whereClause:     regexp.MustCompile(`(?i)\bWHERE\b`),
		identifier:      regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`),
		quotedText:      regexp.MustCompile(`'(?:[^']|'')*'`),
		columnReference: regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?`),
	}
}

// sqlRead is a SELECT literal without a row lock.
type sqlRead struct {
	table   string
	columns map[string]bool
	pos     token.Pos
	line    int
}

// AnalyzeFile checks the SQL string literals of each function; queries held
// in constants need type information and are read by AnalyzeGoProject.
func (r *SelectThenWriteRaceRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SelectThenWriteRaceRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; with type information a query held in
// a constant (a package const, a concatenation of consts) is read by its value.
func (r *SelectThenWriteRaceRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks each function of the file. info is nil for a file without
// type information: then only string literals written in the function are
// queries, a constant declared elsewhere is unknown.
func (r *SelectThenWriteRaceRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	return analyzeGoFunctions(ctx, func(fn *ast.FuncDecl) []*core.Violation {
		return r.checkFunction(ctx, fn, info)
	})
}

func (r *SelectThenWriteRaceRule) checkFunction(ctx *core.FileContext, fn *ast.FuncDecl, info *types.Info) []*core.Violation {
	var reads []sqlRead
	var violations []*core.Violation

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		expr, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		query, ok := constantString(expr, info)
		if !ok {
			return true
		}
		reads = r.checkQuery(ctx, fn, query, expr, reads, &violations)
		// The whole constant is one query: its operands are not visited again.
		return false
	})
	return violations
}

// constantString returns the string value of a constant expression: with type
// information any constant (literal, named const, concatenation), without it
// only a string literal.
func constantString(expr ast.Expr, info *types.Info) (string, bool) {
	if info != nil {
		value := info.Types[expr].Value
		if value == nil || value.Kind() != constant.String {
			return "", false
		}
		return constant.StringVal(value), true
	}
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	// A string literal the parser accepted always unquotes; one that does not
	// is not a query, so skipping it is the success path, not a masked failure.
	// error-masking: safe — a literal that does not unquote is not SQL
	query, err := strconv.Unquote(lit.Value)
	return query, err == nil
}

// checkQuery classifies one SQL string, extending the list of unlocked reads
// or reporting a read-then-write pair.
func (r *SelectThenWriteRaceRule) checkQuery(ctx *core.FileContext, fn *ast.FuncDecl, query string, node ast.Expr, reads []sqlRead, violations *[]*core.Violation) []sqlRead {
	if read, ok := r.parseSelect(query, node, ctx); ok {
		return append(reads, read)
	}

	table, columns, guarded, ok := r.parseUpdate(query)
	if ok {
		for _, prior := range reads {
			if prior.table != table || prior.pos >= node.Pos() {
				continue
			}
			shared := intersectColumn(prior.columns, columns, guarded)
			if shared == "" {
				continue
			}
			line := lineFromNode(ctx, node)
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
func (r *SelectThenWriteRaceRule) parseSelect(query string, lit ast.Expr, ctx *core.FileContext) (sqlRead, bool) {
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

// parseUpdate recognizes an UPDATE literal and returns the SET column set and
// the columns its WHERE clause compares. A column the WHERE compares is a
// compare-and-set: a concurrent change makes the UPDATE match no row instead
// of overwriting it.
func (r *SelectThenWriteRaceRule) parseUpdate(query string) (string, map[string]bool, map[string]bool, bool) {
	match := r.updateQuery.FindStringSubmatch(query)
	if match == nil {
		return "", nil, nil, false
	}
	setClause := match[2]
	guarded := make(map[string]bool)
	if loc := r.whereClause.FindStringIndex(setClause); loc != nil {
		where := r.quotedText.ReplaceAllString(setClause[loc[1]:], "''")
		for _, reference := range r.columnReference.FindAllString(where, -1) {
			if column, ok := r.columnName(reference); ok {
				guarded[column] = true
			}
		}
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
		return "", nil, nil, false
	}
	return strings.ToLower(match[1]), columns, guarded, true
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

// intersectColumn returns the alphabetically first column that is read and
// written back without the UPDATE comparing it, so the reported column does
// not depend on map iteration order.
func intersectColumn(read, written, guarded map[string]bool) string {
	shared := ""
	for column := range read {
		if !written[column] || guarded[column] {
			continue
		}
		if shared == "" || column < shared {
			shared = column
		}
	}
	return shared
}
