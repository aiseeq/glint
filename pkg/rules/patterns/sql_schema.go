package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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

// NewSQLUnknownColumnRule creates the rule
func NewSQLUnknownColumnRule() *SQLUnknownColumnRule {
	return &SQLUnknownColumnRule{BaseRule: rules.NewBaseRule(
		"sql-unknown-column",
		"patterns",
		"Detects SQL in Go string literals naming a table or a column the migrations never created",
		core.SeverityHigh,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations.
func (r *SQLUnknownColumnRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile checks the SQL literals of a Go file against the schema.
func (r *SQLUnknownColumnRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return analyzeSQLAgainstSchema(ctx, r.BaseRule, map[string]string{
		"unknown_table":       "Table %[1]s is not created by any migration — the query fails on its first run",
		"unknown_column":      "Column %[1]s is not in %[2]s as the migrations leave it — the query fails on its first run",
		"alter_before_create": "",
	}, "Name the column or the table the schema has, or add the migration that creates it")
}

// SQLInsertMissingNotNullRule detects an INSERT in a Go string literal whose
// column list leaves out a NOT NULL column without a default:
//
//	INSERT INTO orders (id, user_id, amount, created_at) VALUES ($1, $2, $3, $4)
//	-- updated_at is NOT NULL and has no default
//
// The statement fails with a not-null violation on every run.
type SQLInsertMissingNotNullRule struct {
	*rules.BaseRule
}

// NewSQLInsertMissingNotNullRule creates the rule
func NewSQLInsertMissingNotNullRule() *SQLInsertMissingNotNullRule {
	return &SQLInsertMissingNotNullRule{BaseRule: rules.NewBaseRule(
		"sql-insert-missing-not-null",
		"patterns",
		"Detects an INSERT whose column list leaves out a NOT NULL column that has no default",
		core.SeverityHigh,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations.
func (r *SQLInsertMissingNotNullRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile checks the INSERT literals of a Go file against the schema.
func (r *SQLInsertMissingNotNullRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return analyzeSQLAgainstSchema(ctx, r.BaseRule, map[string]string{
		"missing_not_null": "INSERT into %[2]s leaves out %[1]s, NOT NULL without a default — the statement fails on every run",
	}, "List the column with a value, or give it a default in a migration")
}

func analyzeSQLAgainstSchema(ctx *core.FileContext, rule *rules.BaseRule, messages map[string]string, suggestion string) []*core.Violation {
	if ctx.IsTestFile() || ctx.ProjectRoot == "" {
		return nil
	}
	schema, err := sqlschema.LoadCached(ctx.ProjectRoot, migrationDirs(rule))
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
	literals := sqlLiterals(ctx.GoAST)
	var created []string
	for _, literal := range literals {
		if sqlCreate.MatchString(literal.text) {
			created = append(created, literal.text)
		}
	}
	if len(created) > 0 {
		schema = schema.With(created)
	}
	var violations []*core.Violation
	for _, literal := range literals {
		problems, ok := schema.CheckQuery(literal.text)
		if !ok {
			continue
		}
		for _, problem := range problems {
			format, wanted := messages[problem.Kind]
			if !wanted {
				continue
			}
			line := literal.lineAt(ctx, problem.Offset)
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

// migrationDirs reads the migrations setting.
func migrationDirs(rule *rules.BaseRule) []string {
	var dirs []string
	for _, dir := range strings.Split(rule.GetStringSetting("migrations", ""), ",") {
		if dir = strings.TrimSpace(dir); dir != "" {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// migrationViolations reports what is wrong with a migration file itself:
// that it does not parse, so no SQL was checked, and — with reportFaults —
// the ALTERs of tables a later migration creates.
func migrationViolations(ctx *core.FileContext, rule *rules.BaseRule, schema *sqlschema.Schema, err error, reportFaults bool) []*core.Violation {
	var migrationErr *sqlschema.MigrationError
	if errors.As(err, &migrationErr) {
		if migrationRelPath(ctx.ProjectRoot, migrationErr.Path) != ctx.RelPath {
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
		if migrationRelPath(ctx.ProjectRoot, fault.Path) != ctx.RelPath || ctx.IsSuppressed(fault.Line, rule.Name()) {
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

// migrationRelPath returns the path of a migration as the file contexts under
// root name it.
func migrationRelPath(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path) // not relative to root: no file context names it
}

// sqlLiteral is SQL text assembled from string literals, with where each
// piece of it is written.
type sqlLiteral struct {
	expr   ast.Expr // the literal or the concatenation in the code
	text   string
	pieces []sqlPiece
	// bare is the text with the operands that are not literals left out
	// instead of made parameters — a WHERE clause built elsewhere — at the
	// same offsets; empty when every operand is a literal.
	bare string
}

type sqlPiece struct {
	start int // offset of the piece in text
	end   int
	pos   token.Pos
	raw   bool // a raw string: lines of the text are lines of the source
}

// lineAt returns the source line of an offset in the text.
func (l sqlLiteral) lineAt(ctx *core.FileContext, offset int) int {
	for _, piece := range l.pieces {
		if offset < piece.start || offset >= piece.end {
			continue
		}
		line := ctx.LineForPos(piece.pos)
		if piece.raw {
			line += strings.Count(l.text[piece.start:offset], "\n")
		}
		return line
	}
	return ctx.LineForPos(l.pieces[0].pos)
}

// sqlStart is how a statement begins.
var sqlStart = regexp.MustCompile(`(?i)^\s*\(?\s*(?:select|insert|update|delete|with|create)\s`)

// sqlCreate is a statement creating a table in the code.
var sqlCreate = regexp.MustCompile(`(?i)^\s*create\s+(?:(?:global|local)\s+)?(?:temp|temporary|unlogged\s+)?\s*table\s`)

// fmtVerb is a fmt verb in a format string; it becomes a two-character
// parameter so that offsets stay put.
var fmtVerb = regexp.MustCompile(`%[sdvq]`)

// sqlLiterals returns the string literals and concatenations of literals
// under a node that begin like a SQL statement. An operand that is not a
// literal becomes a parameter; where it stood for a name the text does not
// parse.
func sqlLiterals(root ast.Node) []sqlLiteral {
	var literals []sqlLiteral
	ast.Inspect(root, func(n ast.Node) bool {
		expr, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		if !isStringOrConcat(expr) {
			return true
		}
		literal := sqlLiteral{expr: expr}
		var builder strings.Builder
		var gaps []int
		hasLiteral := false
		for _, operand := range concatOperands(expr) {
			piece, isLit := operand.(*ast.BasicLit)
			text, ok := "", false
			if isLit {
				text, ok = goStringLiteral(piece)
			}
			if !ok {
				gaps = append(gaps, builder.Len())
				builder.WriteString(" $9 ")
				continue
			}
			hasLiteral = true
			start := builder.Len()
			builder.WriteString(fmtVerb.ReplaceAllString(text, "$$9"))
			literal.pieces = append(literal.pieces, sqlPiece{start: start, end: builder.Len(), pos: piece.Pos(), raw: piece.Value[0] == '`'})
		}
		literal.text = builder.String()
		if len(gaps) > 0 {
			bare := []byte(literal.text)
			for _, gap := range gaps {
				copy(bare[gap:], "    ")
			}
			literal.bare = string(bare)
		}
		if hasLiteral && sqlStart.MatchString(literal.text) {
			literals = append(literals, literal)
		}
		return false
	})
	return literals
}

// isStringOrConcat reports a string literal or a + expression, which may
// join string literals.
func isStringOrConcat(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.BinaryExpr:
		return x.Op == token.ADD
	case *ast.BasicLit:
		return x.Kind == token.STRING
	}
	return false
}

// concatOperands flattens a + b + c into its operands.
func concatOperands(expr ast.Expr) []ast.Expr {
	if bin, ok := ast.Unparen(expr).(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		return append(concatOperands(bin.X), concatOperands(bin.Y)...)
	}
	return []ast.Expr{ast.Unparen(expr)}
}
