package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewStringLiteralExceedsColumnWidthRule())
	rules.Register(NewSQLCharColumnPadsValueRule())
}

// StringLiteralExceedsColumnWidthRule detects a string constant that reaches
// a bind parameter of a column the migrations declare narrower than the
// constant, directly or through the parameters of the project's functions:
//
//	o.noteFailure(ctx, order, "send order to the carrier", err)
//	func (o *Orchestrator) noteFailure(ctx context.Context, order *Order, operation string, err error) {
//		o.repo.SetError(ctx, order.ID, operation, err.Error())
//	func (r *Repo) SetError(ctx context.Context, id uuid.UUID, code, message string) error {
//		_, err := r.db.Exec(ctx, `UPDATE orders SET error_code = $1, error_message = $2 WHERE id = $3`, code, message, id)
//	-- error_code VARCHAR(20)
//
// PostgreSQL refuses the value (value too long for type character varying),
// and the write fails every time the code takes that path — usually the path
// that records a failure, so the failure itself is lost.
type StringLiteralExceedsColumnWidthRule struct {
	*rules.BaseRule
}

// NewStringLiteralExceedsColumnWidthRule creates the rule
func NewStringLiteralExceedsColumnWidthRule() *StringLiteralExceedsColumnWidthRule {
	return &StringLiteralExceedsColumnWidthRule{BaseRule: rules.NewBaseRule(
		"string-literal-exceeds-column-width",
		"patterns",
		"Detects a string constant longer than the VARCHAR(n) or CHAR(n) column it reaches through bind parameters — the database refuses the value, and the write fails every time",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the check needs types and the migrations.
func (r *StringLiteralExceedsColumnWidthRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *StringLiteralExceedsColumnWidthRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the constants too long for the column they reach.
func (r *StringLiteralExceedsColumnWidthRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return analyzeAgainstSchema(ctx, r.BaseRule, "Shorten the value to the column's width, or widen the column in a migration", tooLongConstants)
}

// maxWidthDepth bounds how deep calls are followed to the bind.
const maxWidthDepth = 3

// tooLongConstants returns the string constants a function hands to a call
// that binds them to a narrower column.
func tooLongConstants(scope funcScope, schema *sqlschema.Schema, fn *ast.FuncDecl) []funcFinding {
	var findings []funcFinding
	queries := namedStrings(fn)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for i, arg := range call.Args {
			value, ok := stringConstant(scope.info, arg)
			if !ok {
				continue
			}
			length := utf8.RuneCountInString(value)
			column, table := boundColumn(schema, queries, call, i)
			if column == nil {
				column, table = paramColumn(scope.info, scope.decls, schema, call, i, 1)
			}
			if column == nil || column.Width == 0 || length <= column.Width {
				continue
			}
			findings = append(findings, funcFinding{node: arg, message: fmt.Sprintf(
				"%q is %d characters and reaches %s.%s, %s(%d) — the database refuses the value, and the write fails every time this path runs",
				value, length, table, column.Name, strings.ToUpper(sqlTypeName(column.Type)), column.Width)})
		}
		return true
	})
	return findings
}

// sqlTypeName is the type as a migration writes it.
func sqlTypeName(typ string) string {
	if typ == "bpchar" {
		return "char"
	}
	return typ
}

// boundColumn returns the column the index-th argument of a query call is
// bound to, and its table: the call runs an INSERT or an UPDATE written as a
// literal (or a variable of the function assigned one) among its earlier
// arguments.
func boundColumn(schema *sqlschema.Schema, queries map[string]ast.Expr, call *ast.CallExpr, index int) (*sqlschema.Column, string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !queryMethods[sel.Sel.Name] {
		return nil, ""
	}
	for q := 0; q < index; q++ {
		arg := call.Args[q]
		if ident, ok := arg.(*ast.Ident); ok && queries[ident.Name] != nil {
			arg = queries[ident.Name]
		}
		if !isStringOrConcat(arg) {
			continue
		}
		literals := sqlLiterals(arg)
		if len(literals) != 1 {
			return nil, ""
		}
		text := literals[0].text
		if literals[0].bare != "" {
			text = literals[0].bare
		}
		column := schema.Binds(text)[index-q]
		if column == nil {
			return nil, ""
		}
		return column, writtenTable(schema, text)
	}
	return nil, ""
}

// writtenTable returns the table an INSERT or an UPDATE writes.
func writtenTable(schema *sqlschema.Schema, sql string) string {
	if shape, ok := schema.Shape(sql); ok {
		return shape.Table
	}
	return "the table"
}

// paramColumn returns the column a project function binds its index-th
// parameter to, directly or through the functions it hands the parameter
// on to, and its table.
func paramColumn(info *types.Info, decls map[*types.Func]typedFuncDecl, schema *sqlschema.Schema, call *ast.CallExpr, index, depth int) (*sqlschema.Column, string) {
	callee := staticFunc(info, call)
	if callee == nil || depth > maxWidthDepth {
		return nil, ""
	}
	decl, ok := decls[callee.Origin()]
	if !ok {
		return nil, ""
	}
	params := paramObjects(decl)
	if index >= len(params) || params[index] == nil {
		return nil, ""
	}
	param := params[index]
	queries := namedStrings(decl.decl)
	var column *sqlschema.Column
	var table string
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		inner, ok := n.(*ast.CallExpr)
		if !ok || column != nil {
			return column == nil
		}
		for i, arg := range inner.Args {
			if !passesParam(decl.info, arg, param) {
				continue
			}
			if column, table = boundColumn(schema, queries, inner, i); column != nil {
				return false
			}
			if column, table = paramColumn(decl.info, decls, schema, inner, i, depth+1); column != nil {
				return false
			}
		}
		return true
	})
	return column, table
}

// passesParam reports an argument that is the parameter as it is, or
// converted to another string type: string(code).
func passesParam(info *types.Info, arg ast.Expr, param *types.Var) bool {
	arg = ast.Unparen(arg)
	if conv, ok := arg.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if tv, ok := info.Types[conv.Fun]; ok && tv.IsType() {
			arg = ast.Unparen(conv.Args[0])
		}
	}
	ident, ok := arg.(*ast.Ident)
	return ok && info.Uses[ident] == param
}

// SQLCharColumnPadsValueRule detects a CHAR(n) column, n > 1, that the
// migrations leave in the schema:
//
//	payout_country CHAR(3) NOT NULL
//
// PostgreSQL pads every shorter value with spaces: 'SG' is stored and read
// back as 'SG ', and a signature, a comparison in Go or a lookup by the value
// the code wrote no longer matches. VARCHAR(n) or TEXT keeps the value as
// written.
type SQLCharColumnPadsValueRule struct {
	*rules.BaseRule
}

// NewSQLCharColumnPadsValueRule creates the rule
func NewSQLCharColumnPadsValueRule() *SQLCharColumnPadsValueRule {
	return &SQLCharColumnPadsValueRule{BaseRule: rules.NewBaseRule(
		"sql-char-column-pads-value",
		"patterns",
		"Detects a CHAR(n) column (n > 1) in the schema the migrations leave — a shorter value is padded with spaces and read back different from what was written",
		core.SeverityMedium,
	)}
}

// ReadsOtherFiles reports that the findings depend on the later migrations.
func (r *SQLCharColumnPadsValueRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports, on a migration, the CHAR(n) columns whose type it
// gave last.
func (r *SQLCharColumnPadsValueRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !strings.EqualFold(filepath.Ext(ctx.RelPath), ".sql") {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok || schema == nil {
		return nil
	}
	path := filepath.Join(ctx.ProjectRoot, ctx.RelPath)
	var violations []*core.Violation
	for _, table := range schema.TablesWith(nil) {
		for _, name := range table.Columns() {
			column := table.Column(name)
			if column.Type != "bpchar" || column.Width <= 1 || column.TypePath == "" {
				continue
			}
			if filepath.Clean(column.TypePath) != path {
				continue
			}
			if ctx.IsSuppressed(column.TypeLine, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, column.TypeLine, fmt.Sprintf(
				"%s.%s is CHAR(%d) — a value shorter than %d characters is padded with spaces and read back different from what was written",
				table.Name, column.Name, column.Width, column.Width))
			v.WithCode(strings.TrimSpace(ctx.GetLine(column.TypeLine)))
			v.WithSuggestion(fmt.Sprintf("Make the column VARCHAR(%d) or TEXT with a CHECK on the length", column.Width))
			violations = append(violations, v)
		}
	}
	return violations
}
