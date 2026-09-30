package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLScanNullableRule())
	rules.Register(NewSQLXColumnWithoutFieldRule())
}

// SQLScanNullableRule detects a column that can be NULL read into a Go value
// that cannot hold NULL — a string, a number, a bool, a time.Time:
//
//	SELECT r.id, r.from_addr FROM requests r ...   -- from_addr is nullable
//	rows.Scan(&r.ID, &r.FromAddr)                  -- FromAddr string
//
//	db.SelectContext(ctx, &out, "SELECT id, memo FROM requests")  -- Memo string `db:"memo"`
//
// database/sql and sqlx fail the whole call on the first row holding NULL
// ("converting NULL to string is unsupported"). A column can be NULL when its
// table allows it, per the migrations — a DEFAULT covers only the inserts
// that leave the column out — or when it comes from the outer side of a
// join, unless the WHERE clause or an inner join keeps NULL out. The destination is fine as a pointer, a sql.Null* or any type
// with its own Scan; a column read through COALESCE or another expression is
// not checked.
type SQLScanNullableRule struct {
	*rules.BaseRule
}

// NewSQLScanNullableRule creates the rule
func NewSQLScanNullableRule() *SQLScanNullableRule {
	return &SQLScanNullableRule{BaseRule: rules.NewBaseRule(
		"sql-scan-nullable-into-value",
		"patterns",
		"Detects a column that can be NULL scanned into a string, number, bool or time value",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: destinations are known only with type information.
func (r *SQLScanNullableRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLScanNullableRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks the scans of the project against the schema.
func (r *SQLScanNullableRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return analyzeScans(ctx, r.BaseRule, scanNullable)
}

// SQLXColumnWithoutFieldRule detects a sqlx Get or Select into a struct that
// has no field for a column the query returns:
//
//	type Stats struct { ChannelName string; Total int `db:"total"` }
//	db.SelectContext(ctx, &stats, "SELECT channel_name, COUNT(*) AS total ...")
//
// sqlx maps a column to the field whose db tag names it, or whose name
// lower-cased is the column — ChannelName reads channelname — and fails
// with "missing destination name channel_name". Where a field without a tag
// matches the column in snake case, the field is reported.
type SQLXColumnWithoutFieldRule struct {
	*rules.BaseRule
}

// NewSQLXColumnWithoutFieldRule creates the rule
func NewSQLXColumnWithoutFieldRule() *SQLXColumnWithoutFieldRule {
	return &SQLXColumnWithoutFieldRule{BaseRule: rules.NewBaseRule(
		"sqlx-column-without-field",
		"patterns",
		"Detects a sqlx Get or Select into a struct with no field for a column the query returns",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: destinations are known only with type information.
func (r *SQLXColumnWithoutFieldRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLXColumnWithoutFieldRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks the sqlx reads of the project.
func (r *SQLXColumnWithoutFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if customNameMapper(ctx) {
		return nil, nil // the project maps columns its own way: the default mapping says nothing
	}
	return analyzeScans(ctx, r.BaseRule, scanUnmapped)
}

const nullableSuggestion = "Read into a pointer or a sql.Null* value, COALESCE the column, or make it NOT NULL in a migration where the code means it"

// scanCheck is what analyzeScans reports.
type scanCheck int

const (
	scanNullable scanCheck = iota
	scanUnmapped
)

func analyzeScans(ctx *core.GoProjectContext, rule *rules.BaseRule, check scanCheck) ([]*core.Violation, error) {
	schema, err := sqlschema.LoadCached(ctx.ProjectRoot, migrationDirs(rule))
	var migrationErr *sqlschema.MigrationError
	if errors.As(err, &migrationErr) {
		return nil, nil // the schema rules report the migration; nothing to check against
	}
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	if check == scanNullable && schema == nil {
		return nil, nil // nullability comes from the migrations
	}
	reported := make(map[string]bool)
	return rules.AnalyzeTypedFiles(ctx, rule.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		scan := &scanAnalysis{rule: rule, check: check, project: ctx, ctx: fileCtx, info: info, schema: schema, reported: reported}
		for _, decl := range fileCtx.GoAST.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				scan.function(fn)
			}
		}
		return scan.violations
	})
}

type scanAnalysis struct {
	rule       *rules.BaseRule
	check      scanCheck
	project    *core.GoProjectContext
	ctx        *core.FileContext
	info       *types.Info
	schema     *sqlschema.Schema // nil without migrations
	reported   map[string]bool   // file:line reported, across the files of the project
	violations []*core.Violation
}

func (a *scanAnalysis) function(fn *ast.FuncDecl) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "Scan" {
			a.rowScan(fn, call, sel)
			return true
		}
		if destIdx, queryIdx, ok := a.sqlxRead(call); ok {
			a.structRead(fn, call, call.Args[destIdx], call.Args[queryIdx])
		}
		return true
	})
}

// rowScan checks Scan(&a, &b) against the query the rows come from:
// db.QueryRow(q).Scan(...) or rows.Scan(...) on rows := db.Query(q).
func (a *scanAnalysis) rowScan(fn *ast.FuncDecl, scan *ast.CallExpr, sel *ast.SelectorExpr) {
	if a.check != scanNullable {
		return
	}
	queryCall := a.rowsSource(fn, sel.X)
	if queryCall == nil {
		return
	}
	targets, ok := a.queryTargets(fn, queryCall)
	if !ok || len(targets) != len(scan.Args) || scan.Ellipsis.IsValid() {
		return
	}
	for i, arg := range scan.Args {
		unary, ok := arg.(*ast.UnaryExpr)
		if !ok || unary.Op != token.AND || !targets[i].Nullable {
			continue
		}
		if kind, value := nonNullValue(a.info.TypeOf(unary.X)); value {
			a.report(a.ctx, a.ctx.LineFor(arg), fmt.Sprintf(
				"Column %s can be NULL and is scanned into %s (%s) — the query fails on the first row holding NULL",
				targets[i].Name, types.ExprString(unary.X), kind), nullableSuggestion, "row_scan")
		}
	}
}

// rowsSource returns the query call whose rows expr holds.
func (a *scanAnalysis) rowsSource(fn *ast.FuncDecl, expr ast.Expr) *ast.CallExpr {
	switch x := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		return x
	case *ast.Ident:
		rhs := definingValue(fn, a.info, x)
		if call, ok := rhs.(*ast.CallExpr); ok {
			return call
		}
	}
	return nil
}

// queryTargets returns the SELECT a query call runs, with its columns: the
// first string argument, a literal or a local variable assigned one.
func (a *scanAnalysis) queryTargets(fn *ast.FuncDecl, call *ast.CallExpr) ([]sqlschema.Target, bool) {
	for _, arg := range call.Args {
		if !isStringType(a.info.TypeOf(arg)) {
			continue
		}
		_, targets, ok := a.targetsOf(fn, arg)
		return targets, ok
	}
	return nil, false
}

func (a *scanAnalysis) targetsOf(fn *ast.FuncDecl, arg ast.Expr) (sqlLiteral, []sqlschema.Target, bool) {
	expr := ast.Unparen(arg)
	if ident, ok := expr.(*ast.Ident); ok {
		expr = definingValue(fn, a.info, ident)
		if expr == nil {
			return sqlLiteral{}, nil, false
		}
	}
	literals := sqlLiterals(expr)
	if len(literals) != 1 {
		return sqlLiteral{}, nil, false
	}
	literal := literals[0]
	if targets, ok := sqlschema.SelectTargets(literal.text, a.schema); ok {
		return literal, targets, true
	}
	if literal.bare == "" {
		return sqlLiteral{}, nil, false
	}
	targets, ok := sqlschema.SelectTargets(literal.bare, a.schema)
	return literal, targets, ok
}

// sqlxRead recognizes a sqlx-style read, Get or Select with or without a
// context, by its signature: (ctx?, dest any, query string, args ...any)
// error. It returns the indexes of dest and query.
func (a *scanAnalysis) sqlxRead(call *ast.CallExpr) (int, int, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, 0, false
	}
	switch sel.Sel.Name {
	case "Get", "Select", "GetContext", "SelectContext":
	default:
		return 0, 0, false
	}
	if inner, ok := ast.Unparen(sel.X).(*ast.CallExpr); ok {
		if innerSel, ok := inner.Fun.(*ast.SelectorExpr); ok && innerSel.Sel.Name == "Unsafe" {
			return 0, 0, false // Unsafe ignores the columns the struct lacks
		}
	}
	sig, ok := a.info.TypeOf(call.Fun).(*types.Signature)
	if !ok || !sig.Variadic() || sig.Params().Len() < 3 || sig.Results().Len() != 1 {
		return 0, 0, false
	}
	params := sig.Params()
	destIdx, queryIdx := params.Len()-3, params.Len()-2
	if !types.IsInterface(params.At(destIdx).Type()) || !isStringType(params.At(queryIdx).Type()) || len(call.Args) <= queryIdx {
		return 0, 0, false
	}
	return destIdx, queryIdx, true
}

// structRead checks a sqlx read of the query into dest.
func (a *scanAnalysis) structRead(fn *ast.FuncDecl, call *ast.CallExpr, dest, query ast.Expr) {
	literal, targets, ok := a.targetsOf(fn, query)
	if !ok {
		return
	}
	elem := sqlxElem(a.info.TypeOf(dest))
	if elem == nil {
		return
	}
	st, isStruct := elem.Underlying().(*types.Struct)
	if !isStruct || scannable(elem) {
		if a.check == scanNullable && len(targets) == 1 && targets[0].Nullable {
			if kind, value := nonNullValue(elem); value {
				a.report(a.ctx, a.ctx.LineFor(call), fmt.Sprintf(
					"Column %s can be NULL and is read into %s (%s) — the query fails on a row holding NULL",
					targets[0].Name, types.ExprString(dest), kind), nullableSuggestion, "sqlx_value")
			}
		}
		return
	}
	fields := sqlxFields(st)
	for _, target := range targets {
		if target.Name == "" {
			continue // PostgreSQL names it ?column? or after a type: not known here
		}
		line := literal.lineAt(a.ctx, target.Offset)
		field, mapped := fields[target.Name]
		switch {
		case a.check == scanNullable && mapped && target.Nullable:
			if kind, value := nonNullValue(field.Type()); value {
				a.report(a.ctx, line, fmt.Sprintf(
					"Column %s can be NULL and is read into %s.%s (%s) — the query fails on the first row holding NULL",
					target.Name, typeName(elem), field.Name(), kind), nullableSuggestion, "sqlx_struct")
			}
		case a.check == scanUnmapped && !mapped:
			a.reportUnmapped(st, elem, target.Name, line)
		}
	}
}

// reportUnmapped reports a column the struct has no field for: on the field
// without a db tag that names it in snake case, or else on the column.
func (a *scanAnalysis) reportUnmapped(st *types.Struct, elem types.Type, column string, line int) {
	for i := range st.NumFields() {
		field := st.Field(i)
		if !field.Exported() || reflect.StructTag(st.Tag(i)).Get("db") != "" || snakeCase(field.Name()) != column {
			continue
		}
		fieldCtx, err := a.project.FileForPosition(field.Pos())
		if err == nil {
			a.report(fieldCtx, fieldCtx.LineForPos(field.Pos()), fmt.Sprintf(
				"sqlx reads %s.%s as %s, the query returns %s — the read fails with missing destination name",
				typeName(elem), field.Name(), strings.ToLower(field.Name()), column),
				fmt.Sprintf("Tag the field db:%q", column), "untagged_field")
			return
		}
		break // declared outside the project: the column is reported
	}
	a.report(a.ctx, line, fmt.Sprintf(
		"The query returns %s and %s has no field for it — sqlx fails with missing destination name %s",
		column, typeName(elem), column), "Add a field tagged with the column, or drop the column from the query", "missing_field")
}

func (a *scanAnalysis) report(ctx *core.FileContext, line int, message, suggestion, pattern string) {
	key := fmt.Sprintf("%s:%d", ctx.RelPath, line)
	if a.reported[key] || ctx.IsSuppressed(line, a.rule.Name()) {
		return
	}
	a.reported[key] = true
	v := a.rule.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(suggestion)
	v.WithContext("pattern", pattern)
	a.violations = append(a.violations, v)
}

// definingValue returns the value a local variable is declared with: x :=
// value, var x = value.
func definingValue(fn *ast.FuncDecl, info *types.Info, ident *ast.Ident) ast.Expr {
	obj := info.Uses[ident]
	if obj == nil {
		return nil
	}
	var value ast.Expr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if value != nil {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok != token.DEFINE || len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && info.Defs[id] == obj {
					value = node.Rhs[i]
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if info.Defs[name] == obj && i < len(node.Values) {
					value = node.Values[i]
				}
			}
		}
		return true
	})
	if value == nil {
		// x, err := db.Query(...): the first value of a call.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || assign.Tok != token.DEFINE || len(assign.Rhs) != 1 || value != nil {
				return value == nil
			}
			if id, ok := assign.Lhs[0].(*ast.Ident); ok && info.Defs[id] == obj {
				value = assign.Rhs[0]
			}
			return true
		})
	}
	return value
}

// nonNullValue reports a type database/sql cannot put NULL into, and names
// it: a string, number or bool without a Scan method of its own, a
// time.Time.
func nonNullValue(typ types.Type) (string, bool) {
	if typ == nil || hasScanMethod(typ) {
		return "", false
	}
	if named := namedOf(typ); named != nil && named == typ && named.Obj().Pkg().Path() == "time" && named.Obj().Name() == "Time" {
		return "time.Time", true
	}
	basic, ok := typ.Underlying().(*types.Basic)
	if !ok || basic.Info()&(types.IsString|types.IsNumeric|types.IsBoolean) == 0 {
		return "", false
	}
	return typeName(typ), true
}

func hasScanMethod(typ types.Type) bool {
	if _, isPointer := typ.(*types.Pointer); !isPointer {
		typ = types.NewPointer(typ)
	}
	obj, _, _ := types.LookupFieldOrMethod(typ, true, nil, "Scan")
	_, isFunc := obj.(*types.Func)
	return isFunc
}

// sqlxElem returns the type a sqlx destination reads rows into: *T, *[]T,
// *[]*T.
func sqlxElem(dest types.Type) types.Type {
	ptr, ok := dest.(*types.Pointer)
	if !ok {
		return nil
	}
	elem := ptr.Elem()
	if slice, isSlice := elem.Underlying().(*types.Slice); isSlice {
		elem = slice.Elem()
		if inner, isPointer := elem.(*types.Pointer); isPointer {
			elem = inner.Elem()
		}
	}
	return elem
}

// scannable reports a struct sqlx reads as one value: one with a Scan
// method, or without exported fields, like time.Time.
func scannable(typ types.Type) bool {
	if hasScanMethod(typ) {
		return true
	}
	st, ok := typ.Underlying().(*types.Struct)
	if !ok {
		return true
	}
	for i := range st.NumFields() {
		if st.Field(i).Exported() {
			return false
		}
	}
	return true
}

// sqlxFields maps the columns sqlx fills to the fields of a struct: the db
// tag, or the lower-cased name; embedded structs without a tag lend their
// fields.
func sqlxFields(st *types.Struct) map[string]*types.Var {
	fields := make(map[string]*types.Var)
	for i := range st.NumFields() {
		field := st.Field(i)
		tag := strings.Split(reflect.StructTag(st.Tag(i)).Get("db"), ",")[0]
		if tag == "-" || (!field.Exported() && !field.Embedded()) {
			continue
		}
		if field.Embedded() && tag == "" {
			if inner, ok := derefStruct(field.Type()); ok {
				for name, innerField := range sqlxFields(inner) {
					if _, taken := fields[name]; !taken {
						fields[name] = innerField
					}
				}
				continue
			}
		}
		name := tag
		if name == "" {
			name = strings.ToLower(field.Name())
		}
		fields[name] = field
	}
	return fields
}

// typeName writes a type without package paths: models.Investment is
// Investment.
func typeName(typ types.Type) string {
	return types.TypeString(typ, func(*types.Package) string { return "" })
}

// snakeCase spells a Go name the way a column is: ChannelName is
// channel_name, UserID is user_id.
func snakeCase(name string) string {
	var b strings.Builder
	runes := []rune(name)
	for i, r := range runes {
		upper := r >= 'A' && r <= 'Z'
		if upper && i > 0 {
			prevLower := runes[i-1] >= 'a' && runes[i-1] <= 'z' || runes[i-1] >= '0' && runes[i-1] <= '9'
			nextLower := i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z'
			if prevLower || (nextLower && runes[i-1] >= 'A' && runes[i-1] <= 'Z') {
				b.WriteByte('_')
			}
		}
		b.WriteString(strings.ToLower(string(r)))
	}
	return b.String()
}

// customNameMapper reports a project that sets how sqlx maps columns to
// fields.
func customNameMapper(ctx *core.GoProjectContext) bool {
	for _, file := range ctx.Files {
		if file.GoAST == nil {
			continue
		}
		found := false
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "MapperFunc", "NewMapperFunc", "NewMapper", "NewMapperTagFunc", "NameMapper":
					found = true
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}
