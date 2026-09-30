package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLModelFieldSkippedRule())
}

// SQLModelFieldSkippedRule detects a model written or read by SQL that leaves
// out a column the model maps with a db tag:
//
//	INSERT INTO orders (id, user_id, amount) VALUES ($1, $2, $3)        -- order.RegionID never stored,
//	    order.ID, order.UserID, order.Amount                            -- region_id takes DEFAULT 1
//
//	SELECT id, email, status FROM users WHERE id = $1                   -- user.NotifyEnabled stays
//	    Scan(&user.ID, &user.Email, &user.Status); return &user         -- false for everyone
//
//	func (u *User) Columns() []string { return []string{"id", "email"} } // member_code missing
//
// The column exists in the table the migrations leave and the model has a
// field for it, but the statement skips it: an INSERT stores the column
// default in place of the model's value (reported for columns with a
// constant default — a generated one, now() or a sequence, is meant to be
// left out), a SELECT scanned into a model the function returns hands back
// the zero value, a column list written in a method of the model misses a
// field every statement built from it then skips.
type SQLModelFieldSkippedRule struct {
	*rules.BaseRule
}

// NewSQLModelFieldSkippedRule creates the rule
func NewSQLModelFieldSkippedRule() *SQLModelFieldSkippedRule {
	return &SQLModelFieldSkippedRule{BaseRule: rules.NewBaseRule(
		"sql-model-field-skipped",
		"patterns",
		"Detects SQL writing or reading a model that leaves out a column the model maps with a db tag",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the model is known only with type information.
func (r *SQLModelFieldSkippedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLModelFieldSkippedRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks the statements of the project that write or read a
// model against the schema.
func (r *SQLModelFieldSkippedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	schema, err := sqlschema.LoadCached(ctx.ProjectRoot, migrationDirs(r.BaseRule))
	var migrationErr *sqlschema.MigrationError
	if errors.As(err, &migrationErr) {
		return nil, nil // the schema rules report the migration; nothing to check against
	}
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	if schema == nil {
		return nil, nil
	}
	funcsByInfo := make(map[*types.Info]map[string]*ast.FuncDecl)
	updatedByInfo := make(map[*types.Info]map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg != nil && pkg.Package != nil {
			funcsByInfo[pkg.Package.TypesInfo] = packageFuncs(pkg)
			updatedByInfo[pkg.Package.TypesInfo] = updatedColumns(pkg, schema)
		}
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		check := &modelFieldCheck{rule: r, ctx: fileCtx, info: info, schema: schema,
			funcs: funcsByInfo[info], updated: updatedByInfo[info]}
		for _, decl := range fileCtx.GoAST.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				check.function(fn)
			}
		}
		return check.violations
	})
}

type modelFieldCheck struct {
	rule       *SQLModelFieldSkippedRule
	ctx        *core.FileContext
	info       *types.Info
	schema     *sqlschema.Schema
	funcs      map[string]*ast.FuncDecl // the package's own functions, see packageFuncs
	updated    map[string]bool          // table.column an UPDATE of the package sets
	violations []*core.Violation
}

// updatedColumns returns the columns, as table.column, the UPDATE statements
// of a package set.
func updatedColumns(pkg *core.GoPackageContext, schema *sqlschema.Schema) map[string]bool {
	updated := make(map[string]bool)
	for _, file := range pkg.Files {
		if file == nil || file.GoAST == nil || file.IsTestFile() {
			continue
		}
		for _, literal := range sqlLiterals(file.GoAST) {
			if shape, ok := literal.shape(schema); ok && shape.Kind == "update" {
				for _, column := range shape.Columns {
					updated[shape.Table+"."+column] = true
				}
			}
		}
	}
	return updated
}

// shape returns the shape of the statement, reading it without the operands
// that are not literals when it does not parse with them as parameters.
func (l sqlLiteral) shape(schema *sqlschema.Schema) (*sqlschema.Shape, bool) {
	if shape, ok := schema.Shape(l.text); ok {
		return shape, true
	}
	if l.bare == "" {
		return nil, false
	}
	return schema.Shape(l.bare)
}

// modelShape is a statement of a function with its table and columns.
type modelShape struct {
	literal sqlLiteral
	shape   *sqlschema.Shape
}

func (c *modelFieldCheck) function(fn *ast.FuncDecl) {
	var shapes []modelShape
	for _, literal := range sqlLiterals(fn.Body) {
		if shape, ok := literal.shape(c.schema); ok {
			shapes = append(shapes, modelShape{literal: literal, shape: shape})
		}
	}
	for _, s := range shapes {
		switch s.shape.Kind {
		case "insert":
			c.insert(fn, s)
		case "select":
			c.selectInto(fn, s)
		}
	}
	c.columnLists(fn)
}

// insert reports the columns with a constant default an INSERT leaves out
// while it stores fields of the model beside them. A column an UPDATE of the
// package sets is written later in the row's life — a run created first and
// finished with its counters.
func (c *modelFieldCheck) insert(fn *ast.FuncDecl, s modelShape) {
	listed := s.shape.Columns
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		model, fields := c.modelArgs(call.Args, false)
		if model == nil || len(fields) < 2 {
			return true
		}
		inserted := 0
		for _, field := range fields {
			if slices.Contains(listed, field) {
				inserted++
			}
		}
		if inserted*2 < len(fields) {
			return true
		}
		table := c.schema.Table(s.shape.Table)
		var missing []string
		for _, tag := range model.tags {
			column := table.Column(tag)
			if column != nil && column.HasDefault && !column.GeneratedDefault && !slices.Contains(listed, tag) &&
				!c.updated[table.Name+"."+tag] {
				missing = append(missing, tag)
			}
		}
		if len(missing) > 0 {
			c.report(s.literal.lineAt(c.ctx, s.shape.LastOffset), fmt.Sprintf(
				"INSERT into %s stores fields of %s but leaves out %s — the column default replaces the model's value",
				s.shape.Table, model.name, strings.Join(missing, ", ")), "insert")
		}
		return false
	})
}

// selectInto reports the model fields a SELECT leaves out when its row is
// scanned into a model the function hands back.
func (c *modelFieldCheck) selectInto(fn *ast.FuncDecl, s modelShape) {
	for _, scan := range c.scans(fn) {
		if scan.count != len(s.shape.Columns) {
			continue
		}
		table := c.schema.Table(s.shape.Table)
		var missing []string
		for _, tag := range scan.model.tags {
			if table.Column(tag) != nil && !slices.Contains(s.shape.Columns, tag) {
				missing = append(missing, tag)
			}
		}
		if len(missing) > 0 {
			c.report(s.literal.lineAt(c.ctx, s.shape.LastOffset), fmt.Sprintf(
				"SELECT from %s fills %s but leaves out %s — the returned model carries zero values for them",
				s.shape.Table, scan.model.name, strings.Join(missing, ", ")), "select")
		}
		return
	}
}

// modelScan is a Scan into the fields of a model returned by the function
// holding it.
type modelScan struct {
	model *dbModel
	count int // arguments of the Scan
}

// scans returns the Scans of fn into models, and the Scans of the functions
// of the package fn hands its rows to.
func (c *modelFieldCheck) scans(fn *ast.FuncDecl) []modelScan {
	result := c.ownScans(fn)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := ast.Unparen(call.Fun).(*ast.Ident)
		if !ok {
			return true
		}
		if _, ok := c.info.Uses[ident].(*types.Func); !ok {
			return true
		}
		if decl := c.funcs[ident.Name]; decl != nil && decl != fn {
			result = append(result, c.ownScans(decl)...)
		}
		return true
	})
	return result
}

func (c *modelFieldCheck) ownScans(fn *ast.FuncDecl) []modelScan {
	var result []modelScan
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Scan" {
			return true
		}
		model, fields := c.modelArgs(call.Args, true)
		if model == nil || len(fields) < 2 || len(fields)*2 < len(call.Args) || !c.returns(fn, model.typ) {
			return true
		}
		result = append(result, modelScan{model: model, count: len(call.Args)})
		return true
	})
	return result
}

// returns reports whether fn returns the model, a pointer to it or a slice
// of either.
func (c *modelFieldCheck) returns(fn *ast.FuncDecl, model *types.Named) bool {
	obj, ok := c.info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok {
		return false
	}
	for i := range sig.Results().Len() {
		typ := sig.Results().At(i).Type()
		if slice, isSlice := typ.Underlying().(*types.Slice); isSlice {
			typ = slice.Elem()
		}
		if named := namedOf(typ); named != nil && named.Obj() == model.Obj() {
			return true
		}
	}
	return false
}

// columnLists reports a list of column names written in a method of the
// model that names some of its db tags and misses others the table has.
func (c *modelFieldCheck) columnLists(fn *ast.FuncDecl) {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return
	}
	model := c.dbModelOf(c.info.TypeOf(fn.Recv.List[0].Type))
	if model == nil {
		return
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		names, ok := stringElements(lit)
		if !ok || len(names) < 3 {
			return false
		}
		for _, name := range names {
			if !slices.Contains(model.tags, name) {
				return false
			}
		}
		tables := c.schema.TablesWith(names)
		if len(tables) != 1 {
			return false
		}
		var missing []string
		for _, tag := range model.tags {
			if tables[0].Column(tag) != nil && !slices.Contains(names, tag) {
				missing = append(missing, tag)
			}
		}
		if len(missing) > 0 {
			c.report(c.ctx.LineFor(lit.Elts[0]), fmt.Sprintf(
				"The column list of %s leaves out %s of %s — every statement built from it skips the field",
				model.name, strings.Join(missing, ", "), tables[0].Name), "column_list")
		}
		return false
	})
}

// stringElements returns the elements of a []string literal.
func stringElements(lit *ast.CompositeLit) ([]string, bool) {
	arr, ok := lit.Type.(*ast.ArrayType)
	if !ok || !isIdentNamed(arr.Elt, "string") {
		return nil, false
	}
	names := make([]string, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		basic, ok := elt.(*ast.BasicLit)
		if !ok {
			return nil, false
		}
		name, ok := goStringLiteral(basic)
		if !ok {
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}

// dbModel is a struct type whose fields carry db tags.
type dbModel struct {
	typ     *types.Named
	name    string
	tags    []string // db tags of the fields, in order
	byField map[*types.Var]string
}

// dbModelOf returns the model behind typ, or nil when typ is not a struct
// with db tags.
func (c *modelFieldCheck) dbModelOf(typ types.Type) *dbModel {
	named := namedOf(typ)
	if named == nil {
		return nil
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return nil
	}
	model := &dbModel{typ: named, name: named.Obj().Name(), byField: make(map[*types.Var]string)}
	for i := range st.NumFields() {
		tag := strings.Split(reflect.StructTag(st.Tag(i)).Get("db"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		model.tags = append(model.tags, tag)
		model.byField[st.Field(i)] = tag
	}
	if len(model.tags) == 0 {
		return nil
	}
	return model
}

// modelArgs finds the model most of the arguments are fields of — v.F, or
// &v.F for a Scan — and returns it with the db tags of those fields.
func (c *modelFieldCheck) modelArgs(args []ast.Expr, addressed bool) (*dbModel, []string) {
	fieldsOf := make(map[types.Object][]string)
	models := make(map[types.Object]*dbModel)
	var order []types.Object
	for _, arg := range args {
		if addressed {
			unary, ok := arg.(*ast.UnaryExpr)
			if !ok || unary.Op != token.AND {
				continue
			}
			arg = unary.X
		}
		sel, ok := ast.Unparen(arg).(*ast.SelectorExpr)
		if !ok {
			continue
		}
		base, ok := sel.X.(*ast.Ident)
		if !ok {
			continue
		}
		obj := c.info.Uses[base]
		field, ok := c.info.Uses[sel.Sel].(*types.Var)
		if obj == nil || !ok || !field.IsField() {
			continue
		}
		model, seen := models[obj]
		if !seen {
			model = c.dbModelOf(obj.Type())
			models[obj] = model
			order = append(order, obj)
		}
		if model == nil {
			continue
		}
		if tag, tagged := model.byField[field]; tagged {
			fieldsOf[obj] = append(fieldsOf[obj], tag)
		}
	}
	var best types.Object
	for _, obj := range order {
		if best == nil || len(fieldsOf[obj]) > len(fieldsOf[best]) {
			best = obj
		}
	}
	if best == nil || models[best] == nil {
		return nil, nil
	}
	return models[best], fieldsOf[best]
}

func (c *modelFieldCheck) report(line int, message, pattern string) {
	if c.ctx.IsSuppressed(line, c.rule.Name()) {
		return
	}
	v := c.rule.CreateViolation(c.ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(c.ctx.GetLine(line)))
	v.WithSuggestion("List the column in the statement, or drop the db tag from a field the table does not own")
	v.WithContext("pattern", pattern)
	c.violations = append(c.violations, v)
}
