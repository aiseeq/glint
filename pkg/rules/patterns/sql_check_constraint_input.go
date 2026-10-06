package patterns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLCheckConstraintInputUnvalidatedRule())
}

// SQLCheckConstraintInputUnvalidatedRule detects a field of a decoded request
// body that reaches a column the migrations keep within a set or a range by
// a CHECK constraint, with nothing on the way comparing the field with that
// set or range:
//
//	-- category VARCHAR(32) CHECK (category IN ('dex', 'lending', 'yield'))
//	json.NewDecoder(req.Body).Decode(&protocol)
//	r.service.CreateEntry(ctx, &protocol)   // checks only protocol.Category != ""
//	    r.repo.Create(ctx, protocol)           // INSERT ... VALUES ($3) ← protocol.Category
//
// A value outside the set fails in the database with check_violation, and
// the client gets a 500 carrying the constraint's text instead of a 400
// naming the field. A field compared with a constant other than "" (a set
// member, a bound), switched on, looked up or handed to a validating call
// on the way counts as checked, and so does a write whose function maps the
// check violation (23514).
type SQLCheckConstraintInputUnvalidatedRule struct {
	*rules.BaseRule
}

// NewSQLCheckConstraintInputUnvalidatedRule creates the rule
func NewSQLCheckConstraintInputUnvalidatedRule() *SQLCheckConstraintInputUnvalidatedRule {
	return &SQLCheckConstraintInputUnvalidatedRule{BaseRule: rules.NewBaseRule(
		"sql-check-constraint-input-unvalidated",
		"patterns",
		"Detects a request body field written to a column with a CHECK set or range (col IN (...), BETWEEN) that nothing on the way compares with it — a value outside fails in the database and the client gets a 500",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the check needs types and the migrations.
func (r *SQLCheckConstraintInputUnvalidatedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *SQLCheckConstraintInputUnvalidatedRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the request fields that reach a CHECK column
// unvalidated.
func (r *SQLCheckConstraintInputUnvalidatedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return analyzeAgainstSchema(ctx, r.BaseRule,
		"Compare the field with the constraint's set or range before the write (the same list as the migration) and answer 400 naming the field",
		uncheckedConstraintInputs)
}

// maxCheckBindDepth bounds how deep calls are followed from the handler to
// the write.
const maxCheckBindDepth = 3

// checkedBind is a field of a request struct bound to a CHECK column.
type checkedBind struct {
	field  string
	table  string
	column *sqlschema.Column
}

// uncheckedConstraintInputs returns the calls of a handler that hand its
// decoded request body on to a write binding a field of it to a CHECK
// column, with no check of the field on the way.
func uncheckedConstraintInputs(scope funcScope, schema *sqlschema.Schema, fn *ast.FuncDecl) []funcFinding {
	handler := typedFunc{info: scope.info, decl: fn}
	if fn.Body == nil || handlerRequestParam(handler) == nil {
		return nil
	}
	var findings []funcFinding
	for _, target := range requestDecodeTargets(handler) {
		body, ok := ast.Unparen(addressed(target)).(*ast.Ident)
		if !ok {
			continue
		}
		obj := scope.info.ObjectOf(body)
		checked := checkedFieldsDeep(scope.decls, scope.info, fn.Body, obj, maxCheckBindDepth)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for i, arg := range call.Args {
				whole, ok := ast.Unparen(addressed(arg)).(*ast.Ident)
				if !ok || scope.info.ObjectOf(whole) != obj {
					continue
				}
				binds := constraintBinds(scope.decls, schema, scope.info, call, i, 1, checked)
				if len(binds) == 0 {
					continue
				}
				first := binds[0]
				message := fmt.Sprintf("%s.%s from the request body reaches %s.%s, CHECK (%s), and nothing on the way compares it with that — a value outside fails in the database and the client gets a 500",
					body.Name, first.field, first.table, first.column.Name, first.column.Check.String(first.column.Name))
				if len(binds) > 1 {
					message += fmt.Sprintf(" (%d more such fields)", len(binds)-1)
				}
				findings = append(findings, funcFinding{node: call, message: message})
			}
			return true
		})
	}
	return findings
}

// constraintBinds returns the fields of the struct a project function gets
// as its index-th parameter that it binds - itself or through the functions
// it hands the struct on to - to a column with a CHECK set or range, none of
// them checked on the way (checked holds what the callers checked).
func constraintBinds(decls map[*types.Func]typedFuncDecl, schema *sqlschema.Schema, info *types.Info, call *ast.CallExpr, index, depth int, checked map[string]bool) []checkedBind {
	callee := staticFunc(info, call)
	if callee == nil || depth > maxCheckBindDepth {
		return nil
	}
	decl, ok := decls[callee.Origin()]
	if !ok {
		return nil
	}
	params := paramObjects(decl)
	if index >= len(params) || params[index] == nil || mapsCheckViolation(decls, decl, 2) {
		return nil
	}
	param := params[index]
	seen := make(map[string]bool, len(checked))
	for field := range checked {
		seen[field] = true
	}
	for field := range checkedFieldsDeep(decls, decl.info, decl.decl.Body, param, maxCheckBindDepth-depth) {
		seen[field] = true
	}
	queries := namedStrings(decl.decl)
	var binds []checkedBind
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		inner, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for i, arg := range inner.Args {
			if field := paramField(decl.info, arg, param); field != "" {
				column, table := boundColumn(schema, queries, inner, i)
				if column != nil && column.Check != nil && !seen[field] {
					binds = append(binds, checkedBind{field: field, table: table, column: column})
				}
				continue
			}
			if passesParam(decl.info, addressed(arg), param) {
				binds = append(binds, constraintBinds(decls, schema, decl.info, inner, i, depth+1, seen)...)
			}
		}
		return true
	})
	return binds
}

// paramField returns F of an argument param.F (or *param.F); "" for any
// other argument.
func paramField(info *types.Info, arg ast.Expr, param *types.Var) string {
	arg = ast.Unparen(arg)
	if star, ok := arg.(*ast.StarExpr); ok {
		arg = ast.Unparen(star.X)
	}
	sel, ok := arg.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok && info.Uses[id] == param {
		return sel.Sel.Name
	}
	return ""
}

// checkedFields returns the fields of obj a body checks against values or
// sets itself (p.F = value):
// obj.F compared with a constant other than "" and 0, switched on, used as a
// map key, handed to a call that is not a query, a logger or a string helper,
// or asked by a method of its own.
func checkedFields(info *types.Info, body *ast.BlockStmt, obj types.Object) map[string]bool {
	checked := make(map[string]bool)
	if body == nil || obj == nil {
		return checked
	}
	fieldOf := func(expr ast.Expr) string {
		if param, ok := obj.(*types.Var); ok {
			return paramField(info, expr, param)
		}
		return ""
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			// p.F = value: the server sets the field, the client's value is gone.
			for _, lhs := range node.Lhs {
				if field := fieldOf(lhs); field != "" {
					checked[field] = true
				}
			}
		case *ast.BinaryExpr:
			for _, pair := range [][2]ast.Expr{{node.X, node.Y}, {node.Y, node.X}} {
				if field := fieldOf(pair[0]); field != "" && comparesWithValue(info, node.Op, pair[1]) {
					checked[field] = true
				}
			}
		case *ast.SwitchStmt:
			if field := fieldOf(node.Tag); field != "" {
				checked[field] = true
			}
		case *ast.IndexExpr:
			if field := fieldOf(node.Index); field != "" {
				checked[field] = true
			}
		case *ast.SelectorExpr:
			// p.F.Valid(): a method of the field's own type.
			if field := fieldOf(node.X); field != "" {
				checked[field] = true
			}
		case *ast.CallExpr:
			if helpers.IsLoggerCall(node) || stringHelper(node) || queryCall(node) {
				return true
			}
			for _, arg := range node.Args {
				if field := fieldOf(arg); field != "" {
					checked[field] = true
				}
			}
		}
		return true
	})
	return checked
}

// checkedFieldsDeep returns the fields of obj a body checks, itself or in
// the project functions it hands obj to whole (validate(p)), within depth
// calls.
func checkedFieldsDeep(decls map[*types.Func]typedFuncDecl, info *types.Info, body *ast.BlockStmt, obj types.Object, depth int) map[string]bool {
	checked := checkedFields(info, body, obj)
	v, ok := obj.(*types.Var)
	if body == nil || !ok || depth <= 0 {
		return checked
	}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := staticFunc(info, call)
		if callee == nil {
			return true
		}
		decl, ok := decls[callee.Origin()]
		if !ok || decl.decl.Body == nil {
			return true
		}
		params := paramObjects(decl)
		for i, arg := range call.Args {
			if i < len(params) && params[i] != nil && passesParam(info, addressed(arg), v) {
				for field := range checkedFieldsDeep(decls, decl.info, decl.decl.Body, params[i], depth-1) {
					checked[field] = true
				}
			}
		}
		return true
	})
	return checked
}

// comparesWithValue reports a comparison with a constant that names a value:
// not the empty string, not zero.
func comparesWithValue(info *types.Info, op token.Token, other ast.Expr) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ:
	default:
		return false
	}
	tv, ok := info.Types[other]
	if !ok || tv.Value == nil {
		return false
	}
	switch tv.Value.Kind() {
	case constant.String:
		return constant.StringVal(tv.Value) != ""
	case constant.Int, constant.Float:
		return constant.Sign(tv.Value) != 0 || op != token.EQL && op != token.NEQ
	}
	return false
}

// stringHelper reports a call of fmt, strings or strconv: it formats or
// trims the value, it does not check it against a set.
func stringHelper(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && (pkg.Name == "fmt" || pkg.Name == "strings" || pkg.Name == "strconv" || pkg.Name == "errors")
}

// queryCall reports a database call (ExecContext, QueryRow).
func queryCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && queryMethods[sel.Sel.Name]
}

// checkViolationMark is code that recognises a check violation.
var checkViolationMark = []string{"23514", "check_violation", "CheckViolation"}

// mapsCheckViolation reports a function that recognises a check violation,
// itself or in a project function it calls within depth calls.
func mapsCheckViolation(decls map[*types.Func]typedFuncDecl, decl typedFuncDecl, depth int) bool {
	found := false
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind == token.STRING && containsAny(node.Value, checkViolationMark) {
				found = true
			}
		case *ast.Ident:
			found = containsAny(node.Name, checkViolationMark)
		case *ast.CallExpr:
			if callee := staticFunc(decl.info, node); callee != nil && depth > 0 {
				if inner, ok := decls[callee.Origin()]; ok && inner.decl.Body != nil {
					found = mapsCheckViolation(decls, inner, depth-1)
				}
			}
		}
		return !found
	})
	return found
}

// containsAny reports text holding one of marks.
func containsAny(text string, marks []string) bool {
	for _, mark := range marks {
		if strings.Contains(text, mark) {
			return true
		}
	}
	return false
}
