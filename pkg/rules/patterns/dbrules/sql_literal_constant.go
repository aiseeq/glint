package dbrules

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() { rules.Register(NewSQLLiteralCopiesConstantRule()) }

// SQLLiteralCopiesConstantRule detects SQL text that keeps its own copy of
// what a Go constant of the project already holds.
//
// A UUID written into the query:
//
//	const SystemUserID = "00000000-0000-0000-0000-000000000001"
//	... AND user_id NOT IN ('00000000-0000-0000-0000-000000000001', ...)
//
// A condition of a predicate constant — a constant (or a function returning
// fmt.Sprintf) whose name has a Clause, Expr, Where, Filter, Predicate, Cond,
// SQL or Query part and whose value is a condition fragment — written by hand:
//
//	const ExcludeArchivedClause = "status NOT IN ('deleted', 'archived')"
//	... FROM users u WHERE u.status NOT IN ('archived', 'deleted') AND ...
//
// Conditions compare after normalization (no aliases, != is <>, IN values
// sorted, NOT IN is a set of <>, $N bound to a constant argument). A
// condition the query already gets from a concatenated predicate constant is
// reported as redundant. String vars built from constants and SQL fragments
// returned by predicate functions are sources too; function prefixes are
// evaluated with an empty alias. Arithmetic column expressions from named SQL
// functions and numeric literals compared with columns named in a constant
// are also reported when copied. Not findings: the source file, full queries
// as the source of conditions, a guard of a single-row UPDATE or DELETE
// (WHERE id = $N), test files, and SQL that calls the source to build itself.
// When a source changes, the copy stays behind: use that source or pass values
// as query parameters.
type SQLLiteralCopiesConstantRule struct {
	*rules.BaseRule
	constants   map[string]string
	predicates  map[string][]predicateConstant
	values      map[string]string
	expressions map[string]predicateConstant
	thresholds  []thresholdConstant
}
type predicateConstant struct {
	name, location, path string
	line                 int
	expansionCount       int
	legacy               bool
}
type thresholdConstant struct {
	name, value, path string
	line              int
}

// NewSQLLiteralCopiesConstantRule creates the rule.
func NewSQLLiteralCopiesConstantRule() *SQLLiteralCopiesConstantRule {
	return &SQLLiteralCopiesConstantRule{BaseRule: rules.NewBaseRule(
		"sql-literal-copies-constant", "patterns",
		"Detects UUIDs, conditions, SQL expressions or named thresholds repeated in SQL when Go declarations already hold them",
		core.SeverityMedium,
	)}
}

var uuidText = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
var predicateName = regexp.MustCompile(`(?:Clause|Expr|Where|Filter|Predicate|Cond|SQL|Query)(?:$|[A-Z0-9_])`)
var predicatePrefix = regexp.MustCompile(`(?i)^(?:AND|WHERE)\b\s*`)
var predicateStatement = regexp.MustCompile(`(?i)^(?:SELECT|WITH|UPDATE|DELETE|INSERT|VALUES)\b`)
var formatVerb = regexp.MustCompile(`%[-+#0-9.]*[a-zA-Z]`)
var sqlParam = regexp.MustCompile(`\$([0-9]+)`)
var trailingBooleanOperator = regexp.MustCompile(`(?i)\b(?:AND|OR)\s*$`)

// UseProjectFiles indexes UUIDs, Go constant values and predicate atoms.
func (r *SQLLiteralCopiesConstantRule) UseProjectFiles(files []*core.FileContext) {
	r.constants = make(map[string]string)
	r.predicates = make(map[string][]predicateConstant)
	r.expressions = make(map[string]predicateConstant)
	r.thresholds = nil
	r.values = collectGoConstantValues(files)
	collectGoStringValues(r.values, files)
	r.predicates = sqlLiteralPredicateIndex(collectSQLPredicateIndex(files, r.values))
	indexPredicateConstants(r, files)
	indexPredicateFunctions(r, files)
}

func collectGoStringValues(values map[string]string, files []*core.FileContext) {
	for _, ctx := range files {
		if !patternkit.ProductionGoFile(ctx) {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, raw := range gen.Specs {
				spec, ok := raw.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range spec.Names {
					if i >= len(spec.Values) {
						continue
					}
					if value, ok := constString(spec.Values[i], values); ok {
						values[name.Name] = value
					}
				}
			}
		}
	}
}

func collectGoConstantValues(files []*core.FileContext) map[string]string {
	values := make(map[string]string)
	for _, ctx := range files {
		if !patternkit.ProductionGoFile(ctx) {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, raw := range gen.Specs {
				collectConstantValueSpec(values, raw)
			}
		}
	}
	return values
}

func collectConstantValueSpec(values map[string]string, raw ast.Spec) {
	spec, ok := raw.(*ast.ValueSpec)
	if !ok {
		return
	}
	for i, name := range spec.Names {
		if i >= len(spec.Values) {
			continue
		}
		if value, ok := constString(spec.Values[i], values); ok {
			values[name.Name] = value
		}
	}
}

func indexPredicateFunctions(r *SQLLiteralCopiesConstantRule, files []*core.FileContext) {
	for _, ctx := range files {
		if !patternkit.ProductionGoFile(ctx) {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !predicateName.MatchString(fn.Name.Name) || fn.Body == nil {
				continue
			}
			for _, returned := range returnedSQLStrings(fn, r.values) {
				if returned.node == nil || returned.expression == "" {
					continue
				}
				value := returned.expression
				if isSQLArithmeticExpression(value) {
					r.expressions[normalizeSQLExpression(value)] = predicateConstant{
						name: fn.Name.Name, path: ctx.RelPath, line: ctx.LineFor(returned.node),
						location: fmt.Sprintf("%s (%s:%d)", fn.Name.Name, ctx.RelPath, ctx.LineFor(returned.node)),
					}
				}
			}
		}
	}
}

type returnedSQLString struct {
	node            ast.Node
	expression      string
	predicateSource bool
}

type sqlStringContext struct {
	functions map[string]*ast.FuncDecl
	seen      map[string]bool
}

func returnedSQLStrings(fn *ast.FuncDecl, values map[string]string) []returnedSQLString {
	return returnedSQLStringsWithContext(fn, values, nil, nil)
}

func returnedSQLStringsWithContext(fn *ast.FuncDecl, values, args map[string]string, context *sqlStringContext) []returnedSQLString {
	locals := make(map[string]string)
	maps.Copy(locals, args)
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "string" {
				for _, name := range field.Names {
					if _, exists := locals[name.Name]; !exists && context != nil {
						locals[name.Name] = ""
					}
				}
			}
		}
	}
	var results []returnedSQLString
	for _, stmt := range fn.Body.List {
		inspectSQLStringStatement(stmt, locals, values, &results, context)
	}
	return results
}

func inspectSQLStringStatement(stmt ast.Stmt, locals, values map[string]string, results *[]returnedSQLString, context *sqlStringContext) {
	switch x := stmt.(type) {
	case *ast.DeclStmt:
		decl, ok := x.Decl.(*ast.GenDecl)
		if ok {
			for _, raw := range decl.Specs {
				if spec, ok := raw.(*ast.ValueSpec); ok {
					assignSQLStringValues(spec.Names, spec.Values, locals, values, context)
				}
			}
		}
	case *ast.AssignStmt:
		for i, lhs := range x.Lhs {
			id, ok := lhs.(*ast.Ident)
			if ok && i < len(x.Rhs) {
				if value, ok := staticString(x.Rhs[i], locals, values, context); ok {
					locals[id.Name] = value
				}
			}
		}
	case *ast.ReturnStmt:
		collectSQLStringReturn(x, locals, values, results, context)
	default:
		inspectSQLStringControl(stmt, locals, values, results, context)
	}
}

func assignSQLStringValues(names []*ast.Ident, exprs []ast.Expr, locals, values map[string]string, context *sqlStringContext) {
	for i, name := range names {
		if i < len(exprs) {
			if value, ok := staticString(exprs[i], locals, values, context); ok {
				locals[name.Name] = value
			}
		}
	}
}

func inspectSQLStringControl(stmt ast.Stmt, locals, values map[string]string, results *[]returnedSQLString, context *sqlStringContext) {
	inspectInit := func(init ast.Stmt) {
		if init != nil {
			inspectSQLStringStatement(init, locals, values, results, context)
		}
	}
	inspectChildren := func(children []ast.Stmt) {
		for _, child := range children {
			inspectSQLStringStatement(child, locals, values, results, context)
		}
	}
	switch x := stmt.(type) {
	case *ast.IfStmt:
		// Alias prefixes are indexed with the empty alias; return branches are
		// still visited so boolean options can contribute each SQL expression.
		inspectInit(x.Init)
		inspectSQLStringStatement(x.Body, locals, values, results, context)
		if x.Else != nil {
			inspectSQLStringStatement(x.Else, locals, values, results, context)
		}
	case *ast.ForStmt:
		inspectInit(x.Init)
		inspectSQLStringStatement(x.Body, locals, values, results, context)
	case *ast.RangeStmt:
		inspectSQLStringStatement(x.Body, locals, values, results, context)
	case *ast.SwitchStmt:
		inspectInit(x.Init)
		inspectSQLStringStatement(x.Body, locals, values, results, context)
	case *ast.TypeSwitchStmt:
		inspectInit(x.Init)
		inspectSQLStringStatement(x.Body, locals, values, results, context)
	case *ast.SelectStmt:
		inspectSQLStringStatement(x.Body, locals, values, results, context)
	case *ast.CaseClause:
		inspectChildren(x.Body)
	case *ast.CommClause:
		inspectChildren(x.Body)
	case *ast.BlockStmt:
		inspectChildren(x.List)
	}
}

func collectSQLStringReturn(ret *ast.ReturnStmt, locals, values map[string]string, results *[]returnedSQLString, context *sqlStringContext) {
	if len(ret.Results) == 0 || !returnHasNilError(ret) {
		return
	}
	expr := ret.Results[0]
	if tuple, ok := ast.Unparen(expr).(*ast.CallExpr); ok && isSprintf(tuple) {
		if value, ok := staticString(tuple, locals, values, context); ok {
			*results = append(*results, returnedSQLString{node: tuple, expression: value, predicateSource: true})
		} else if len(tuple.Args) > 0 {
			if format, ok := staticString(tuple.Args[0], locals, values, context); ok {
				*results = append(*results, returnedSQLString{node: tuple, expression: formatVerb.ReplaceAllLiteralString(format, "$9"), predicateSource: true})
			}
		}
		return
	}
	if value, ok := staticString(expr, locals, values, context); ok {
		*results = append(*results, returnedSQLString{node: expr, expression: value})
	}
}

func returnHasNilError(ret *ast.ReturnStmt) bool {
	if len(ret.Results) < 2 {
		return true
	}
	ident, ok := ast.Unparen(ret.Results[1]).(*ast.Ident)
	return ok && ident.Name == "nil"
}

func isSprintf(call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Sprintf"
}

func staticString(expr ast.Expr, locals, values map[string]string, contexts ...*sqlStringContext) (string, bool) {
	var context *sqlStringContext
	if len(contexts) > 0 {
		context = contexts[0]
	}
	switch x := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if value, ok := locals[x.Name]; ok {
			return value, true
		}
		return constString(x, values)
	case *ast.SelectorExpr:
		return constString(x, values)
	case *ast.BasicLit:
		return constString(x, values)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		a, ok := staticString(x.X, locals, values, context)
		if !ok {
			return "", false
		}
		b, ok := staticString(x.Y, locals, values, context)
		return a + b, ok
	case *ast.CallExpr:
		if isSprintf(x) && len(x.Args) > 0 {
			format, ok := staticString(x.Args[0], locals, values, context)
			if !ok {
				return "", false
			}
			args := make([]any, 0, len(x.Args)-1)
			verbs := formatVerb.FindAllString(format, -1)
			for i, arg := range x.Args[1:] {
				value, ok := staticString(arg, locals, values, context)
				if !ok {
					return "", false
				}
				if i < len(verbs) && strings.HasSuffix(verbs[i], "d") {
					format = strings.Replace(format, verbs[i], value, 1)
					continue
				}
				args = append(args, value)
			}
			return fmt.Sprintf(format, args...), true
		}
		if context != nil {
			return staticStringProjectCall(x, locals, values, context)
		}
	}
	return "", false
}

func staticStringProjectCall(call *ast.CallExpr, locals, values map[string]string, context *sqlStringContext) (string, bool) {
	callee, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok || context.functions[callee.Name] == nil || context.seen[callee.Name] {
		return "", false
	}
	fn := context.functions[callee.Name]
	bindings, ok := bindSQLStringArguments(call, fn, locals, values, context)
	if !ok {
		return "", false
	}
	context.seen[callee.Name] = true
	defer delete(context.seen, callee.Name)
	for _, returned := range returnedSQLStringsWithContext(fn, values, bindings, context) {
		if returned.expression != "" {
			return returned.expression, true
		}
	}
	return "", false
}

func bindSQLStringArguments(call *ast.CallExpr, fn *ast.FuncDecl, locals, values map[string]string, context *sqlStringContext) (map[string]string, bool) {
	bindings := make(map[string]string)
	argIndex := 0
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			for _, name := range field.Names {
				if argIndex >= len(call.Args) {
					return nil, false
				}
				value, ok := staticString(call.Args[argIndex], locals, values, context)
				if !ok {
					return nil, false
				}
				bindings[name.Name] = value
				argIndex++
			}
		}
	}
	if argIndex != len(call.Args) {
		return nil, false
	}
	return bindings, true
}

func isSQLArithmeticExpression(value string) bool {
	lower := strings.ToLower(value)
	return strings.ContainsAny(value, "+-*/") || strings.Contains(lower, "coalesce(")
}

var sqlAliasPrefix = regexp.MustCompile(`\b[a-z_][a-z0-9_]*\.`)
var sqlExpressionSpace = regexp.MustCompile(`\s+`)

func normalizeSQLExpression(value string) string {
	value = strings.ToLower(value)
	value = sqlAliasPrefix.ReplaceAllString(value, "")
	return sqlExpressionSpace.ReplaceAllString(value, "")
}

func indexPredicateConstants(r *SQLLiteralCopiesConstantRule, files []*core.FileContext) {
	for _, ctx := range files {
		if !patternkit.ProductionGoFile(ctx) {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST && gen.Tok != token.VAR {
				continue
			}
			for _, raw := range gen.Specs {
				indexValueSpec(r, ctx, raw, gen.Tok == token.CONST)
			}
		}
	}
}

func indexValueSpec(r *SQLLiteralCopiesConstantRule, ctx *core.FileContext, raw ast.Spec, isConst bool) {
	spec, ok := raw.(*ast.ValueSpec)
	if !ok {
		return
	}
	for i, name := range spec.Names {
		if i >= len(spec.Values) {
			continue
		}
		value, ok := constString(spec.Values[i], r.values)
		if !ok {
			continue
		}
		if !predicateName.MatchString(name.Name) {
			indexUUIDConstant(r, ctx, name.Name, spec.Values[i], value)
		}
		if isConst {
			value = strings.TrimSpace(value)
			if !thresholdInteger.MatchString(value) {
				continue
			}
			r.thresholds = append(r.thresholds, thresholdConstant{name: name.Name, value: value, path: ctx.RelPath, line: ctx.LineFor(spec.Values[i])})
		}
	}
}

func indexUUIDConstant(r *SQLLiteralCopiesConstantRule, ctx *core.FileContext, name string, expr ast.Expr, value string) {
	if len(value) != 36 || !uuidText.MatchString(value) {
		return
	}
	if _, seen := r.constants[value]; seen {
		return
	}
	r.constants[value] = fmt.Sprintf("%s (%s:%d)", name, ctx.RelPath, ctx.LineFor(expr))
}

func collectPredicateAtoms(name string, ctx *core.FileContext, at ast.Node, value string) map[string][]predicateConstant {
	result := make(map[string][]predicateConstant)
	fragment := strings.TrimSpace(value)
	for {
		stripped := predicatePrefix.ReplaceAllString(fragment, "")
		if stripped == fragment {
			break
		}
		fragment = strings.TrimSpace(stripped)
	}
	if predicateStatement.MatchString(fragment) {
		return result
	}
	line := ctx.LineFor(at)
	for _, conj := range sqlschema.ConditionConjuncts(fragment) {
		if !conj.HasLiteral || len(conj.Params) > 0 || nonAtomicPredicate(conj.Norm) {
			continue
		}
		norms := predicateEquivalentNorms(conj.Norm)
		atom := predicateConstant{name: name, path: ctx.RelPath, line: line, location: fmt.Sprintf("%s (%s:%d)", name, ctx.RelPath, line), expansionCount: len(norms)}
		for _, norm := range norms {
			result[norm] = append(result[norm], atom)
		}
	}
	return result
}

func predicateEquivalentNorms(norm string) []string {
	lists := sqlschema.InLists("SELECT 1 WHERE " + norm)
	if len(lists) != 1 || len(lists[0].Values) == 0 {
		return []string{norm}
	}
	list := lists[0]
	if !list.Negated && (list.Operator != "IN" || len(list.Values) != 1) {
		return []string{norm}
	}
	operator := "="
	if list.Negated {
		operator = "<>"
	}
	result := make([]string, 0, len(list.Values))
	for _, value := range list.Values {
		literal := value
		if strings.Contains(norm, "'"+strings.ReplaceAll(value, "'", "''")+"'") {
			literal = "'" + strings.ReplaceAll(value, "'", "''") + "'"
		}
		terms := sqlschema.ConditionConjuncts(list.Column + " " + operator + " " + literal)
		if len(terms) == 1 {
			result = append(result, terms[0].Norm)
		}
	}
	if len(result) == 0 {
		return []string{norm}
	}
	return result
}
func nonAtomicPredicate(norm string) bool {
	n := strings.ToLower(strings.TrimSpace(norm))
	return n == "true" || n == "false" || strings.Contains(n, " is null") || strings.Contains(n, " is not null")
}
func constString(expr ast.Expr, values map[string]string) (string, bool) {
	switch x := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			s, e := strconv.Unquote(x.Value)
			return s, e == nil
		}
		if x.Kind == token.INT || x.Kind == token.FLOAT {
			return x.Value, true
		}
	case *ast.Ident:
		s, ok := values[x.Name]
		return s, ok
	case *ast.SelectorExpr:
		s, ok := values[x.Sel.Name]
		return s, ok
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			a, ok := constString(x.X, values)
			if !ok {
				return "", false
			}
			b, ok := constString(x.Y, values)
			return a + b, ok
		}
	case *ast.CallExpr:
		if len(x.Args) > 0 {
			if sel, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Sprintf" && len(x.Args) == 1 {
				s, ok := constString(x.Args[0], values)
				if ok && !strings.Contains(s, "%") {
					return s, true
				}
			}
		}
	}
	return "", false
}

// ResetState drops the constants of the previous root.
func (r *SQLLiteralCopiesConstantRule) ResetState() {
	r.constants = nil
	r.predicates = nil
	r.values = nil
	r.expressions = nil
	r.thresholds = nil
}

// AnalyzeFile reports UUID and predicate copies in production SQL text.
func (r *SQLLiteralCopiesConstantRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !patternkit.ProductionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	seen := make(map[ast.Expr]bool)
	for _, literal := range patternkit.SqlLiterals(ctx.GoAST) {
		violations = append(violations, r.literalSourceFindings(ctx, literal)...)
	}
	for _, call := range patternkit.SqlCalls(ctx.GoAST) {
		violations = append(violations, r.analyzeSQLLiteral(ctx, call.Literal, call.Literal.Text, call.Call, seen)...)
	}
	for _, literal := range patternkit.SqlLiterals(ctx.GoAST) {
		text, ok := constString(literal.Expr, r.values)
		if !ok {
			text = literal.Text
		}
		violations = append(violations, r.analyzeSQLLiteral(ctx, literal, text, nil, seen)...)
	}
	return violations
}

func (r *SQLLiteralCopiesConstantRule) literalSourceFindings(ctx *core.FileContext, literal patternkit.SqlLiteral) []*core.Violation {
	var violations []*core.Violation
	queryExpression := normalizeSQLExpression(literal.Text)
	for _, expression := range slices.Sorted(maps.Keys(r.expressions)) {
		source := r.expressions[expression]
		if source.path == ctx.RelPath || expression == "" || !strings.Contains(queryExpression, expression) {
			continue
		}
		line := literal.LineAt(ctx, 0)
		if !ctx.IsSuppressed(line, r.Name()) {
			violations = append(violations, patternkit.SqlViolation(r.BaseRule, ctx, line,
				"SQL text copies the arithmetic expression from "+source.location,
				"Use the SQL expression source"))
		}
	}
	for _, loc := range uuidText.FindAllStringIndex(literal.Text, -1) {
		constant, ok := r.constants[literal.Text[loc[0]:loc[1]]]
		if !ok {
			continue
		}
		line := literal.LineAt(ctx, loc[0])
		if !ctx.IsSuppressed(line, r.Name()) {
			violations = append(violations, patternkit.SqlViolation(r.BaseRule, ctx, line, "SQL text copies the value of the constant "+constant+" — the query keeps its own copy, which stays behind when the constant changes", "Pass the constant as a query parameter (user_id <> ALL($1) with the list of constants)"))
		}
	}
	return violations
}

func (r *SQLLiteralCopiesConstantRule) analyzeSQLLiteral(ctx *core.FileContext, literal patternkit.SqlLiteral, text string, call *ast.CallExpr, seen map[ast.Expr]bool) []*core.Violation {
	if seen[literal.Expr] {
		return nil
	}
	seen[literal.Expr] = true
	guardedOperators := make(map[string]bool)
	for _, original := range sqlschema.Conjuncts(text) {
		if original.GuardedByKey && (original.Operator == "UPDATE" || original.Operator == "DELETE") {
			guardedOperators[original.Operator] = true
		}
	}
	if literal.Bare != "" {
		text = parseableBareSQL(literal)
	}
	if call != nil {
		text = bindConstArguments(text, call, literal, r.values)
	}
	var violations []*core.Violation
	for _, conj := range sqlschema.Conjuncts(text) {
		violations = append(violations, r.thresholdFindings(ctx, literal, conj)...)
		if guardedOperators[conj.Operator] || conj.GuardedByKey && (conj.Operator == "UPDATE" || conj.Operator == "DELETE") {
			continue
		}
		violations = append(violations, r.predicateFindings(ctx, literal, conj)...)
	}
	return violations
}

func (r *SQLLiteralCopiesConstantRule) thresholdFindings(ctx *core.FileContext, literal patternkit.SqlLiteral, conj sqlschema.Conjunct) []*core.Violation {
	threshold, ok := matchingThreshold(r.thresholds, conj.Norm, ctx.RelPath)
	if !ok {
		return nil
	}
	line := literal.LineAt(ctx, conj.Offset)
	if ctx.IsSuppressed(line, r.Name()) {
		return nil
	}
	message := "SQL threshold repeats the value of the constant " + threshold.name + " (" + threshold.path + ":" + strconv.Itoa(threshold.line) + ")"
	return []*core.Violation{patternkit.SqlViolation(r.BaseRule, ctx, line, message, "Pass the threshold as a query parameter")}
}

func (r *SQLLiteralCopiesConstantRule) predicateFindings(ctx *core.FileContext, literal patternkit.SqlLiteral, conj sqlschema.Conjunct) []*core.Violation {
	keys := predicateEquivalentNorms(conj.Norm)
	matches := make([]predicateConstant, 0, len(keys))
	matchedLocations := make(map[string]bool)
	for _, key := range keys {
		entry, ok := matchingPredicate(r.predicates[key], literal.Expr, conj.Offset, ctx, r.values, len(keys) > 1)
		if !ok {
			return nil
		}
		if !matchedLocations[entry.location] {
			matches = append(matches, entry)
			matchedLocations[entry.location] = true
		}
	}
	if len(matches) == 0 {
		return nil
	}
	line := literal.LineAt(ctx, conj.Offset)
	if ctx.IsSuppressed(line, r.Name()) {
		return nil
	}
	locations := make([]string, len(matches))
	for i, entry := range matches {
		locations[i] = entry.location
	}
	location := strings.Join(locations, " and ")
	message := "SQL text repeats the condition of the constant " + location + " — use the constant"
	suggestion := "Use the predicate constant in this query"
	for _, entry := range matches {
		if containsNamedPredicate(literal.Expr, entry.name) {
			message = "the condition is already in the constant " + location + " — drop the copy"
			suggestion = "Remove the repeated condition from the SQL text"
			break
		}
	}
	return []*core.Violation{patternkit.SqlViolation(r.BaseRule, ctx, line, message, suggestion)}
}

var thresholdInteger = regexp.MustCompile(`^-?[0-9]+$`)
var thresholdComparison = regexp.MustCompile(`(?i)^([a-z_][a-z0-9_.]*)\s*(?:<=|>=|<>|!=|=|<|>)\s*(-?[0-9]+)$`)

func matchingThreshold(entries []thresholdConstant, condition, queryPath string) (thresholdConstant, bool) {
	match := thresholdComparison.FindStringSubmatch(strings.TrimSpace(condition))
	if len(match) != 3 {
		return thresholdConstant{}, false
	}
	column := strings.ToLower(match[1])
	column = column[strings.LastIndex(column, ".")+1:]
	for _, entry := range entries {
		if entry.path != queryPath && entry.value == match[2] && thresholdNameContainsColumn(entry.name, column) {
			return entry, true
		}
	}
	return thresholdConstant{}, false
}

func thresholdNameContainsColumn(name, column string) bool {
	if column == "" {
		return false
	}
	return slices.Contains(patternkit.IdentifierWords(name), strings.ToLower(column))
}

func matchingPredicate(entries []predicateConstant, expr ast.Expr, offset int, ctx *core.FileContext, values map[string]string, listExpansion bool) (predicateConstant, bool) {
	var fallback predicateConstant
	foundFallback := false
	for _, entry := range entries {
		if entry.path == ctx.RelPath || entry.expansionCount > 1 && !listExpansion || predicateContribution(expr, entry.name, offset, values, 0) {
			continue
		}
		if !foundFallback {
			fallback = entry
			foundFallback = true
		}
		if containsNamedPredicate(expr, entry.name) {
			return entry, true
		}
	}
	return fallback, foundFallback
}

func parseableBareSQL(literal patternkit.SqlLiteral) string {
	text := literal.Bare
	if match := trailingBooleanOperator.FindStringIndex(text); match != nil {
		text = text[:match[0]] + strings.Repeat(" ", match[1]-match[0]) + text[match[1]:]
	}
	return text
}

func containsNamedPredicate(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == name {
			found = true
		}
		return !found
	})
	return found
}

func predicateContribution(expr ast.Expr, name string, offset int, values map[string]string, base int) bool {
	expr = ast.Unparen(expr)
	switch x := expr.(type) {
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			left, ok := constString(x.X, values)
			if !ok {
				return false
			}
			return predicateContribution(x.X, name, offset, values, base) ||
				predicateContribution(x.Y, name, offset, values, base+len(left))
		}
	case *ast.Ident:
		return x.Name == name && offset >= base && offset < base+len(values[x.Name])
	case *ast.SelectorExpr:
		return x.Sel.Name == name && offset >= base && offset < base+len(values[x.Sel.Name])
	}
	return false
}

func bindConstArguments(text string, call *ast.CallExpr, literal patternkit.SqlLiteral, values map[string]string) string {
	queryArg := -1
	for i, arg := range call.Args {
		if patternkit.DeclaredValue(arg) == literal.Expr {
			queryArg = i
			break
		}
	}
	if queryArg < 0 {
		return text
	}
	args := call.Args[queryArg+1:]
	return sqlParam.ReplaceAllStringFunc(text, func(param string) string {
		index, ok := sqlParamArgumentIndex(param, len(args))
		if !ok {
			return param
		}
		value, ok := constString(args[index], values)
		if !ok {
			return param
		}
		return sqlConst(value)
	})
}

func sqlParamArgumentIndex(param string, argumentCount int) (int, bool) {
	if len(param) < 2 || argumentCount == 0 {
		return 0, false
	}
	number := 0
	for _, char := range param[1:] {
		digit := int(char - '0')
		if number > argumentCount/10 || number == argumentCount/10 && digit > argumentCount%10 {
			return 0, false
		}
		number = number*10 + digit
	}
	if number == 0 {
		return 0, false
	}
	return number - 1, true
}

func sqlConst(value string) string {
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
