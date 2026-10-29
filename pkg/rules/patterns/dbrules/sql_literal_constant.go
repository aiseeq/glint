package dbrules

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
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
// reported as redundant. Not findings: the file of the constant, full queries
// as the source of conditions, a guard of a single-row UPDATE or DELETE
// (WHERE id = $N), test files. When the constant changes, the copy stays
// behind: pass the constant as a parameter or use the predicate constant.
type SQLLiteralCopiesConstantRule struct {
	*rules.BaseRule
	constants  map[string]string
	predicates map[string][]predicateConstant
	values     map[string]string
}
type predicateConstant struct {
	name, location, path string
	line                 int
	expansionCount       int
}

// NewSQLLiteralCopiesConstantRule creates the rule.
func NewSQLLiteralCopiesConstantRule() *SQLLiteralCopiesConstantRule {
	return &SQLLiteralCopiesConstantRule{BaseRule: rules.NewBaseRule(
		"sql-literal-copies-constant", "patterns",
		"Detects UUIDs or conditions repeated in SQL when a Go constant already holds them",
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
	r.values = collectGoConstantValues(files)
	indexPredicateFunctions(r, files)
	indexPredicateConstants(r, files)
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
			for _, call := range returnedSprintfCalls(fn.Body) {
				format, ok := constString(call.Args[0], r.values)
				if !ok {
					continue
				}
				format = formatVerb.ReplaceAllLiteralString(format, "$9")
				addPredicateAtoms(r, fn.Name.Name, ctx, call, format)
			}
		}
	}
}

func returnedSprintfCalls(body *ast.BlockStmt) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(node ast.Node) bool {
		ret, ok := node.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		call, ok := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "Sprintf" {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

func indexPredicateConstants(r *SQLLiteralCopiesConstantRule, files []*core.FileContext) {
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
				indexValueSpec(r, ctx, raw)
			}
		}
	}
}

func indexValueSpec(r *SQLLiteralCopiesConstantRule, ctx *core.FileContext, raw ast.Spec) {
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
		if predicateName.MatchString(name.Name) {
			addPredicateAtoms(r, name.Name, ctx, spec.Values[i], value)
			continue
		}
		indexUUIDConstant(r, ctx, name.Name, spec.Values[i], value)
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

func addPredicateAtoms(r *SQLLiteralCopiesConstantRule, name string, ctx *core.FileContext, at ast.Node, value string) {
	fragment := strings.TrimSpace(value)
	for {
		stripped := predicatePrefix.ReplaceAllString(fragment, "")
		if stripped == fragment {
			break
		}
		fragment = strings.TrimSpace(stripped)
	}
	if predicateStatement.MatchString(fragment) {
		return
	}
	line := ctx.LineFor(at)
	for _, conj := range sqlschema.ConditionConjuncts(fragment) {
		if !conj.HasLiteral || len(conj.Params) > 0 || nonAtomicPredicate(conj.Norm) {
			continue
		}
		norms := predicateEquivalentNorms(conj.Norm)
		atom := predicateConstant{name: name, path: ctx.RelPath, line: line, location: fmt.Sprintf("%s (%s:%d)", name, ctx.RelPath, line), expansionCount: len(norms)}
		for _, norm := range norms {
			r.predicates[norm] = append(r.predicates[norm], atom)
		}
	}
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
}

// AnalyzeFile reports UUID and predicate copies in production SQL text.
func (r *SQLLiteralCopiesConstantRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !patternkit.ProductionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, literal := range patternkit.SqlLiterals(ctx.GoAST) {
		for _, loc := range uuidText.FindAllStringIndex(literal.Text, -1) {
			constant, ok := r.constants[literal.Text[loc[0]:loc[1]]]
			if !ok {
				continue
			}
			line := literal.LineAt(ctx, loc[0])
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, patternkit.SqlViolation(r.BaseRule, ctx, line, "SQL text copies the value of the constant "+constant+" — the query keeps its own copy, which stays behind when the constant changes", "Pass the constant as a query parameter (user_id <> ALL($1) with the list of constants)"))
		}
	}
	seen := make(map[ast.Expr]bool)
	check := func(literal patternkit.SqlLiteral, text string, call *ast.CallExpr) {
		if seen[literal.Expr] {
			return
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
		for _, conj := range sqlschema.Conjuncts(text) {
			if guardedOperators[conj.Operator] || conj.GuardedByKey && (conj.Operator == "UPDATE" || conj.Operator == "DELETE") {
				continue
			}
			keys := predicateEquivalentNorms(conj.Norm)
			matches := make([]predicateConstant, 0, len(keys))
			matchedLocations := make(map[string]bool)
			allMatched := true
			for _, key := range keys {
				entry, ok := matchingPredicate(r.predicates[key], literal.Expr, conj.Offset, ctx, r.values, len(keys) > 1)
				if !ok {
					allMatched = false
					break
				}
				if !matchedLocations[entry.location] {
					matches = append(matches, entry)
					matchedLocations[entry.location] = true
				}
			}
			if !allMatched || len(matches) == 0 {
				continue
			}
			line := literal.LineAt(ctx, conj.Offset)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
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
			violations = append(violations, patternkit.SqlViolation(r.BaseRule, ctx, line, message, suggestion))
		}
	}
	for _, call := range patternkit.SqlCalls(ctx.GoAST) {
		check(call.Literal, call.Literal.Text, call.Call)
	}
	for _, literal := range patternkit.SqlLiterals(ctx.GoAST) {
		text, ok := constString(literal.Expr, r.values)
		if !ok {
			text = literal.Text
		}
		check(literal, text, nil)
	}
	return violations
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
