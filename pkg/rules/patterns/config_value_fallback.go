package patterns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewConfigValueFallbackRule())
}

// configFieldTags mark a struct field as a configuration value: whoever runs
// the program writes it and expects it to take effect. json is left out, it
// marks payloads as often as configuration.
var configFieldTags = []string{"yaml", "toml", "mapstructure", "env", "ini", "koanf", "envconfig"}

// ConfigValueFallbackRule detects a configuration value quietly replaced by a
// literal when it is unset:
//
//	days := cfg.Report.WindowDays
//	if days <= 0 {
//	    days = 14
//	}
//
// The literal is a second default the configuration does not know about: the
// operator sets 0 to switch something off and gets 14, the configuration's own
// default drifts from the code's, and a broken config file is never noticed.
// fallback-return misses the shape because no error is involved. The value must
// be validated where the configuration loads, and its default declared there.
//
// Reported, for a configuration field or a variable initialised from one:
//   - assignment: an if without else whose condition tests the value for zero
//     (== 0, <= 0, < 0, == "", == nil, .IsZero()) and whose body only assigns
//     a constant, or a constructor call over constants, to that same value;
//   - return: `if <zero> { return <constant> }`, or `if <set> { return
//     <value> }` (!= 0, > 0, != "", != nil, !.IsZero()) followed by, or with an
//     else of, `return <constant>` — the constant non-zero, of the value's own
//     type, any error result nil; a zero value or an error is validation.
//     Not reported when the program tests the field for zero inside a larger
//     condition elsewhere (x.f != "" && !x.Args): the unset state carries
//     meaning, and the default cannot move into the field.
//
// The package that declares the configuration is skipped for the assignment
// only: an applyDefaults there writes the default into the field, while a
// getter returning a literal leaves the loaded configuration empty.
type ConfigValueFallbackRule struct {
	*rules.BaseRule
}

// NewConfigValueFallbackRule creates the rule
func NewConfigValueFallbackRule() *ConfigValueFallbackRule {
	return &ConfigValueFallbackRule{
		BaseRule: rules.NewBaseRule(
			"config-value-fallback",
			"patterns",
			"Detects a configuration value replaced by, or a getter falling back to, a hardcoded literal when unset — a second default the configuration does not know about",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: telling a configuration field apart needs types.
func (r *ConfigValueFallbackRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ConfigValueFallbackRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every typed production file.
func (r *ConfigValueFallbackRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	tests := collectUnsetTests(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, tests)
	})
}

// unsetTests records the configuration fields (by declaration position)
// whose unset state takes part in the program's logic beyond a default: a
// zero or non-zero test combined with other conditions, stored, or passed on
// (x.f != "" && !x.Args). A test that is the whole condition of an if is a
// default or a validation and is not recorded.
type unsetTests map[token.Pos]bool

func collectUnsetTests(ctx *core.GoProjectContext) unsetTests {
	tests := make(unsetTests)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Package.Syntax {
			// Inspect visits an if before its condition.
			whole := make(map[ast.Expr]bool)
			ast.Inspect(file, func(n ast.Node) bool {
				var operand ast.Expr
				switch node := n.(type) {
				case *ast.IfStmt:
					cond := ast.Unparen(node.Cond)
					whole[cond] = true
					if not, ok := cond.(*ast.UnaryExpr); ok && not.Op == token.NOT {
						whole[ast.Unparen(not.X)] = true
					}
				case *ast.BinaryExpr:
					if !whole[node] {
						operand, _, _ = comparedWithZero(info, node)
					}
				case *ast.CallExpr:
					if !whole[node] {
						operand, _ = isZeroCall(node)
					}
				}
				if sel, ok := operand.(*ast.SelectorExpr); ok {
					if source, ok := configField(info, sel); ok {
						tests[source.field.Origin().Pos()] = true
					}
				}
				return true
			})
		}
	}
	return tests
}

// usedInLogic reports whether the field's unset state takes part in the
// program's logic: then the default cannot be written into the field without
// losing that state, and a getter is where it belongs.
func (t unsetTests) usedInLogic(field *types.Var) bool {
	return t[field.Origin().Pos()]
}

// configSource is the configuration field a value was read from.
type configSource struct {
	field *types.Var
	tag   reflect.StructTag
	path  string
}

func (r *ConfigValueFallbackRule) analyze(ctx *core.FileContext, info *types.Info, tests unsetTests) []*core.Violation {
	// Variables initialised from a configuration field, anywhere in the file:
	// objects are unique, so one map serves every function. Collected first,
	// so an if sees the variables declared before it in any shape.
	derived := make(map[types.Object]configSource)
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE && len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					r.recordDerived(info, derived, lhs, node.Rhs[i])
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) == len(node.Values) {
				for i, name := range node.Names {
					r.recordDerived(info, derived, name, node.Values[i])
				}
			}
		}
		return true
	})

	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			if v := r.checkIf(ctx, info, derived, node); v != nil {
				violations = append(violations, v)
			}
		case *ast.FuncDecl:
			if fn, ok := info.Defs[node.Name].(*types.Func); ok && node.Body != nil {
				if sig, ok := fn.Type().(*types.Signature); ok {
					violations = append(violations, r.checkReturns(ctx, info, derived, tests, sig, node.Body)...)
				}
			}
		case *ast.FuncLit:
			if sig, ok := info.TypeOf(node).(*types.Signature); ok {
				violations = append(violations, r.checkReturns(ctx, info, derived, tests, sig, node.Body)...)
			}
		}
		return true
	})
	return violations
}

// checkReturns walks the statement lists of one function body, leaving nested
// function literals to their own visit, and checks every if together with the
// statement that follows it.
func (r *ConfigValueFallbackRule) checkReturns(ctx *core.FileContext, info *types.Info, derived map[types.Object]configSource, tests unsetTests, sig *types.Signature, body *ast.BlockStmt) []*core.Violation {
	if sig.Results().Len() == 0 {
		return nil
	}
	var violations []*core.Violation
	checkList := func(list []ast.Stmt) {
		for i, stmt := range list {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				continue
			}
			var next ast.Stmt
			if i+1 < len(list) {
				next = list[i+1]
			}
			if v := r.checkReturnIf(ctx, info, derived, tests, sig, ifStmt, next); v != nil {
				violations = append(violations, v)
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.BlockStmt:
			checkList(node.List)
		case *ast.CaseClause:
			checkList(node.Body)
		case *ast.CommClause:
			checkList(node.Body)
		}
		return true
	})
	return violations
}

// checkReturnIf reports a configuration value replaced by a returned literal:
//
//	if <value is zero> { return <constant> }
//	if <value is set> { return <value> }; return <constant>
//	if <value is set> { return <value> } else { return <constant> }
//
// The function must return the value's own type, error results must be nil,
// and the constant must not be a zero value: returning 0 or "" with an error
// is validation, not a default.
func (r *ConfigValueFallbackRule) checkReturnIf(ctx *core.FileContext, info *types.Info, derived map[types.Object]configSource, tests unsetTests, sig *types.Signature, ifStmt *ast.IfStmt, next ast.Stmt) *core.Violation {
	if target, ok := zeroTested(info, ifStmt.Cond); ok {
		replacement, ok := returnedFallback(info, sig, soleReturn(ifStmt.Body), target)
		if !ok {
			return nil
		}
		source, ok := r.sourceOf(info, derived, target)
		if !ok || tests.usedInLogic(source.field) {
			return nil
		}
		return r.report(ctx, ifStmt, source, replacement, "falls back to")
	}

	target, ok := nonZeroTested(info, ifStmt.Cond)
	if !ok {
		return nil
	}
	kept, _, ok := returnedValue(info, sig, soleReturn(ifStmt.Body))
	if !ok || !sameTarget(info, kept, target) {
		return nil
	}
	fallback := next
	if ifStmt.Else != nil {
		block, ok := ifStmt.Else.(*ast.BlockStmt)
		if !ok {
			return nil
		}
		fallback = soleReturn(block)
	}
	ret, ok := fallback.(*ast.ReturnStmt)
	if !ok {
		return nil
	}
	replacement, ok := returnedFallback(info, sig, ret, target)
	if !ok {
		return nil
	}
	source, ok := r.sourceOf(info, derived, target)
	if !ok || tests.usedInLogic(source.field) {
		return nil
	}
	return r.report(ctx, ifStmt, source, replacement, "falls back to")
}

// soleReturn returns the return statement a block consists of, or nil.
func soleReturn(block *ast.BlockStmt) *ast.ReturnStmt {
	if block == nil || len(block.List) != 1 {
		return nil
	}
	ret, ok := block.List[0].(*ast.ReturnStmt)
	if !ok {
		return nil
	}
	return ret
}

// returnedValue returns the one non-error result of a return statement whose
// error results are all nil, with the type of its result slot.
func returnedValue(info *types.Info, sig *types.Signature, ret *ast.ReturnStmt) (ast.Expr, types.Type, bool) {
	if ret == nil || len(ret.Results) != sig.Results().Len() {
		return nil, nil, false
	}
	var value ast.Expr
	var slot types.Type
	for i, result := range ret.Results {
		resultType := sig.Results().At(i).Type()
		if implementsError(resultType) {
			if tv, ok := info.Types[result]; !ok || !tv.IsNil() {
				return nil, nil, false
			}
			continue
		}
		if value != nil {
			return nil, nil, false
		}
		value, slot = result, resultType
	}
	return value, slot, value != nil
}

// returnedFallback returns the constant a return statement hands out in place
// of the tested value: a non-zero constant, or a constructor over constants,
// in a result of the value's own type.
func returnedFallback(info *types.Info, sig *types.Signature, ret *ast.ReturnStmt, target ast.Expr) (ast.Expr, bool) {
	value, slot, ok := returnedValue(info, sig, ret)
	if !ok || !isConstantValue(info, value) || isZeroValue(info, value) {
		return nil, false
	}
	targetType := info.TypeOf(target)
	if targetType == nil || !types.Identical(slot, targetType) {
		return nil, false
	}
	return value, true
}

// isZeroValue reports a zero constant, or a constructor whose arguments are
// all zero constants (decimal.NewFromInt(0)).
func isZeroValue(info *types.Info, expr ast.Expr) bool {
	if isZeroConstant(info, expr) {
		return true
	}
	if tv, ok := info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.Bool {
		return !constant.BoolVal(tv.Value)
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	for _, arg := range call.Args {
		if !isZeroConstant(info, arg) {
			return false
		}
	}
	return true
}

// implementsError reports whether a result slot carries an error.
func implementsError(t types.Type) bool {
	return types.AssignableTo(t, types.Universe.Lookup("error").Type())
}

func (r *ConfigValueFallbackRule) recordDerived(info *types.Info, derived map[types.Object]configSource, lhs, rhs ast.Expr) {
	ident, ok := lhs.(*ast.Ident)
	if !ok {
		return
	}
	obj := info.Defs[ident]
	if obj == nil {
		return
	}
	if source, ok := configFieldIn(info, rhs); ok {
		derived[obj] = source
	}
}

// configFieldIn returns the configuration field an initialiser reads: the
// field itself, or the single argument of a conversion or constructor over it
// (decimal.NewFromFloat(cfg.Threshold), time.Duration(cfg.Seconds)).
func configFieldIn(info *types.Info, expr ast.Expr) (configSource, bool) {
	expr = ast.Unparen(expr)
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 1 {
		expr = ast.Unparen(call.Args[0])
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return configSource{}, false
	}
	return configField(info, sel)
}

// configField resolves a selector to a struct field carrying a configuration
// tag.
func configField(info *types.Info, sel *ast.SelectorExpr) (configSource, bool) {
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.FieldVal {
		return configSource{}, false
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok {
		return configSource{}, false
	}
	st, ok := derefStruct(selection.Recv())
	if !ok {
		return configSource{}, false
	}
	// Embedded fields resolve through the index path; the tag lives on the
	// struct that declares the field.
	indices := selection.Index()
	for _, index := range indices[:len(indices)-1] {
		st, ok = derefStruct(st.Field(index).Type())
		if !ok {
			return configSource{}, false
		}
	}
	tag := reflect.StructTag(st.Tag(indices[len(indices)-1]))
	for _, name := range configFieldTags {
		if _, found := tag.Lookup(name); found {
			return configSource{field: field, tag: tag, path: types.ExprString(sel)}, true
		}
	}
	return configSource{}, false
}

func derefStruct(t types.Type) (*types.Struct, bool) {
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	return st, ok
}

// checkIf reports `if <config value is zero> { <config value> = <constant> }`.
func (r *ConfigValueFallbackRule) checkIf(ctx *core.FileContext, info *types.Info, derived map[types.Object]configSource, ifStmt *ast.IfStmt) *core.Violation {
	if ifStmt.Else != nil || len(ifStmt.Body.List) == 0 {
		return nil
	}
	target, ok := zeroTested(info, ifStmt.Cond)
	if !ok {
		return nil
	}
	source, ok := r.sourceOf(info, derived, target)
	if !ok {
		return nil
	}
	// The package that declares the configuration is where its defaults
	// belong: applyDefaults() filling an unset field is the fix, not the bug.
	if fileScope := info.Scopes[ctx.GoAST]; fileScope != nil && source.field.Pkg() != nil &&
		source.field.Pkg().Scope() == fileScope.Parent() {
		return nil
	}
	var replacement ast.Expr
	for _, stmt := range ifStmt.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return nil
		}
		if !sameTarget(info, assign.Lhs[0], target) || !isConstantValue(info, assign.Rhs[0]) {
			return nil
		}
		replacement = assign.Rhs[0]
	}

	return r.report(ctx, ifStmt, source, replacement, "is replaced with")
}

// report builds the finding; how names the shape: "is replaced with" for an
// assignment, "falls back to" for a returned literal.
func (r *ConfigValueFallbackRule) report(ctx *core.FileContext, ifStmt *ast.IfStmt, source configSource, replacement ast.Expr, how string) *core.Violation {
	message := fmt.Sprintf("Configuration value %s %s %s when unset — a hardcoded second default the configuration does not know about",
		source.path, how, types.ExprString(replacement))
	if def, found := source.tag.Lookup("default"); found {
		message += fmt.Sprintf(" (the field already declares default:%q)", def)
	}
	v := r.CreateViolation(ctx.RelPath, ctx.LineFor(ifStmt), message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(ctx.LineFor(ifStmt))))
	v.WithSuggestion("Validate the value where the configuration loads and fail on an invalid one; declare the default in the configuration, not at the use site")
	v.WithContext("config_field", source.path)
	return v
}

// sourceOf returns the configuration field behind the tested expression: the
// field itself, or the variable initialised from one.
func (r *ConfigValueFallbackRule) sourceOf(info *types.Info, derived map[types.Object]configSource, target ast.Expr) (configSource, bool) {
	switch t := target.(type) {
	case *ast.Ident:
		source, ok := derived[info.Uses[t]]
		return source, ok
	case *ast.SelectorExpr:
		return configField(info, t)
	}
	return configSource{}, false
}

// zeroTested returns the expression a condition tests for its zero value:
// == 0, <= 0, < 0, == "", == nil, .IsZero().
func zeroTested(info *types.Info, cond ast.Expr) (ast.Expr, bool) {
	switch c := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		x, op, ok := comparedWithZero(info, c)
		if ok && (op == token.EQL || op == token.LEQ || op == token.LSS) {
			return x, true
		}
	case *ast.CallExpr:
		if x, ok := isZeroCall(c); ok {
			return x, true
		}
	}
	return nil, false
}

// nonZeroTested returns the expression a condition tests for being set:
// != 0, > 0, != "", != nil, !x.IsZero().
func nonZeroTested(info *types.Info, cond ast.Expr) (ast.Expr, bool) {
	switch c := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		x, op, ok := comparedWithZero(info, c)
		if ok && (op == token.NEQ || op == token.GTR) {
			return x, true
		}
	case *ast.UnaryExpr:
		if call, ok := ast.Unparen(c.X).(*ast.CallExpr); ok && c.Op == token.NOT {
			return isZeroCall(call)
		}
	}
	return nil, false
}

// comparedWithZero returns the operand a comparison sets against a zero
// constant and the operator read with that operand on the left: 0 < x is
// x > 0.
func comparedWithZero(info *types.Info, c *ast.BinaryExpr) (ast.Expr, token.Token, bool) {
	if isZeroConstant(info, c.Y) {
		return ast.Unparen(c.X), c.Op, true
	}
	if !isZeroConstant(info, c.X) {
		return nil, token.ILLEGAL, false
	}
	mirrored := map[token.Token]token.Token{
		token.EQL: token.EQL, token.NEQ: token.NEQ,
		token.LSS: token.GTR, token.GTR: token.LSS,
		token.LEQ: token.GEQ, token.GEQ: token.LEQ,
	}
	op, ok := mirrored[c.Op]
	return ast.Unparen(c.Y), op, ok
}

// isZeroCall returns the receiver of x.IsZero().
func isZeroCall(call *ast.CallExpr) (ast.Expr, bool) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if ok && sel.Sel.Name == "IsZero" && len(call.Args) == 0 {
		return ast.Unparen(sel.X), true
	}
	return nil, false
}

func isZeroConstant(info *types.Info, expr ast.Expr) bool {
	tv, ok := info.Types[expr]
	if !ok {
		return false
	}
	if tv.IsNil() {
		return true
	}
	if tv.Value == nil {
		return false
	}
	switch tv.Value.Kind() {
	case constant.Int, constant.Float:
		return constant.Sign(tv.Value) == 0
	case constant.String:
		return constant.StringVal(tv.Value) == ""
	}
	return false
}

// sameTarget reports whether the assignment writes the tested expression.
func sameTarget(info *types.Info, lhs, target ast.Expr) bool {
	lhs = ast.Unparen(lhs)
	switch t := target.(type) {
	case *ast.Ident:
		l, ok := lhs.(*ast.Ident)
		return ok && info.Uses[l] != nil && info.Uses[l] == info.Uses[t]
	case *ast.SelectorExpr:
		return types.ExprString(lhs) == types.ExprString(t)
	}
	return false
}

// isConstantValue reports whether the expression is a constant, or a call
// whose arguments are all constants (decimal.NewFromFloat(-1.0)).
func isConstantValue(info *types.Info, expr ast.Expr) bool {
	if tv, ok := info.Types[expr]; ok && tv.Value != nil {
		return true
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		// A method call on a value reads that value: not a constant.
		if selection, isMethod := info.Selections[sel]; isMethod && selection.Kind() == types.MethodVal {
			return false
		}
	}
	for _, arg := range call.Args {
		if argValue, ok := info.Types[arg]; !ok || argValue.Value == nil {
			return false
		}
	}
	return true
}
