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
// fallback-return misses the shape because nothing is returned. The value must
// be validated where the configuration loads, and its default declared there.
//
// Reported: an if without else whose condition tests a configuration field —
// or a variable initialised from one — for its zero value (== 0, <= 0, < 0,
// == "", == nil, .IsZero()) and whose body only assigns a constant, or a
// constructor call over constants, to that same field or variable.
type ConfigValueFallbackRule struct {
	*rules.BaseRule
}

// NewConfigValueFallbackRule creates the rule
func NewConfigValueFallbackRule() *ConfigValueFallbackRule {
	return &ConfigValueFallbackRule{
		BaseRule: rules.NewBaseRule(
			"config-value-fallback",
			"patterns",
			"Detects a configuration value replaced by a hardcoded literal when unset — a second default the configuration does not know about",
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
	return rules.AnalyzeTypedFiles(ctx, r.Name(), r.analyze)
}

// configSource is the configuration field a value was read from.
type configSource struct {
	field *types.Var
	tag   reflect.StructTag
	path  string
}

func (r *ConfigValueFallbackRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	var violations []*core.Violation
	// Variables initialised from a configuration field, anywhere in the file:
	// objects are unique, so one map serves every function.
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
		case *ast.IfStmt:
			if v := r.checkIf(ctx, info, derived, node); v != nil {
				violations = append(violations, v)
			}
		}
		return true
	})
	return violations
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

	message := fmt.Sprintf("Configuration value %s is replaced with %s when unset — a hardcoded second default the configuration does not know about",
		source.path, types.ExprString(replacement))
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

// zeroTested returns the expression a condition tests for its zero value.
func zeroTested(info *types.Info, cond ast.Expr) (ast.Expr, bool) {
	switch c := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		if c.Op != token.EQL && c.Op != token.LEQ && c.Op != token.LSS {
			return nil, false
		}
		if isZeroConstant(info, c.Y) {
			return ast.Unparen(c.X), true
		}
	case *ast.CallExpr:
		sel, ok := ast.Unparen(c.Fun).(*ast.SelectorExpr)
		if ok && sel.Sel.Name == "IsZero" && len(c.Args) == 0 {
			return ast.Unparen(sel.X), true
		}
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
