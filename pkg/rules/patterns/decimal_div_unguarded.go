package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDecimalDivUnguardedRule())
}

// DecimalDivUnguardedRule detects a decimal division by a value nothing
// checked for zero:
//
//	growth := last.Value.Sub(first.Value).Div(first.Value)
//
// decimal.Decimal.Div panics on a zero divisor ("decimal division by 0"):
// one snapshot with a zero value takes down the request, or the whole
// worker. A divisor is safe when the function compares it before dividing
// — IsZero, Sign, Equal, GreaterThan, a comparison of the integer it was
// built from — or when it cannot be zero: a decimal built from non-zero
// constants or a power of ten, a variable, a field or a function result that
// only ever holds one, a package-level value.
//
// The check is lexical, not path-sensitive: a comparison anywhere before the
// division counts, whichever branch it guards. The rule would rather miss a
// check on the wrong branch than report a division a reader sees is guarded.
// A function named for division (floorDiv, a wrapper's Div) that divides by
// its own parameter hands the zero case to its caller, as decimal does.
type DecimalDivUnguardedRule struct {
	*rules.BaseRule
}

// NewDecimalDivUnguardedRule creates the rule
func NewDecimalDivUnguardedRule() *DecimalDivUnguardedRule {
	return &DecimalDivUnguardedRule{BaseRule: rules.NewBaseRule(
		"decimal-div-unguarded",
		"patterns",
		"Detects decimal.Decimal Div/DivRound/Mod/QuoRem by a value the function never checked for zero — decimal panics on division by zero",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the method must be decimal's.
func (r *DecimalDivUnguardedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DecimalDivUnguardedRule) RequiresSSA() bool { return false }

// decimalDivisions are the decimal methods that panic on a zero argument.
var decimalDivisions = map[string]bool{"Div": true, "DivRound": true, "Mod": true, "QuoRem": true}

// decimalGuards are the decimal methods that compare a value with zero or
// with another value.
var decimalGuards = map[string]bool{
	"IsZero": true, "Sign": true, "Equal": true, "Equals": true, "Cmp": true, "Compare": true,
	"GreaterThan": true, "GreaterThanOrEqual": true, "LessThan": true, "LessThanOrEqual": true,
	"IsPositive": true, "IsNegative": true,
}

// AnalyzeGoProject reports the unguarded decimal divisions of every function.
func (r *DecimalDivUnguardedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	index := indexDivisors(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			site := divisorSite{index: index, fn: fn, info: info}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 || !decimalDivision(info, call) {
					return true
				}
				divisor := call.Args[0]
				if site.nonZero(divisor, 3) || site.divisionHelperParam(divisor) || divisorChecked(fn, info, divisor, call) {
					return true
				}
				line := file.LineFor(call)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line, "Decimal division by "+types.ExprString(divisor)+", which nothing before it checks for zero — decimal panics on a zero divisor")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Check the divisor first (if d.IsZero() { return …, error }) and decide what a zero means here")
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

// decimalDivision reports a call of decimal.Decimal's Div, DivRound, Mod or
// QuoRem.
func decimalDivision(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !decimalDivisions[sel.Sel.Name] {
		return false
	}
	method, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := method.Type().(*types.Signature)
	return ok && sig.Recv() != nil && isShopspringDecimalType(sig.Recv().Type())
}

// divisorIndex holds what the project's functions return and its fields are
// set to, so that a divisor read from them can be judged.
type divisorIndex struct {
	funcs  map[*types.Func]divisorSite
	fields map[*types.Var][]divisorValue
}

// divisorValue is a value assigned to a field, where it was assigned.
type divisorValue struct {
	site  divisorSite
	value ast.Expr
}

// divisorSite is a function body of a type-checked package.
type divisorSite struct {
	index *divisorIndex
	fn    *ast.FuncDecl
	info  *types.Info
}

func indexDivisors(ctx *core.GoProjectContext) *divisorIndex {
	index := &divisorIndex{funcs: make(map[*types.Func]divisorSite), fields: make(map[*types.Var][]divisorValue)}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				site := divisorSite{index: index, fn: fn, info: info}
				if obj, ok := info.Defs[fn.Name].(*types.Func); ok {
					index.funcs[obj] = site
				}
				index.collectFields(site)
			}
		}
	}
	return index
}

// collectFields records the values the function puts into struct fields:
// keyed composite literals and assignments to a selector.
func (index *divisorIndex) collectFields(site divisorSite) {
	ast.Inspect(site.fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok {
				if field, ok := site.info.Uses[key].(*types.Var); ok && field.IsField() {
					index.fields[field] = append(index.fields[field], divisorValue{site: site, value: node.Value})
				}
			}
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					if field, ok := site.info.Uses[sel.Sel].(*types.Var); ok && field.IsField() {
						index.fields[field] = append(index.fields[field], divisorValue{site: site, value: node.Rhs[i]})
					}
				}
			}
		}
		return true
	})
}

// nonZero reports a divisor that cannot be zero: a non-zero constant, a
// decimal built from such values or a power of ten, a local variable, a
// field or a function result that only ever holds one, a package-level
// value other than decimal.Zero.
func (s divisorSite) nonZero(expr ast.Expr, depth int) bool {
	if depth < 0 {
		return false
	}
	expr = ast.Unparen(expr)
	if tv, ok := s.info.Types[expr]; ok && tv.Value != nil {
		return constant.Sign(tv.Value) != 0
	}
	switch e := expr.(type) {
	case *ast.Ident:
		v, ok := s.info.Uses[e].(*types.Var)
		if !ok {
			return false
		}
		if isPackageLevelVar(v) {
			return true
		}
		if v.IsField() {
			return false
		}
		values, ok := localValues(s.fn, s.info, v)
		if !ok {
			return false
		}
		for _, value := range values {
			if value.call != nil {
				if !s.nonZeroResult(value.call, value.result, depth-1) {
					return false
				}
				continue
			}
			if !s.nonZero(value.expr, depth-1) {
				return false
			}
		}
		return true
	case *ast.SelectorExpr:
		v, ok := s.info.Uses[e.Sel].(*types.Var)
		if !ok {
			return false
		}
		if !v.IsField() {
			return isPackageLevelVar(v) && (v.Pkg().Path() != shopspringDecimalPath || v.Name() != "Zero")
		}
		values := s.index.fields[v]
		for _, value := range values {
			if !value.site.nonZero(value.value, depth-1) {
				return false
			}
		}
		return len(values) > 0
	case *ast.CallExpr:
		return s.nonZeroResult(e, 0, depth)
	}
	return false
}

// nonZeroResult judges result index of a call: a conversion, max with a
// positive constant, decimal's constructors and arithmetic, a project
// function whose every successful return is non-zero there.
func (s divisorSite) nonZeroResult(call *ast.CallExpr, index, depth int) bool {
	if index > 0 {
		callee := staticFunc(s.info, call)
		site, ok := s.index.funcs[callee]
		return ok && callee != nil && site.returnsNonZero(index, depth-1)
	}
	if tv, ok := s.info.Types[call.Fun]; ok && tv.IsType() && len(call.Args) == 1 {
		return s.nonZero(call.Args[0], depth)
	}
	if ident, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if builtin, ok := s.info.Uses[ident].(*types.Builtin); ok && builtin.Name() == "max" {
			for _, arg := range call.Args {
				if tv, ok := s.info.Types[arg]; ok && tv.Value != nil && constant.Sign(tv.Value) > 0 {
					return true
				}
			}
			return false
		}
	}
	var callee *types.Func
	var receiver ast.Expr
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		callee, _ = s.info.Uses[fun].(*types.Func)
	case *ast.SelectorExpr:
		callee, _ = s.info.Uses[fun.Sel].(*types.Func)
		if _, qualified := s.info.Uses[identOf(fun.X)].(*types.PkgName); !qualified {
			receiver = fun.X
		}
	}
	if callee == nil {
		return false
	}
	if callee.Pkg() != nil && callee.Pkg().Path() == shopspringDecimalPath {
		switch callee.Name() {
		case "New":
			return len(call.Args) == 2 && s.nonZero(call.Args[0], depth) // v × 10^exp
		case "NewFromInt", "NewFromInt32", "NewFromUint64", "NewFromFloat", "NewFromFloat32", "RequireFromString":
			return len(call.Args) == 1 && s.nonZero(call.Args[0], depth)
		case "Pow", "Neg", "Abs", "Shift":
			return receiver != nil && s.nonZero(receiver, depth)
		case "Mul":
			return receiver != nil && s.nonZero(receiver, depth) && s.nonZero(call.Args[0], depth)
		}
		return false
	}
	site, ok := s.index.funcs[callee]
	if !ok {
		return false
	}
	return site.returnsNonZero(0, depth-1)
}

// staticFunc returns the function a call names, nil for anything else.
func staticFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		callee, _ := info.Uses[fun].(*types.Func)
		return callee
	case *ast.SelectorExpr:
		callee, _ := info.Uses[fun.Sel].(*types.Func)
		return callee
	}
	return nil
}

// returnsNonZero reports a function whose every successful return statement
// returns a non-zero value at result index: a non-zero expression, a value
// the function compared before returning it, or the same result of a call
// that returns non-zero. A return that hands back a zero value together with
// an error is the failure path, which the caller handles through the error.
func (s divisorSite) returnsNonZero(index, depth int) bool {
	returns := 0
	nonZero := true
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		returns++
		switch {
		case len(ret.Results) == 1 && index > 0:
			call, isCall := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
			nonZero = isCall && s.nonZeroResult(call, index, depth)
		case index >= len(ret.Results):
			nonZero = false
		case s.failureReturn(ret, index):
		default:
			value := ret.Results[index]
			nonZero = s.nonZero(value, depth) || (identOf(value) != nil && divisorChecked(s.fn, s.info, value, ret))
		}
		return nonZero
	})
	return returns > 0 && nonZero
}

// failureReturn reports a return of the zero value at index together with an
// error that is not nil: the failure path.
func (s divisorSite) failureReturn(ret *ast.ReturnStmt, index int) bool {
	last := ret.Results[len(ret.Results)-1]
	if len(ret.Results) < 2 || index == len(ret.Results)-1 || !isErrorType(s.info.TypeOf(last)) {
		return false
	}
	if ident, ok := last.(*ast.Ident); ok && ident.Name == "nil" {
		return false
	}
	lit, ok := ast.Unparen(ret.Results[index]).(*ast.CompositeLit)
	return ok && len(lit.Elts) == 0
}

// divisorLocal is a value a local variable is given: an expression, or,
// when call is set, its result number result.
type divisorLocal struct {
	expr   ast.Expr
	call   *ast.CallExpr
	result int
}

// localValues returns every value a local variable is given: its
// definition and each later assignment. ok is false when one of them is not
// a plain single value - the zero value of a bare declaration, one result of
// a call, a compound assignment - or the variable's address is taken.
func localValues(fn *ast.FuncDecl, info *types.Info, v *types.Var) ([]divisorLocal, bool) {
	var values []divisorLocal
	ok := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				ident, isIdent := lhs.(*ast.Ident)
				if !isIdent || (info.Defs[ident] != v && info.Uses[ident] != v) {
					continue
				}
				if node.Tok != token.DEFINE && node.Tok != token.ASSIGN {
					ok = false
					continue
				}
				if len(node.Lhs) != len(node.Rhs) {
					// x, err := f(): result i of the call.
					call, isCall := node.Rhs[0].(*ast.CallExpr)
					if len(node.Rhs) != 1 || !isCall {
						ok = false
						continue
					}
					values = append(values, divisorLocal{call: call, result: i})
					continue
				}
				values = append(values, divisorLocal{expr: node.Rhs[i]})
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if info.Defs[name] != v {
					continue
				}
				if len(node.Values) != len(node.Names) {
					ok = false
					continue
				}
				values = append(values, divisorLocal{expr: node.Values[i]})
			}
		case *ast.UnaryExpr:
			if ident, isIdent := node.X.(*ast.Ident); isIdent && node.Op == token.AND && info.Uses[ident] == v {
				ok = false
			}
		}
		return ok
	})
	return values, ok && len(values) > 0
}

// divisionHelperParam reports a divisor read from a parameter of a function
// named for division: floorDiv(a, b), SafeDecimal.Div(other).
func (s divisorSite) divisionHelperParam(divisor ast.Expr) bool {
	named := false
	for _, word := range identifierTokens(s.fn.Name.Name) {
		switch word {
		case "div", "divide", "quo", "mod", "ratio":
			named = true
		}
	}
	if !named || s.fn.Type.Params == nil {
		return false
	}
	root := ast.Unparen(divisor)
	for {
		sel, ok := root.(*ast.SelectorExpr)
		if !ok {
			break
		}
		root = ast.Unparen(sel.X)
	}
	ident, ok := root.(*ast.Ident)
	if !ok {
		return false
	}
	obj := s.info.Uses[ident]
	for _, field := range s.fn.Type.Params.List {
		for _, name := range field.Names {
			if s.info.Defs[name] == obj {
				return true
			}
		}
	}
	return false
}

// divisorChecked reports a comparison of the divisor, or of a local value it
// was built from, anywhere in the function before the division, or a
// division by the length of a collection inside a loop over it.
func divisorChecked(fn *ast.FuncDecl, info *types.Info, divisor ast.Expr, division ast.Node) bool {
	sources := divisorSources(fn, info, divisor)
	if insideRangeOver(fn, division, sources.lengths) {
		return true
	}
	checks := func(node ast.Node) bool {
		found := false
		ast.Inspect(node, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				found = found || sources.vars[info.Uses[x]]
			case ast.Expr:
				text := types.ExprString(x)
				for _, value := range sources.texts {
					found = found || sameValue(text, value)
				}
			}
			return !found
		})
		return found
	}
	checked := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if checked || n == nil || n.Pos() >= division.Pos() {
			return false
		}
		switch x := n.(type) {
		case *ast.BinaryExpr:
			switch x.Op {
			case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
				checked = checks(x.X) || checks(x.Y)
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && decimalGuards[sel.Sel.Name] {
				checked = checks(sel.X)
				for _, arg := range x.Args {
					checked = checked || checks(arg)
				}
			}
		}
		return !checked
	})
	return checked
}

// insideRangeOver reports a division inside a range loop over one of the
// collections whose length the divisor holds: the loop body runs only when
// the collection has elements.
func insideRangeOver(fn *ast.FuncDecl, division ast.Node, collections map[string]bool) bool {
	if len(collections) == 0 {
		return false
	}
	inside := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if inside || n == nil || n.Pos() > division.Pos() || n.End() < division.End() {
			return false
		}
		if loop, ok := n.(*ast.RangeStmt); ok && loop.Body.Pos() <= division.Pos() && collections[types.ExprString(loop.X)] {
			inside = true
		}
		return !inside
	})
	return inside
}

// sameValue reports two expressions naming the same value or one a part of
// the other: a check of first.Value guards a division by first.Value.Decimal.
func sameValue(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".")
}

// divisorOrigins is what a divisor is made of.
type divisorOrigins struct {
	vars    map[types.Object]bool // local variables in it or in their definitions
	texts   []string              // the divisor, and what a variable of it aliases
	lengths map[string]bool       // the collections whose len it holds
}

// divisorSources returns the local variables the divisor is made of, and
// those their definitions are made of: a check of hours guards a division
// by days := decimal.NewFromInt(hours).Div(perDay). The base of a field
// access is not a source — first.Value is not checked by a check of first —
// but a variable that only names a field (before := snapshot.Value) is
// checked by a check of that field.
func divisorSources(fn *ast.FuncDecl, info *types.Info, divisor ast.Expr) divisorOrigins {
	origins := divisorOrigins{
		vars:    make(map[types.Object]bool),
		texts:   []string{types.ExprString(ast.Unparen(divisor))},
		lengths: make(map[string]bool),
	}
	var collect func(expr ast.Expr, depth int)
	collect = func(expr ast.Expr, depth int) {
		ast.Inspect(expr, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				_, field := info.Uses[x.Sel].(*types.Var)
				return !field
			case *ast.CallExpr:
				if fun, ok := ast.Unparen(x.Fun).(*ast.Ident); ok && fun.Name == "len" && len(x.Args) == 1 {
					if _, builtin := info.Uses[fun].(*types.Builtin); builtin {
						origins.lengths[types.ExprString(x.Args[0])] = true
					}
				}
				if keepsNonZero(info, x) {
					return true
				}
				// What the call makes of its arguments is unknown; only a
				// check of the call itself guards its value.
				origins.texts = append(origins.texts, types.ExprString(x))
				return false
			case *ast.Ident:
				v, ok := info.Uses[x].(*types.Var)
				if !ok || isPackageLevelVar(v) || origins.vars[v] {
					return true
				}
				origins.vars[v] = true
				if depth == 0 {
					return true
				}
				value := definingValue(fn, info, x)
				if value == nil {
					return true
				}
				if fieldChain(value) {
					origins.texts = append(origins.texts, types.ExprString(value))
				}
				collect(value, depth-1)
			}
			return true
		})
	}
	collect(divisor, 2)
	return origins
}

// nonZeroKeepers are the decimal functions and methods whose result is not
// zero when their operands are not: a check of an operand still guards it.
// Any other call — Pow, Round, a function of the project — can turn a
// checked operand into zero, so a check of its arguments guards nothing.
// The constructors from a number are decimalConstructors.
var nonZeroKeepers = map[string]bool{
	"NewFromBigInt": true, "NewFromString": true, "RequireFromString": true,
	"Abs": true, "Neg": true, "Mul": true, "Div": true, "Copy": true, "Max": true, "Min": true, "len": true,
}

// keepsNonZero reports a call through which the divisor's sources are
// followed: a conversion, the len builtin, or a decimal function that keeps a
// non-zero operand non-zero.
func keepsNonZero(info *types.Info, call *ast.CallExpr) bool {
	if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
		return true
	}
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		_, builtin := info.Uses[fun].(*types.Builtin)
		return builtin && nonZeroKeepers[fun.Name]
	case *ast.SelectorExpr:
		obj, ok := info.Uses[fun.Sel].(*types.Func)
		return ok && obj.Pkg() != nil && obj.Pkg().Path() == shopspringDecimalPath &&
			(nonZeroKeepers[fun.Sel.Name] || decimalConstructors[fun.Sel.Name])
	}
	return false
}

// fieldChain reports a.b.c: a value that only names a field.
func fieldChain(expr ast.Expr) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	for {
		switch x := ast.Unparen(sel.X).(type) {
		case *ast.Ident:
			return true
		case *ast.SelectorExpr:
			sel = x
		default:
			return false
		}
	}
}
