package security

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// sqlTaint is what the rule knows about the text of an expression: whether it
// can hold a string that came from outside the function, and the construct
// that first mixed such a string with other text ("concatenation" or
// "sprintf"; empty while the outside string is passed as is).
type sqlTaint struct {
	outside bool
	pattern string
}

func (t sqlTaint) join(other sqlTaint) sqlTaint {
	if !t.outside {
		return other
	}
	if t.pattern == "" && other.outside {
		t.pattern = other.pattern
	}
	return t
}

// mixed marks the point where an outside string is joined into larger text.
func (t sqlTaint) mixed(pattern string) sqlTaint {
	if t.outside && t.pattern == "" {
		t.pattern = pattern
	}
	return t
}

// sqlSafeTypePackages hold types whose text form cannot carry a quote: a
// time, a UUID, a decimal.
var sqlSafeTypePackages = map[string]bool{
	"time":                          true,
	"github.com/google/uuid":        true,
	"github.com/shopspring/decimal": true,
}

// sqlTaintCheck judges where the text of a query comes from within one file.
//
// The sources of outside text are the parameters of declared functions and
// methods: not the receiver, not closure parameters, which the enclosing
// function fills itself, and not a value of an unexported type of the same
// package - a query builder only that package fills. Text flows through assignments to local variables
// (flow-insensitively: a variable holds the join of every value assigned to
// it, element and field stores included), concatenation, fmt.Sprint*, the
// strings and strconv functions, append, conversions, indexing and ranging.
// Any other call returns text the rule does not see into, so a fragment helper
// or a filter builder ends the trail - the rule reports only a path it can
// follow, and values of numeric, bool, time, UUID or decimal type never carry
// outside text. A variable checked against a whitelist - a switch over
// constant cases that rejects the rest, an if that indexes a map with it,
// passes it to a validator or compares it with a non-empty constant and
// rejects - is clean.
type sqlTaintCheck struct {
	info      *types.Info
	params    map[*types.Var]bool
	assigned  map[*types.Var][]ast.Expr
	validated map[*types.Var]bool
	taints    map[*types.Var]*sqlTaint
	mentions  map[*types.Var]*bool
}

func newSQLTaintCheck(file *ast.File, info *types.Info) *sqlTaintCheck {
	c := &sqlTaintCheck{
		info:      info,
		params:    make(map[*types.Var]bool),
		assigned:  make(map[*types.Var][]ast.Expr),
		validated: make(map[*types.Var]bool),
		taints:    make(map[*types.Var]*sqlTaint),
		mentions:  make(map[*types.Var]*bool),
	}
	c.collect(file)
	return c
}

// injectedPattern returns the construct that mixed outside text into a query
// holding SQL text, or "" when the query holds none.
func (c *sqlTaintCheck) injectedPattern(query ast.Expr) string {
	t := c.taint(query)
	if !t.outside || t.pattern == "" || !c.mentionsSQL(query) {
		return ""
	}
	return t.pattern
}

// collect records the parameters, the assignments and the whitelist checks of
// the file.
func (c *sqlTaintCheck) collect(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Type.Params != nil {
				for _, field := range node.Type.Params.List {
					for _, name := range field.Names {
						if v, ok := c.info.Defs[name].(*types.Var); ok && !sqlPackagePrivateType(v) {
							c.params[v] = true
						}
					}
				}
			}
		case *ast.RangeStmt:
			for _, target := range []ast.Expr{node.Key, node.Value} {
				c.record(target, node.X)
			}
		case *ast.AssignStmt:
			c.recordAssign(node)
		case *ast.ValueSpec:
			if len(node.Names) == len(node.Values) {
				for i, name := range node.Names {
					c.record(name, node.Values[i])
				}
			}
		case *ast.SwitchStmt:
			c.recordSwitchWhitelist(node)
		case *ast.IfStmt:
			if sqlTerminates(node.Body) {
				c.recordChecked(node.Init)
				c.recordChecked(node.Cond)
			}
		case *ast.BlockStmt:
			c.recordValidatorResults(node.List)
		}
		return true
	})
}

func (c *sqlTaintCheck) recordAssign(node *ast.AssignStmt) {
	switch {
	case len(node.Lhs) == len(node.Rhs):
		for i, lhs := range node.Lhs {
			value := node.Rhs[i]
			if node.Tok == token.ADD_ASSIGN {
				value = &ast.BinaryExpr{X: lhs, OpPos: node.TokPos, Op: token.ADD, Y: value}
			}
			c.record(lhs, value)
		}
	case len(node.Rhs) == 1 && len(node.Lhs) == 2:
		// v, ok := m[k] / x.(T) / <-ch: the first result is the value.
		switch ast.Unparen(node.Rhs[0]).(type) {
		case *ast.IndexExpr, *ast.TypeAssertExpr, *ast.UnaryExpr:
			c.record(node.Lhs[0], node.Rhs[0])
		}
	}
	// One result of a multi-value call is text the rule does not see into.
}

// record adds value to the variable a store target is rooted at: x, x[i],
// x.f and *x all store into x.
func (c *sqlTaintCheck) record(target, value ast.Expr) {
	if target == nil {
		return
	}
	if v := c.rootVar(target); v != nil {
		c.assigned[v] = append(c.assigned[v], value)
	}
}

func (c *sqlTaintCheck) rootVar(expr ast.Expr) *types.Var {
	for {
		switch node := ast.Unparen(expr).(type) {
		case *ast.Ident:
			v, ok := c.info.ObjectOf(node).(*types.Var)
			if !ok || v.IsField() {
				return nil
			}
			return v
		case *ast.IndexExpr:
			expr = node.X
		case *ast.SelectorExpr:
			if _, isPkg := c.info.Uses[identOf(node.X)].(*types.PkgName); isPkg {
				expr = node.Sel
				continue
			}
			expr = node.X
		case *ast.StarExpr:
			expr = node.X
		default:
			return nil
		}
	}
}

func identOf(expr ast.Expr) *ast.Ident {
	ident, _ := ast.Unparen(expr).(*ast.Ident)
	return ident
}

// recordSwitchWhitelist marks the tag of a switch whose cases are constants
// and whose default rejects the value: past the switch the tag is one of the
// constants.
func (c *sqlTaintCheck) recordSwitchWhitelist(node *ast.SwitchStmt) {
	v := c.varOf(node.Tag)
	if v == nil || node.Init != nil {
		return
	}
	rejects := false
	for _, stmt := range node.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			return
		}
		if clause.List == nil {
			rejects = sqlTerminatesList(clause.Body)
			continue
		}
		for _, value := range clause.List {
			if !c.isConstant(value) {
				return
			}
		}
	}
	if rejects {
		c.validated[v] = true
	}
}

// recordChecked marks every variable a rejecting if checks against a
// whitelist: the index of a map lookup, the argument of a validator call, the
// operand of != with a non-empty constant.
func (c *sqlTaintCheck) recordChecked(node ast.Node) {
	if node == nil {
		return
	}
	ast.Inspect(node, func(n ast.Node) bool {
		switch expr := n.(type) {
		case *ast.IndexExpr:
			if _, isMap := c.typeOf(expr.X).Underlying().(*types.Map); isMap {
				c.markValidated(expr.Index)
			}
		case *ast.CallExpr:
			if c.isValidatorCall(expr) {
				c.markValidated(expr.Args[0])
			}
		case *ast.BinaryExpr:
			if expr.Op != token.NEQ {
				return true
			}
			if text, ok := c.constantString(expr.Y); ok && text != "" {
				c.markValidated(expr.X)
			}
			if text, ok := c.constantString(expr.X); ok && text != "" {
				c.markValidated(expr.Y)
			}
		}
		return true
	})
}

// recordValidatorResults handles the two-statement form of a validator check:
// err := validate(v) followed by if err != nil { return ... }.
func (c *sqlTaintCheck) recordValidatorResults(list []ast.Stmt) {
	for i := 0; i+1 < len(list); i++ {
		assign, ok := list[i].(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			continue
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || !c.isValidatorCall(call) {
			continue
		}
		check, ok := list[i+1].(*ast.IfStmt)
		if !ok || check.Init != nil || !sqlTerminates(check.Body) || !c.usesAny(check.Cond, assign.Lhs) {
			continue
		}
		c.markValidated(call.Args[0])
	}
}

// usesAny reports whether expr refers to a variable one of targets declares
// or assigns.
func (c *sqlTaintCheck) usesAny(expr ast.Expr, targets []ast.Expr) bool {
	vars := make(map[*types.Var]bool)
	for _, target := range targets {
		if v := c.varOf(target); v != nil {
			vars[v] = true
		}
	}
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && vars[c.varOf(ident)] {
			found = true
		}
		return !found
	})
	return found
}

func (c *sqlTaintCheck) markValidated(expr ast.Expr) {
	if v := c.varOf(expr); v != nil {
		c.validated[v] = true
	}
}

func (c *sqlTaintCheck) varOf(expr ast.Expr) *types.Var {
	ident := identOf(expr)
	if ident == nil {
		return nil
	}
	v, _ := c.info.ObjectOf(ident).(*types.Var)
	return v
}

// sqlTerminates reports whether a block rejects: it ends in return, panic or
// continue.
func sqlTerminates(block *ast.BlockStmt) bool {
	return block != nil && sqlTerminatesList(block.List)
}

func sqlTerminatesList(list []ast.Stmt) bool {
	if len(list) == 0 {
		return false
	}
	switch last := list[len(list)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return last.Tok == token.CONTINUE
	case *ast.ExprStmt:
		call, ok := last.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		ident, ok := call.Fun.(*ast.Ident)
		return ok && ident.Name == "panic"
	}
	return false
}

// taint judges the text of an expression.
func (c *sqlTaintCheck) taint(expr ast.Expr) sqlTaint {
	expr = ast.Unparen(expr)
	if c.isConstant(expr) || sqlSafeType(c.typeOf(expr)) {
		return sqlTaint{}
	}
	switch node := expr.(type) {
	case *ast.Ident:
		return c.varTaint(c.varOf(node))
	case *ast.BinaryExpr:
		if node.Op != token.ADD {
			return sqlTaint{}
		}
		return c.taint(node.X).join(c.taint(node.Y)).mixed("concatenation")
	case *ast.CallExpr:
		return c.callTaint(node)
	case *ast.SelectorExpr:
		if _, isPkg := c.info.Uses[identOf(node.X)].(*types.PkgName); isPkg {
			return c.varTaint(c.varOf(node.Sel))
		}
		if sel := c.info.Selections[node]; sel == nil || sel.Kind() != types.FieldVal {
			return sqlTaint{}
		}
		return c.taint(node.X)
	case *ast.IndexExpr:
		return c.taint(node.X)
	case *ast.SliceExpr:
		return c.taint(node.X)
	case *ast.StarExpr:
		return c.taint(node.X)
	case *ast.UnaryExpr:
		return c.taint(node.X)
	case *ast.TypeAssertExpr:
		return c.taint(node.X)
	case *ast.CompositeLit:
		var t sqlTaint
		for _, elt := range node.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				elt = kv.Value
			}
			t = t.join(c.taint(elt))
		}
		return t
	}
	return sqlTaint{}
}

// varTaint judges a variable once: a parameter of a declared function is
// outside text unless whitelisted; any other variable holds the join of what
// was assigned to it. A variable met again while its own values are being
// judged adds nothing beyond them.
func (c *sqlTaintCheck) varTaint(v *types.Var) sqlTaint {
	if v == nil || c.validated[v] {
		return sqlTaint{}
	}
	if c.params[v] {
		return sqlTaint{outside: true}
	}
	if t, seen := c.taints[v]; seen {
		if t == nil {
			return sqlTaint{}
		}
		return *t
	}
	c.taints[v] = nil
	var t sqlTaint
	for _, value := range c.assigned[v] {
		t = t.join(c.taint(value))
	}
	c.taints[v] = &t
	return t
}

// callTaint judges the text a call returns. Calls the rule follows pass their
// arguments' text on; any other call is a helper whose result the rule does
// not see into.
func (c *sqlTaintCheck) callTaint(call *ast.CallExpr) sqlTaint {
	if c.isConversion(call) {
		if len(call.Args) != 1 {
			return sqlTaint{}
		}
		return c.taint(call.Args[0])
	}
	pattern, follows := c.followedCall(call)
	if !follows {
		return sqlTaint{}
	}
	var t sqlTaint
	for _, arg := range call.Args {
		t = t.join(c.taint(arg))
	}
	return t.mixed(pattern)
}

// followedCall reports whether the rule follows text through a call, and the
// construct it counts as mixing text: append, fmt.Sprint*, the functions of
// strings and strconv, and a database package's Rebind.
func (c *sqlTaintCheck) followedCall(call *ast.CallExpr) (string, bool) {
	var name *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		name = fun
	case *ast.SelectorExpr:
		name = fun.Sel
	default:
		return "", false
	}
	switch obj := c.info.Uses[name].(type) {
	case *types.Builtin:
		return "concatenation", obj.Name() == "append"
	case *types.Func:
		if obj.Pkg() == nil {
			return "", false
		}
		sig, ok := obj.Type().(*types.Signature)
		if !ok {
			return "", false
		}
		path := obj.Pkg().Path()
		if sig.Recv() != nil {
			return "concatenation", obj.Name() == "Rebind" && isSQLDatabasePackage(path)
		}
		switch {
		case path == "fmt" && strings.HasPrefix(obj.Name(), "Sprint"):
			return "sprintf", true
		case path == "strings", path == "strconv":
			return "concatenation", true
		}
	}
	return "", false
}

// mentionsSQL reports whether constant text an expression is built from holds
// an SQL keyword.
func (c *sqlTaintCheck) mentionsSQL(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if text, ok := c.constantString(expr); ok {
		return sqlKeyword.MatchString(text)
	}
	switch node := expr.(type) {
	case *ast.BinaryExpr:
		return node.Op == token.ADD && (c.mentionsSQL(node.X) || c.mentionsSQL(node.Y))
	case *ast.CallExpr:
		for _, arg := range node.Args {
			if c.mentionsSQL(arg) {
				return true
			}
		}
	case *ast.Ident:
		v := c.varOf(node)
		if v == nil {
			return false
		}
		if seen, ok := c.mentions[v]; ok {
			return seen != nil && *seen
		}
		c.mentions[v] = nil
		found := false
		for _, value := range c.assigned[v] {
			if c.mentionsSQL(value) {
				found = true
				break
			}
		}
		c.mentions[v] = &found
		return found
	}
	return false
}

// sqlPackagePrivateType reports whether a parameter has an unexported type of
// its own package, or a pointer to one: only that package builds such values,
// and a query builder of its own is no outside text.
func sqlPackagePrivateType(v *types.Var) bool {
	t := v.Type()
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj.Pkg() != nil && obj.Pkg() == v.Pkg() && !obj.Exported()
}

// sqlSafeType reports whether values of a type print without quotes: numbers,
// bools, times, UUIDs, decimals, and pointers, slices and arrays of them.
func sqlSafeType(t types.Type) bool {
	if t == nil {
		return false
	}
	if named, ok := types.Unalias(t).(*types.Named); ok {
		if pkg := named.Obj().Pkg(); pkg != nil && sqlSafeTypePackages[pkg.Path()] {
			return true
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() != types.Invalid && u.Info()&types.IsString == 0
	case *types.Pointer:
		return sqlSafeType(u.Elem())
	case *types.Slice:
		return sqlSafeType(u.Elem())
	case *types.Array:
		return sqlSafeType(u.Elem())
	}
	return false
}

func (c *sqlTaintCheck) typeOf(expr ast.Expr) types.Type {
	if tv, ok := c.info.Types[expr]; ok && tv.Type != nil {
		return tv.Type
	}
	if ident, ok := expr.(*ast.Ident); ok {
		if obj := c.info.ObjectOf(ident); obj != nil {
			return obj.Type()
		}
	}
	return types.Typ[types.Invalid]
}

// isValidatorCall reports whether a call looks like a check of one value:
// a single argument, and a single error or bool result - validate(v),
// allowed.Has(v). A database call is no check of its query.
func (c *sqlTaintCheck) isValidatorCall(call *ast.CallExpr) bool {
	if len(call.Args) != 1 || c.isConversion(call) || sqlQueryArgument(call, c.info) != nil {
		return false
	}
	sig, ok := c.typeOf(call.Fun).Underlying().(*types.Signature)
	if !ok || sig.Results().Len() != 1 {
		return false
	}
	result := sig.Results().At(0).Type()
	if basic, ok := result.Underlying().(*types.Basic); ok {
		return basic.Info()&types.IsBoolean != 0
	}
	return types.Identical(result, types.Universe.Lookup("error").Type())
}

func (c *sqlTaintCheck) isConversion(call *ast.CallExpr) bool {
	tv, ok := c.info.Types[call.Fun]
	return ok && tv.IsType()
}

func (c *sqlTaintCheck) isConstant(expr ast.Expr) bool {
	tv, ok := c.info.Types[expr]
	return ok && tv.Value != nil
}

func (c *sqlTaintCheck) constantString(expr ast.Expr) (string, bool) {
	tv, ok := c.info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}
