package security

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp/syntax"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// sqlTaint is what the rule knows about the text of an expression: whether it
// can hold a string that came from outside the function, and the construct
// that first mixed such a string with other text ("concatenation" or
// "sprintf"; empty while the outside string is passed as is).
type sqlTaint struct {
	outside bool
	pattern string
}

type sqlValidation struct {
	at        token.Pos
	scope     ast.Node
	block     *ast.BlockStmt
	statement int
}

type sqlNodeContext struct {
	callable       ast.Node
	blocks         []*ast.BlockStmt
	iifeScopes     []ast.Node
	deferredScopes []ast.Node
}

type sqlRegexpOutcome uint8

type sqlRegexpResult struct {
	outcome  sqlRegexpOutcome
	parseErr error
}

const (
	sqlRegexpInvalid sqlRegexpOutcome = iota
	sqlRegexpNotAnchored
	sqlRegexpAnchored
)

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
	file           *ast.File
	info           *types.Info
	params         map[*types.Var]bool
	assigned       map[*types.Var][]ast.Expr
	validated      map[*types.Var][]sqlValidation
	contexts       map[token.Pos]sqlNodeContext
	collectContext sqlNodeContext
	functions      map[*types.Func]*ast.FuncDecl
	literalMaps    map[types.Object]bool
	syncCalls      map[*ast.FuncLit]bool
	regexpPatterns map[types.Object]string
	at             token.Pos
	scope          ast.Node
	queryContext   sqlNodeContext
	writes         map[*types.Var][]token.Pos
	taints         map[*types.Var]*sqlTaint
	mentions       map[*types.Var]*bool
}

func newSQLTaintCheck(file *ast.File, info *types.Info) *sqlTaintCheck {
	c := &sqlTaintCheck{
		info:           info,
		file:           file,
		params:         make(map[*types.Var]bool),
		assigned:       make(map[*types.Var][]ast.Expr),
		validated:      make(map[*types.Var][]sqlValidation),
		contexts:       make(map[token.Pos]sqlNodeContext),
		functions:      make(map[*types.Func]*ast.FuncDecl),
		literalMaps:    make(map[types.Object]bool),
		syncCalls:      make(map[*ast.FuncLit]bool),
		regexpPatterns: make(map[types.Object]string),
		writes:         make(map[*types.Var][]token.Pos),
		taints:         make(map[*types.Var]*sqlTaint),
		mentions:       make(map[*types.Var]*bool),
	}
	c.collect(file)
	return c
}

// injectedPattern returns the construct that mixed outside text into a query
// holding SQL text, or "" when the query holds none.
func (c *sqlTaintCheck) injectedPattern(query ast.Expr, at token.Pos) string {
	c.at = at
	c.queryContext = c.contexts[at]
	c.scope = c.queryContext.callable
	c.taints = make(map[*types.Var]*sqlTaint)
	c.mentions = make(map[*types.Var]*bool)
	t := c.taint(query)
	if !t.outside || t.pattern == "" || !c.mentionsSQL(query) {
		return ""
	}
	return t.pattern
}

// collect records the parameters, the assignments and the whitelist checks of
// the file.
func (c *sqlTaintCheck) collect(file *ast.File) {
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		stack = append(stack, n)
		context := sqlContextFor(stack)
		if old, ok := c.contexts[n.Pos()]; !ok || len(context.blocks) >= len(old.blocks) {
			c.contexts[n.Pos()] = context
		}
		c.collectContext = context
		c.recordSyncCall(stack)
		c.collectNode(n)
		return true
	})
}

// recordSyncCall marks a function literal called in place, not by go or
// defer: it returns before the statement after the call runs.
func (c *sqlTaintCheck) recordSyncCall(stack []ast.Node) {
	call, ok := stack[len(stack)-1].(*ast.CallExpr)
	if !ok {
		return
	}
	literal, ok := ast.Unparen(call.Fun).(*ast.FuncLit)
	if !ok || len(stack) < 2 {
		return
	}
	switch stack[len(stack)-2].(type) {
	case *ast.GoStmt, *ast.DeferStmt:
		return
	}
	c.syncCalls[literal] = true
}

func sqlContextFor(stack []ast.Node) sqlNodeContext {
	var context sqlNodeContext
	for i, parent := range stack {
		switch node := parent.(type) {
		case *ast.FuncDecl:
			context.callable = node
		case *ast.FuncLit:
			outer := context.callable
			context.callable = node
			if i > 1 {
				if call, ok := stack[i-1].(*ast.CallExpr); ok && call.Fun == node {
					_, deferred := stack[i-2].(*ast.DeferStmt)
					_, goroutine := stack[i-2].(*ast.GoStmt)
					if deferred || goroutine {
						context.deferredScopes = append(context.deferredScopes, outer)
					} else {
						context.iifeScopes = append(context.iifeScopes, outer)
					}
				}
			}
		case *ast.BlockStmt:
			context.blocks = append(context.blocks, node)
		}
	}
	return context
}

func (c *sqlTaintCheck) collectNode(n ast.Node) {
	switch node := n.(type) {
	case *ast.FuncDecl:
		c.collectFunction(node)
	case *ast.RangeStmt:
		c.collectRange(node)
	case *ast.AssignStmt:
		c.collectAssignment(node)
	case *ast.ValueSpec:
		c.collectValues(node)
	case *ast.SwitchStmt:
		c.recordSwitchWhitelist(node)
	case *ast.IfStmt:
		c.collectIf(node)
	case *ast.BlockStmt:
		c.recordValidatorResults(node.List)
	case *ast.CallExpr:
		if !c.readOnlyMapBuiltin(node) {
			for _, arg := range node.Args {
				c.invalidateLiteralMap(arg)
			}
		}
	case *ast.ReturnStmt:
		for _, result := range node.Results {
			c.invalidateLiteralMap(result)
		}
	}
}

func (c *sqlTaintCheck) collectFunction(node *ast.FuncDecl) {
	fn, ok := c.info.Defs[node.Name].(*types.Func)
	if ok {
		c.functions[fn] = node
	}
	if node.Type.Params == nil {
		return
	}
	for _, field := range node.Type.Params.List {
		for _, name := range field.Names {
			v, ok := c.info.Defs[name].(*types.Var)
			if ok && !sqlPackagePrivateType(v) {
				c.params[v] = true
			}
		}
	}
}

func (c *sqlTaintCheck) collectRange(node *ast.RangeStmt) {
	for _, target := range []ast.Expr{node.Key, node.Value} {
		c.record(target, node.X)
	}
}

func (c *sqlTaintCheck) collectAssignment(node *ast.AssignStmt) {
	c.recordAssign(node)
	for _, rhs := range node.Rhs {
		if typ := c.typeOf(rhs); typ != nil {
			if _, mapType := typ.Underlying().(*types.Map); mapType {
				c.invalidateLiteralMap(rhs)
			}
		}
	}
	for _, lhs := range node.Lhs {
		if _, indexed := ast.Unparen(lhs).(*ast.IndexExpr); indexed {
			if v := c.rootVar(lhs); v != nil {
				c.literalMaps[v] = false
			}
		}
	}
	if len(node.Lhs) != len(node.Rhs) {
		return
	}
	for i, lhs := range node.Lhs {
		id, ok := ast.Unparen(lhs).(*ast.Ident)
		if !ok {
			continue
		}
		obj := c.info.ObjectOf(id)
		if obj == nil {
			continue
		}
		if _, composite := ast.Unparen(node.Rhs[i]).(*ast.CompositeLit); composite {
			c.literalMaps[obj] = c.finiteMapLiteral(node.Rhs[i])
		}
		if pattern := c.regexpLiteral(node.Rhs[i]); pattern != "" {
			c.regexpPatterns[obj] = pattern
		}
	}
}

func (c *sqlTaintCheck) readOnlyMapBuiltin(call *ast.CallExpr) bool {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	builtin, ok := c.info.Uses[id].(*types.Builtin)
	return ok && (builtin.Name() == "len" || builtin.Name() == "cap")
}

func (c *sqlTaintCheck) invalidateLiteralMap(expr ast.Expr) {
	if typ := c.typeOf(expr); typ != nil {
		if _, ok := typ.Underlying().(*types.Map); !ok {
			return
		}
	} else {
		return
	}
	if v := c.rootVar(expr); v != nil {
		c.literalMaps[v] = false
	}
}

func (c *sqlTaintCheck) collectValues(node *ast.ValueSpec) {
	if len(node.Names) != len(node.Values) {
		return
	}
	for i, name := range node.Names {
		value := node.Values[i]
		c.record(name, value)
		obj := c.info.Defs[name]
		if obj == nil {
			continue
		}
		if _, composite := ast.Unparen(value).(*ast.CompositeLit); composite {
			c.literalMaps[obj] = c.finiteMapLiteral(value)
		}
		if pattern := c.regexpLiteral(value); pattern != "" {
			c.regexpPatterns[obj] = pattern
		}
	}
}

func (c *sqlTaintCheck) collectIf(node *ast.IfStmt) {
	if !sqlTerminates(node.Body) {
		return
	}
	c.recordErrorValidatorInit(node.Init, node.Cond, node.Pos())
	c.recordRejectingCondition(node.Cond)
	c.recordCommaOKWhitelist(node)
}

func (c *sqlTaintCheck) recordErrorValidatorInit(init ast.Stmt, condition ast.Expr, at token.Pos) {
	assign, ok := init.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		return
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if ok && c.isValidatorCall(call) && c.validatorReturnsError(call) && c.rejectsError(assign.Lhs, condition) {
		c.markValidated(c.varOf(call.Args[0]), at)
	}
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
		case *ast.CallExpr:
			if c.httpRequestCookie(node.Rhs[0]) {
				c.record(node.Lhs[0], node.Rhs[0])
			}
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
		c.writes[v] = append(c.writes[v], target.Pos())
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
			if _, isPkg := c.info.Uses[helpers.IdentOf(node.X)].(*types.PkgName); isPkg {
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
		c.markValidated(v, node.Pos())
	}
}

// recordRejectingCondition marks values restricted by a rejecting condition.
func (c *sqlTaintCheck) recordRejectingCondition(node ast.Node) {
	condition, ok := node.(ast.Expr)
	if !ok || condition == nil {
		return
	}
	condition = ast.Unparen(condition)
	if negated, ok := condition.(*ast.UnaryExpr); ok && negated.Op == token.NOT {
		c.recordPositiveWhitelist(negated.X, condition.Pos())
		return
	}
	if condition, ok := finiteExclusionVariable(condition, c); ok {
		c.markValidated(condition, node.Pos())
		return
	}
	comparison, ok := condition.(*ast.BinaryExpr)
	if !ok || comparison.Op != token.NEQ {
		return
	}
	if text, ok := c.constantString(comparison.Y); ok && text != "" {
		c.markValidated(c.varOf(comparison.X), condition.Pos())
	} else if text, ok := c.constantString(comparison.X); ok && text != "" {
		c.markValidated(c.varOf(comparison.Y), condition.Pos())
	}
}

func finiteExclusionVariable(expr ast.Expr, c *sqlTaintCheck) (*types.Var, bool) {
	expr = ast.Unparen(expr)
	if binary, ok := expr.(*ast.BinaryExpr); ok && binary.Op == token.LAND {
		left, leftOK := finiteExclusionVariable(binary.X, c)
		right, rightOK := finiteExclusionVariable(binary.Y, c)
		return left, leftOK && rightOK && left == right
	}
	binary, ok := expr.(*ast.BinaryExpr)
	if !ok || binary.Op != token.NEQ {
		return nil, false
	}
	if text, ok := c.constantString(binary.Y); ok && text != "" {
		v := c.varOf(binary.X)
		return v, v != nil
	}
	if text, ok := c.constantString(binary.X); ok && text != "" {
		v := c.varOf(binary.Y)
		return v, v != nil
	}
	return nil, false
}

// recordCommaOKWhitelist handles map membership expressed by an init clause:
// if _, ok := allowed[value]; !ok { return }.
func (c *sqlTaintCheck) recordCommaOKWhitelist(node *ast.IfStmt) {
	assign, ok := node.Init.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return
	}
	index, ok := ast.Unparen(assign.Rhs[0]).(*ast.IndexExpr)
	if !ok || c.typeOf(index.X) == nil || !c.isNegatedIdent(node.Cond, c.varOf(assign.Lhs[1])) {
		return
	}
	if _, isMap := c.typeOf(index.X).Underlying().(*types.Map); isMap && c.literalMap(index.X) {
		c.markValidated(c.varOf(index.Index), node.Cond.Pos())
	}
}

func (c *sqlTaintCheck) isNegatedIdent(expr ast.Expr, target *types.Var) bool {
	negated, ok := ast.Unparen(expr).(*ast.UnaryExpr)
	if !ok || negated.Op != token.NOT || target == nil {
		return false
	}
	ident, ok := ast.Unparen(negated.X).(*ast.Ident)
	return ok && target == c.varOf(ident)
}

// recordPositiveWhitelist accepts only predicates whose true result restricts
// the argument to a finite set or to a regexp-anchored identifier shape.
func (c *sqlTaintCheck) recordPositiveWhitelist(expr ast.Expr, at token.Pos) {
	expr = ast.Unparen(expr)
	switch node := expr.(type) {
	case *ast.CallExpr:
		result := c.anchoredRegexpCall(node)
		if result.outcome == sqlRegexpAnchored && result.parseErr == nil {
			arg := 0
			if _, method := ast.Unparen(node.Fun).(*ast.SelectorExpr); !method {
				arg = 1
			}
			c.markValidated(c.varOf(node.Args[arg]), at)
			return
		}
		if len(node.Args) != 1 {
			return
		}
		if c.boolWhitelistFunction(node) {
			c.markValidated(c.varOf(node.Args[0]), at)
		}
	case *ast.IndexExpr:
		if _, isMap := c.typeOf(node.X).Underlying().(*types.Map); isMap && c.literalMap(node.X) {
			c.markValidated(c.varOf(node.Index), at)
		}
	}
}

func (c *sqlTaintCheck) boolWhitelistFunction(call *ast.CallExpr) bool {
	ident := helpers.IdentOf(call.Fun)
	fn, ok := c.info.Uses[ident].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 1 || sig.Results().Len() != 1 || !types.Identical(sig.Results().At(0).Type(), types.Typ[types.Bool]) {
		return false
	}
	decl := c.functions[fn]
	if decl == nil || decl.Body == nil || len(decl.Body.List) != 1 || len(decl.Type.Params.List) != 1 {
		return false
	}
	param := decl.Type.Params.List[0].Names
	if len(param) != 1 {
		return false
	}
	ret, ok := decl.Body.List[0].(*ast.ReturnStmt)
	return ok && len(ret.Results) == 1 && finiteEqualitySet(ret.Results[0], param[0].Name)
}

func finiteEqualitySet(expr ast.Expr, name string) bool {
	expr = ast.Unparen(expr)
	if binary, ok := expr.(*ast.BinaryExpr); ok && binary.Op == token.LOR {
		return finiteEqualitySet(binary.X, name) && finiteEqualitySet(binary.Y, name)
	}
	binary, ok := expr.(*ast.BinaryExpr)
	if !ok || binary.Op != token.EQL {
		return false
	}
	ident, left := ast.Unparen(binary.X).(*ast.Ident)
	if left && ident.Name == name {
		return isSQLStringLiteral(binary.Y)
	}
	ident, right := ast.Unparen(binary.Y).(*ast.Ident)
	return right && ident.Name == name && isSQLStringLiteral(binary.X)
}

func isSQLStringLiteral(expr ast.Expr) bool {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

func (c *sqlTaintCheck) literalMap(expr ast.Expr) bool {
	if _, ok := ast.Unparen(expr).(*ast.CompositeLit); ok {
		return c.finiteMapLiteral(expr)
	}
	id := helpers.IdentOf(expr)
	if id == nil {
		return false
	}
	return c.literalMaps[c.info.Uses[id]]
}

func (c *sqlTaintCheck) finiteMapLiteral(expr ast.Expr) bool {
	literal, ok := ast.Unparen(expr).(*ast.CompositeLit)
	if !ok {
		return false
	}
	if typ := c.typeOf(literal); typ == nil {
		return false
	} else if _, ok := typ.Underlying().(*types.Map); !ok {
		return false
	}
	for _, element := range literal.Elts {
		entry, ok := element.(*ast.KeyValueExpr)
		if !ok || !c.isConstant(entry.Key) {
			return false
		}
	}
	return true
}

func (c *sqlTaintCheck) anchoredRegexpCall(call *ast.CallExpr) sqlRegexpResult {
	pattern := ""
	if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && selector.Sel.Name == "MatchString" {
		if len(call.Args) != 1 {
			return sqlRegexpResult{outcome: sqlRegexpNotAnchored}
		}
		typ := c.typeOf(selector.X)
		if pointer, ok := typ.(*types.Pointer); ok {
			typ = pointer.Elem()
		}
		named, ok := typ.(*types.Named)
		if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "regexp" || named.Obj().Name() != "Regexp" {
			return sqlRegexpResult{outcome: sqlRegexpNotAnchored}
		}
		if ident := helpers.IdentOf(selector.X); ident != nil {
			if obj := c.info.Uses[ident]; obj != nil {
				pattern = c.regexpPatterns[obj]
			}
		}
	} else {
		if len(call.Args) != 2 || helpers.CalleeName(call) != "MatchString" {
			return sqlRegexpResult{outcome: sqlRegexpNotAnchored}
		}
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return sqlRegexpResult{outcome: sqlRegexpNotAnchored}
		}
		pkg, ok := c.info.Uses[helpers.IdentOf(selector.X)].(*types.PkgName)
		if !ok || pkg.Imported().Path() != "regexp" {
			return sqlRegexpResult{outcome: sqlRegexpNotAnchored}
		}
		pattern = c.constantStringExpr(call.Args[0])
	}
	return anchoredRegexp(pattern)
}

func anchoredRegexp(pattern string) sqlRegexpResult {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if parsed == nil {
		return sqlRegexpResult{outcome: sqlRegexpInvalid, parseErr: err}
	}
	root := parsed.Simplify()
	if root.Op != syntax.OpConcat || len(root.Sub) < 2 {
		return sqlRegexpResult{outcome: sqlRegexpNotAnchored}
	}
	first, last := root.Sub[0].Op, root.Sub[len(root.Sub)-1].Op
	if first == syntax.OpBeginText && last == syntax.OpEndText {
		return sqlRegexpResult{outcome: sqlRegexpAnchored}
	}
	return sqlRegexpResult{outcome: sqlRegexpNotAnchored}
}

func (c *sqlTaintCheck) constantStringExpr(expr ast.Expr) string {
	text, _ := c.constantString(expr)
	return text
}

func (c *sqlTaintCheck) regexpLiteral(expr ast.Expr) string {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return ""
	}
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "MustCompile" {
		return ""
	}
	pkg, ok := c.info.Uses[helpers.IdentOf(selector.X)].(*types.PkgName)
	if !ok || pkg.Imported().Path() != "regexp" {
		return ""
	}
	lit, ok := ast.Unparen(call.Args[0]).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	value := constant.MakeFromLiteral(lit.Value, lit.Kind, 0)
	if value.Kind() != constant.String {
		return ""
	}
	return constant.StringVal(value)
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
		if !ok || !c.isValidatorCall(call) || !c.validatorReturnsError(call) {
			continue
		}
		check, ok := list[i+1].(*ast.IfStmt)
		if !ok || check.Init != nil || !sqlTerminates(check.Body) || !c.rejectsError(assign.Lhs, check.Cond) {
			continue
		}
		c.markValidated(c.varOf(call.Args[0]), check.Pos())
	}
}

func (c *sqlTaintCheck) rejectsError(targets []ast.Expr, condition ast.Expr) bool {
	comparison, ok := ast.Unparen(condition).(*ast.BinaryExpr)
	if !ok || comparison.Op != token.NEQ {
		return false
	}
	for _, side := range [][2]ast.Expr{{comparison.X, comparison.Y}, {comparison.Y, comparison.X}} {
		ident, ok := ast.Unparen(side[0]).(*ast.Ident)
		if !ok || !c.usesAny(ident, targets) {
			continue
		}
		nilIdent, ok := ast.Unparen(side[1]).(*ast.Ident)
		if ok && nilIdent.Name == "nil" {
			return true
		}
	}
	return false
}

func (c *sqlTaintCheck) validatorReturnsError(call *ast.CallExpr) bool {
	sig, ok := c.typeOf(call.Fun).Underlying().(*types.Signature)
	return ok && sig.Results().Len() == 1 && types.Identical(sig.Results().At(0).Type(), types.Universe.Lookup("error").Type())
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
	return helpers.ContainsNode[*ast.Ident](expr, func(ident *ast.Ident) bool {
		return vars[c.varOf(ident)]
	})
}

func (c *sqlTaintCheck) markValidated(v *types.Var, at token.Pos) {
	if v != nil {
		context := c.contexts[at]
		block := lastSQLBlock(context.blocks)
		statement := statementIndex(block, at)
		if block == nil {
			context = c.collectContext
			block = lastSQLBlock(context.blocks)
			statement = statementIndex(block, at)
		}
		if block != nil && statement >= 0 {
			c.validated[v] = append(c.validated[v], sqlValidation{
				at: at, scope: context.callable, block: block, statement: statement,
			})
		}
	}
}

func lastSQLBlock(blocks []*ast.BlockStmt) *ast.BlockStmt {
	if len(blocks) == 0 {
		return nil
	}
	return blocks[len(blocks)-1]
}

func statementIndex(block *ast.BlockStmt, pos token.Pos) int {
	if block == nil {
		return -1
	}
	for i, statement := range block.List {
		if statement.Pos() <= pos && pos <= statement.End() {
			return i
		}
	}
	return -1
}

func (c *sqlTaintCheck) varOf(expr ast.Expr) *types.Var {
	ident := helpers.IdentOf(expr)
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
		if _, isPkg := c.info.Uses[helpers.IdentOf(node.X)].(*types.PkgName); isPkg {
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
	if v == nil || c.validatedAt(v) {
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

// capturedByClosure reports a local variable that a function literal checks
// but does not declare: unless the literal is called in place, the enclosing
// function may write it after the literal starts, while the literal still runs.
func (c *sqlTaintCheck) capturedByClosure(v *types.Var, scope ast.Node) bool {
	literal, ok := scope.(*ast.FuncLit)
	if !ok || c.syncCalls[literal] || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
		return false
	}
	return v.Pos() < scope.Pos() || v.Pos() >= scope.End()
}

func (c *sqlTaintCheck) validatedAt(v *types.Var) bool {
	for _, validation := range c.validated[v] {
		deferred := slices.Contains(c.queryContext.deferredScopes, validation.scope)
		if validation.scope != c.scope && !deferred && !slices.Contains(c.queryContext.iifeScopes, validation.scope) {
			continue
		}
		queryStatement := -1
		for _, block := range c.queryContext.blocks {
			if block == validation.block {
				queryStatement = statementIndex(block, c.at)
				break
			}
		}
		if queryStatement < 0 || validation.statement >= queryStatement {
			continue
		}
		// A deferred or launched closure runs later: a write anywhere after
		// the check, up to the end of the checking function, may reach it.
		until := c.at
		if deferred {
			until = validation.scope.End()
		}
		captured := c.capturedByClosure(v, validation.scope)
		changed := false
		for _, write := range c.writes[v] {
			if validation.at < write && write < until || captured && write > validation.scope.End() {
				changed = true
				break
			}
		}
		if !changed {
			return true
		}
	}
	return false
}

// callTaint judges the text a call returns. HTTP request accessors are outside
// text sources; calls the rule follows pass their arguments' text on, and any
// other call is a helper whose result the rule does not see into.
func (c *sqlTaintCheck) callTaint(call *ast.CallExpr) sqlTaint {
	if c.httpRequestValue(call) {
		return sqlTaint{outside: true}
	}
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

// httpRequestValue reports methods that return text supplied by an HTTP
// request. Match their declared receiver type so unrelated methods with the
// same name do not become sources.
func (c *sqlTaintCheck) httpRequestValue(call *ast.CallExpr) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := c.info.Uses[selector.Sel].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	name := fn.Name()
	receiver := sig.Recv().Type()
	if isNamedType(receiver, "net/http", "Request") {
		return name == "FormValue" || name == "PostFormValue" || name == "PathValue" || name == "Cookie"
	}
	return name == "Get" && (isNamedType(receiver, "net/url", "Values") || isNamedType(receiver, "net/http", "Header")) && c.httpRequestContainer(selector.X, make(map[*types.Var]bool))
}

func (c *sqlTaintCheck) httpRequestContainer(expr ast.Expr, visiting map[*types.Var]bool) bool {
	expr = ast.Unparen(expr)
	switch node := expr.(type) {
	case *ast.CallExpr:
		selector, ok := ast.Unparen(node.Fun).(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Query" || len(node.Args) != 0 {
			return false
		}
		fn, ok := c.info.Uses[selector.Sel].(*types.Func)
		if !ok {
			return false
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() == nil || !isNamedType(sig.Recv().Type(), "net/url", "URL") {
			return false
		}
		return c.isHTTPRequestURL(selector.X, visiting)
	case *ast.SelectorExpr:
		if selectorIsRequestField(node, c) {
			return true
		}
	case *ast.Ident:
		v := c.varOf(node)
		if v == nil || visiting[v] {
			return false
		}
		visiting[v] = true
		defer delete(visiting, v)
		for _, assigned := range c.assigned[v] {
			if c.httpRequestContainer(assigned, visiting) {
				return true
			}
		}
	}
	return false
}

func (c *sqlTaintCheck) isHTTPRequestURL(expr ast.Expr, visiting map[*types.Var]bool) bool {
	expr = ast.Unparen(expr)
	switch node := expr.(type) {
	case *ast.SelectorExpr:
		return node.Sel.Name == "URL" && c.isHTTPRequest(node.X)
	case *ast.Ident:
		v := c.varOf(node)
		if v == nil || visiting[v] {
			return false
		}
		visiting[v] = true
		defer delete(visiting, v)
		for _, assigned := range c.assigned[v] {
			if c.isHTTPRequestURL(assigned, visiting) {
				return true
			}
		}
	}
	return false
}

func selectorIsRequestField(selector *ast.SelectorExpr, c *sqlTaintCheck) bool {
	if selector.Sel.Name != "Form" && selector.Sel.Name != "PostForm" && selector.Sel.Name != "Header" {
		return false
	}
	return c.isHTTPRequest(selector.X)
}

func (c *sqlTaintCheck) isHTTPRequest(expr ast.Expr) bool {
	typ := c.typeOf(expr)
	return isNamedType(typ, "net/http", "Request")
}

func (c *sqlTaintCheck) httpRequestCookie(call ast.Expr) bool {
	callExpr, ok := ast.Unparen(call).(*ast.CallExpr)
	if !ok || !c.httpRequestValue(callExpr) {
		return false
	}
	selector, ok := ast.Unparen(callExpr.Fun).(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Cookie"
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
		if slices.ContainsFunc(node.Args, c.mentionsSQL) {
			return true
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
		found := slices.ContainsFunc(c.assigned[v], c.mentionsSQL)
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
