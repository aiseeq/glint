package patterns

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorsIsTargetUnreachableRule())
}

// ErrorsIsTargetUnreachableRule detects a check of an error against a sentinel
// that the error can never be:
//
//	_, err := s.repo.GetUser(ctx, id)      // the repository answers ErrNotFound
//	if errors.Is(err, sql.ErrNoRows) {     // never true
//	    return ErrUserNotFound
//	}
//
// The check is dead, and the case it was written for leaves through the
// generic branch — a missing record answered as a server error. It happens
// when one layer starts translating the driver's sentinel and its callers keep
// testing for the old one, or when a function reports "not found" as text.
//
// What a call can return is followed through the project's code: return
// statements, local variables, wrappers that pass a parameter on (%w), the
// implementations of an interface method, minus a sentinel a guard before the
// return already handled (if err == sql.ErrNoRows { return ... }). Anything
// the analysis cannot see — a function value, a callback handed to a library,
// a field, an error type with its own Unwrap or Is — makes it stay silent.
// Of the library sentinels only database/sql's ErrNoRows is judged: what
// database/sql returns it from is known (Row.Scan, sqlx Get), and a library
// that does not import database/sql cannot return it.
//
// A value whose static type is a concrete error type without Unwrap or Is is
// judged by its type alone: errors.Is compares it with the sentinel and
// nothing else, and a sentinel made by errors.New is never of that type.
type ErrorsIsTargetUnreachableRule struct {
	*rules.BaseRule
}

// NewErrorsIsTargetUnreachableRule creates the rule
func NewErrorsIsTargetUnreachableRule() *ErrorsIsTargetUnreachableRule {
	return &ErrorsIsTargetUnreachableRule{BaseRule: rules.NewBaseRule(
		"errors-is-target-unreachable",
		"patterns",
		"Detects errors.Is or == against a sentinel the checked error can never be — the call never returns it, so the branch is dead",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: what a call returns is found in other files.
func (r *ErrorsIsTargetUnreachableRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ErrorsIsTargetUnreachableRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the sentinel checks that can never match.
func (r *ErrorsIsTargetUnreachableRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("errors is target unreachable: nil Go project context")
	}
	flow := newErrorFlow(ctx)
	var violations []*core.Violation
	for _, fn := range flow.order {
		for _, site := range sentinelChecks(fn) {
			reason, unreachable := flow.unreachable(fn, site)
			if !unreachable {
				continue
			}
			line := fn.file.LineFor(site.node)
			if fn.file.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(fn.file.RelPath, line, "The check for "+site.sentinel.Name()+" never matches: "+reason+
				" — the branch is dead, and the case it was written for takes the generic error path")
			v.WithCode(strings.TrimSpace(fn.file.GetLine(line)))
			v.WithSuggestion("Check for the sentinel the call actually returns, or make the callee return (wrap with %w) the one its callers test")
			violations = append(violations, v)
		}
	}
	return violations, nil
}

// sentinelCheck is a comparison of an error with a package-level sentinel.
type sentinelCheck struct {
	node     ast.Node
	checked  ast.Expr
	sentinel *types.Var
}

// sentinelChecks returns the checks of a function: err == S, err != S,
// errors.Is(err, S), switch err { case S: }.
func sentinelChecks(fn typedFunc) []sentinelCheck {
	var checks []sentinelCheck
	add := func(node ast.Node, checked, target ast.Expr) {
		if isNilIdent(ast.Unparen(checked)) {
			return
		}
		if sentinel := sentinelVar(fn.info, target); sentinel != nil && implementsError(fn.info.TypeOf(checked)) {
			checks = append(checks, sentinelCheck{node: node, checked: ast.Unparen(checked), sentinel: sentinel})
		}
	}
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if (node.Op == token.EQL || node.Op == token.NEQ) && (sentinelVar(fn.info, node.X) == nil) != (sentinelVar(fn.info, node.Y) == nil) {
				add(node, node.X, node.Y)
				add(node, node.Y, node.X)
			}
		case *ast.CallExpr:
			if len(node.Args) == 2 && isPackageFuncCall(fn.file.GoAST, fn.info, node, "errors", "Is") {
				add(node, node.Args[0], node.Args[1])
			}
		case *ast.SwitchStmt:
			if node.Tag == nil {
				return true
			}
			for _, stmt := range node.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, value := range clause.List {
					add(value, node.Tag, value)
				}
			}
		}
		return true
	})
	return checks
}

// sentinelVar returns the package-level error variable an expression names,
// named as a sentinel is (ErrNotFound): other error variables hold state.
func sentinelVar(info *types.Info, expr ast.Expr) *types.Var {
	var ident *ast.Ident
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		ident = e
	case *ast.SelectorExpr:
		ident = e.Sel
	default:
		return nil
	}
	v, ok := info.Uses[ident].(*types.Var)
	if !ok || v.IsField() || !isPackageLevelVar(v) || !implementsError(v.Type()) ||
		!sentinelName(v.Name()) {
		return nil
	}
	return v
}

// errorSet is what an error expression may hold.
type errorSet struct {
	sentinels map[*types.Var]bool // package-level sentinels, canonical
	params    map[int]map[*types.Var]bool
	libraries map[*types.Package]bool // packages outside the project the error may come from
	unknown   bool
	opaque    bool // an error type with its own Unwrap or Is
	// notFoundText marks an error made by errors.New or fmt.Errorf whose text
	// says "not found": a not-found no caller can tell apart.
	notFoundText bool
	// invalid are the errors made by errors.New or fmt.Errorf without %w
	// that reject an input ("name is required", "must be positive"): a
	// client's mistake no caller can tell apart.
	invalid []inputCheck
}

func newErrorSet() *errorSet {
	return &errorSet{sentinels: map[*types.Var]bool{}, params: map[int]map[*types.Var]bool{}, libraries: map[*types.Package]bool{}}
}

func unknownErrors() *errorSet {
	set := newErrorSet()
	set.unknown = true
	return set
}

func (s *errorSet) add(other *errorSet, drop map[*types.Var]bool) {
	for v := range other.sentinels {
		if !drop[v] {
			s.sentinels[v] = true
		}
	}
	for index, handled := range other.params {
		merged := map[*types.Var]bool{}
		for v := range handled {
			merged[v] = true
		}
		for v := range drop {
			merged[v] = true
		}
		if existing, ok := s.params[index]; ok {
			// Two paths pass the parameter on: only what both handle is handled.
			for v := range existing {
				if !merged[v] {
					delete(existing, v)
				}
			}
			continue
		}
		s.params[index] = merged
	}
	for lib := range other.libraries {
		s.libraries[lib] = true
	}
	s.unknown = s.unknown || other.unknown
	s.opaque = s.opaque || other.opaque
	s.notFoundText = s.notFoundText || other.notFoundText
	for _, check := range other.invalid {
		if !slices.Contains(s.invalid, check) {
			s.invalid = append(s.invalid, check)
		}
	}
}

// errorFlow follows what the project's functions return as errors.
type errorFlow struct {
	funcs     map[*types.Func]typedFunc
	order     []typedFunc
	project   map[string]bool
	impls     map[*types.Func][]*types.Func
	summaries map[*types.Func]*errorSet
	visiting  map[*types.Func]bool
	aliases   map[*types.Var]*types.Var
	madeByNew map[*types.Var]bool // sentinels declared with errors.New or fmt.Errorf
}

func newErrorFlow(ctx *core.GoProjectContext) *errorFlow {
	flow := &errorFlow{
		funcs:     map[*types.Func]typedFunc{},
		project:   map[string]bool{},
		impls:     map[*types.Func][]*types.Func{},
		summaries: map[*types.Func]*errorSet{},
		visiting:  map[*types.Func]bool{},
		aliases:   map[*types.Var]*types.Var{},
		madeByNew: map[*types.Var]bool{},
	}
	for _, pkg := range ctx.Packages {
		if pkg != nil && pkg.Package != nil {
			flow.project[pkg.Package.PkgPath] = true
		}
	}
	interfaces := projectInterfaces(ctx)
	flow.order = projectFuncDecls(ctx)
	for _, fn := range flow.order {
		obj, ok := fn.info.Defs[fn.decl.Name].(*types.Func)
		if !ok {
			continue
		}
		flow.funcs[obj] = fn
		if testDouble(obj) {
			continue
		}
		for _, method := range implementedMethods(obj, interfaces) {
			flow.impls[method] = append(flow.impls[method], obj)
		}
		flow.collectAliases(fn.file.GoAST, fn.info)
	}
	return flow
}

// testDouble reports a method of a package that only holds test doubles: a
// directory named mock, fake or stub, or a package named like xtest.
func testDouble(fn *types.Func) bool {
	if fn.Pkg() == nil {
		return false
	}
	parts := strings.Split(fn.Pkg().Path(), "/")
	for _, part := range parts {
		switch part {
		case "mock", "mocks", "fake", "fakes", "stub", "stubs", "testutil":
			return true
		}
	}
	return strings.HasSuffix(parts[len(parts)-1], "test")
}

// collectAliases records the sentinels declared as another sentinel
// (var ErrAbsent = ErrNotFound) and those made by errors.New or fmt.Errorf.
func (f *errorFlow) collectAliases(file *ast.File, info *types.Info) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Values) != len(vs.Names) {
				continue
			}
			for i, name := range vs.Names {
				v, ok := info.Defs[name].(*types.Var)
				if !ok {
					continue
				}
				if target := sentinelVar(info, vs.Values[i]); target != nil {
					f.aliases[v] = target
				}
				if call, ok := ast.Unparen(vs.Values[i]).(*ast.CallExpr); ok &&
					(isPackageFuncCall(file, info, call, "errors", "New") || isPackageFuncCall(file, info, call, "fmt", "Errorf")) {
					f.madeByNew[v] = true
				}
			}
		}
	}
}

// canonical follows sentinel aliases to the variable holding the value.
func (f *errorFlow) canonical(v *types.Var) *types.Var {
	for range 8 {
		target, ok := f.aliases[v]
		if !ok {
			return v
		}
		v = target
	}
	return v
}

// unreachable reports a check whose checked error can never be the sentinel,
// with why.
func (f *errorFlow) unreachable(fn typedFunc, site sentinelCheck) (string, bool) {
	if reason, ok := f.concreteMismatch(fn.info, site); ok {
		return reason, true
	}
	sentinel := f.canonical(site.sentinel)
	library := sentinel.Pkg() != nil && !f.project[sentinel.Pkg().Path()]
	if library && !isNoRows(sentinel) {
		return "", false
	}
	set := f.exprErrors(fn, site.checked, site.node, 0)
	if set.unknown || set.opaque || len(set.params) > 0 || set.sentinels[sentinel] {
		return "", false
	}
	if library {
		for lib := range set.libraries {
			if lib.Path() != sqlxPath && !stdlibPath(lib.Path()) && importsSQL(lib, map[*types.Package]bool{}) {
				return "", false
			}
		}
	}
	if call := f.originCall(fn, site.checked, site.node); call != nil {
		return types.ExprString(call.Fun) + " never returns it", true
	}
	return "the checked error never holds it", true
}

const sqlxPath = "github.com/jmoiron/sqlx"

// importsSQL reports a library that reaches database/sql through its imports:
// it may return ErrNoRows from a path the analysis does not model.
func importsSQL(pkg *types.Package, seen map[*types.Package]bool) bool {
	if seen[pkg] {
		return false
	}
	seen[pkg] = true
	for _, imported := range pkg.Imports() {
		if imported.Path() == "database/sql" || importsSQL(imported, seen) {
			return true
		}
	}
	return false
}

// stdlibPath reports a standard library import path.
func stdlibPath(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

// sentinelName reports a name given to sentinel errors: ErrNotFound, errClosed.
func sentinelName(name string) bool {
	return strings.HasPrefix(name, "Err") || strings.HasPrefix(name, "err")
}

func isNoRows(v *types.Var) bool {
	return v.Pkg() != nil && v.Pkg().Path() == "database/sql" && v.Name() == "ErrNoRows"
}

// concreteMismatch reports a checked value of a concrete error type with
// neither Unwrap nor Is, compared with a sentinel made by errors.New or
// fmt.Errorf: errors.Is can only compare the two, and they differ in type.
func (f *errorFlow) concreteMismatch(info *types.Info, site sentinelCheck) (string, bool) {
	t := info.TypeOf(site.checked)
	if t == nil || types.IsInterface(t) || hasErrorChainMethod(t) {
		return "", false
	}
	sentinel := f.canonical(site.sentinel)
	if !isErrorType(sentinel.Type()) || (!isNoRows(sentinel) && !f.madeByNew[sentinel]) {
		return "", false
	}
	return "the checked value is a " + types.TypeString(t, types.RelativeTo(nil)) + " without Unwrap or Is, and the sentinel is not of that type", true
}

// hasErrorChainMethod reports a type whose value or pointer has Unwrap or Is.
func hasErrorChainMethod(t types.Type) bool {
	for _, name := range []string{"Unwrap", "Is", "As"} {
		if obj, _, _ := types.LookupFieldOrMethod(t, true, nil, name); obj != nil {
			return true
		}
	}
	return false
}

// originCall returns the call the checked error was last assigned from
// before the check.
func (f *errorFlow) originCall(fn typedFunc, checked ast.Expr, at ast.Node) *ast.CallExpr {
	switch expr := checked.(type) {
	case *ast.CallExpr:
		return expr
	case *ast.Ident:
		obj, ok := fn.info.Uses[expr].(*types.Var)
		if !ok {
			return nil
		}
		var origin *ast.CallExpr
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || assign.End() > at.Pos() {
				return true
			}
			for i, lhs := range assign.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || fn.info.ObjectOf(ident) != obj {
					continue
				}
				origin = nil
				switch {
				case len(assign.Rhs) == len(assign.Lhs):
					origin, _ = ast.Unparen(assign.Rhs[i]).(*ast.CallExpr)
				case len(assign.Rhs) == 1:
					origin, _ = ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
				}
			}
			return true
		})
		return origin
	}
	return nil
}

// callErrors returns what a call may return as its error.
func (f *errorFlow) callErrors(fn typedFunc, call *ast.CallExpr, at ast.Node) *errorSet {
	if tv, ok := fn.info.Types[call.Fun]; ok && tv.IsType() {
		if len(call.Args) == 1 {
			return f.exprErrors(fn, call.Args[0], at, 0)
		}
		return unknownErrors()
	}
	callee, ok := typeutil.Callee(fn.info, call).(*types.Func)
	if !ok {
		return unknownErrors()
	}
	if callee.Pkg() == nil || !f.project[callee.Pkg().Path()] {
		return f.libraryErrors(fn, callee, call, at)
	}
	sig, _ := callee.Type().(*types.Signature)
	targets := []*types.Func{callee.Origin()}
	if sig != nil && sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
		targets = f.impls[callee]
		if len(targets) == 0 {
			return unknownErrors()
		}
	}
	set := newErrorSet()
	for _, target := range targets {
		summary := f.summary(target)
		set.add(f.substitute(fn, summary, call, at), nil)
	}
	return set
}

// substitute replaces the parameters a summary passes on with what the call
// hands them.
func (f *errorFlow) substitute(fn typedFunc, summary *errorSet, call *ast.CallExpr, at ast.Node) *errorSet {
	set := newErrorSet()
	plain := *summary
	plain.params = nil
	set.add(&plain, nil)
	for index, handled := range summary.params {
		if index < 0 || index >= len(call.Args) {
			set.unknown = true
			continue
		}
		set.add(f.exprErrors(fn, call.Args[index], at, 0), handled)
	}
	return set
}

// libraryErrors models a call outside the project. Of database/sql only the
// single-row reads return ErrNoRows; a library handed a function may return
// what the function returns.
func (f *errorFlow) libraryErrors(fn typedFunc, callee *types.Func, call *ast.CallExpr, at ast.Node) *errorSet {
	if callee.Pkg() == nil {
		return unknownErrors()
	}
	path := callee.Pkg().Path()
	switch {
	case path == "errors" && callee.Name() == "New":
		set := newErrorSet()
		set.notFoundText = len(call.Args) == 1 && saysNotFound(fn.info, call.Args[0])
		if len(call.Args) == 1 {
			set.invalid = rejectedInput(fn, call, call.Args[0])
		}
		return set
	case path == "fmt" && callee.Name() == "Errorf":
		return f.errorfErrors(fn, call, at)
	case path == "errors" && callee.Name() == "Join":
		set := newErrorSet()
		for _, arg := range call.Args {
			set.add(f.exprErrors(fn, arg, at, 0), nil)
		}
		return set
	}
	if sig, ok := callee.Type().(*types.Signature); ok && sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
		// A project type may implement the interface, unless the value came
		// from the library itself: res.RowsAffected() on what ExecContext gave.
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !f.libraryValue(fn, sel.X) {
			return unknownErrors()
		}
	}
	set := newErrorSet()
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && fn.info.Selections[sel] != nil {
		set.add(f.callbackErrors(fn.info.TypeOf(sel.X)), nil)
	}
	for _, arg := range call.Args {
		set.add(f.callbackErrors(fn.info.TypeOf(arg)), nil)
	}
	set.libraries[callee.Pkg()] = true
	if noRows := noRowsSource(callee); noRows != nil {
		set.sentinels[noRows] = true
	}
	return set
}

// libraryValue reports a local variable every assignment of which is a call
// into a library: its dynamic type is the library's.
func (f *errorFlow) libraryValue(fn typedFunc, expr ast.Expr) bool {
	v, ok := variableOf(fn.info, ast.Unparen(expr)).(*types.Var)
	if !ok || isPackageLevelVar(v) {
		return false
	}
	if _, isParam := paramIndex(fn, v); isParam {
		return false
	}
	assigned, library := false, true
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || !assignsVar(fn.info, assign, v) {
			return true
		}
		assigned = true
		call, ok := ast.Unparen(assign.Rhs[len(assign.Rhs)-1]).(*ast.CallExpr)
		if !ok || len(assign.Rhs) != 1 {
			library = false
			return false
		}
		callee, ok := typeutil.Callee(fn.info, call).(*types.Func)
		if !ok || callee.Pkg() == nil || f.project[callee.Pkg().Path()] {
			library = false
		}
		return library
	})
	return assigned && library
}

// callbackErrors returns what a library handed a value may return from the
// project code it runs through it: a function's errors are unknown, and a
// project type's methods returning an error (an UnmarshalJSON, a Scan), its
// own or a field's, return what they return.
func (f *errorFlow) callbackErrors(t types.Type) *errorSet {
	set := newErrorSet()
	f.collectCallbacks(t, map[types.Type]bool{}, 0, set)
	return set
}

func (f *errorFlow) collectCallbacks(t types.Type, seen map[types.Type]bool, depth int, set *errorSet) {
	if t == nil || seen[t] || set.unknown {
		return
	}
	if depth > maxErrorTrace {
		set.unknown = true
		return
	}
	seen[t] = true
	if named, ok := t.(*types.Named); ok {
		if named.Obj().Pkg() == nil || !f.project[named.Obj().Pkg().Path()] {
			// A library value runs the project code set in its fields: a
			// command's Execute returns what its RunE returned.
			if hooksProjectCode(named) {
				set.unknown = true
			}
			return
		}
		for _, method := range errorMethods(types.NewPointer(named)) {
			if method.Pkg() == nil {
				set.unknown = true
				return
			}
			if !f.project[method.Pkg().Path()] {
				// Promoted from an embedded library type.
				set.libraries[method.Pkg()] = true
				continue
			}
			summary := f.summary(method.Origin())
			if len(summary.params) > 0 {
				set.unknown = true
				return
			}
			set.add(summary, nil)
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		f.collectCallbacks(u.Elem(), seen, depth+1, set)
	case *types.Slice:
		f.collectCallbacks(u.Elem(), seen, depth+1, set)
	case *types.Array:
		f.collectCallbacks(u.Elem(), seen, depth+1, set)
	case *types.Map:
		f.collectCallbacks(u.Key(), seen, depth+1, set)
		f.collectCallbacks(u.Elem(), seen, depth+1, set)
	case *types.Signature:
		set.unknown = true
	case *types.Interface:
		if len(errorMethods(u)) > 0 {
			set.unknown = true
		}
	case *types.Struct:
		for i := range u.NumFields() {
			f.collectCallbacks(u.Field(i).Type(), seen, depth+1, set)
		}
	}
}

// hooksProjectCode reports a library struct with an exported field holding a
// function or an interface whose methods return errors.
func hooksProjectCode(named *types.Named) bool {
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := range st.NumFields() {
		field := st.Field(i)
		if !field.Exported() {
			continue
		}
		switch u := field.Type().Underlying().(type) {
		case *types.Signature:
			return true
		case *types.Interface:
			if len(errorMethods(u)) > 0 {
				return true
			}
		}
	}
	return false
}

// errorMethods returns the methods of a method set that return an error.
func errorMethods(t types.Type) []*types.Func {
	var methods []*types.Func
	set := types.NewMethodSet(t)
	for i := range set.Len() {
		method, ok := set.At(i).Obj().(*types.Func)
		if !ok {
			continue
		}
		sig := method.Signature()
		for j := range sig.Results().Len() {
			if isErrorType(sig.Results().At(j).Type()) {
				methods = append(methods, method)
				break
			}
		}
	}
	return methods
}

// noRowsSource returns database/sql's ErrNoRows for the calls that return
// it: Row.Scan and Row.Err, and sqlx's Get and the Scan methods of its Row.
func noRowsSource(callee *types.Func) *types.Var {
	path := callee.Pkg().Path()
	sig, _ := callee.Type().(*types.Signature)
	recv := ""
	if sig != nil && sig.Recv() != nil {
		t := sig.Recv().Type()
		if ptr, ok := t.(*types.Pointer); ok {
			t = ptr.Elem()
		}
		if named, ok := t.(*types.Named); ok {
			recv = named.Obj().Name()
		}
	}
	returns := false
	switch path {
	case "database/sql":
		returns = recv == "Row" && (callee.Name() == "Scan" || callee.Name() == "Err")
	case sqlxPath:
		returns = callee.Name() == "Get" || callee.Name() == "GetContext" ||
			(recv == "Row" && (strings.HasSuffix(callee.Name(), "Scan") || callee.Name() == "Err"))
	}
	if !returns {
		return nil
	}
	return lookupNoRows(callee.Pkg())
}

// lookupNoRows finds database/sql's ErrNoRows from a package that is it or
// imports it.
func lookupNoRows(pkg *types.Package) *types.Var {
	if pkg.Path() != "database/sql" {
		for _, imported := range pkg.Imports() {
			if imported.Path() == "database/sql" {
				pkg = imported
				break
			}
		}
	}
	if pkg.Path() != "database/sql" {
		return nil
	}
	v, _ := pkg.Scope().Lookup("ErrNoRows").(*types.Var)
	return v
}

// errorfErrors returns what fmt.Errorf wraps: the error arguments of its %w
// verbs, or every error argument when the format is not a constant.
func (f *errorFlow) errorfErrors(fn typedFunc, call *ast.CallExpr, at ast.Node) *errorSet {
	set := newErrorSet()
	if len(call.Args) == 0 {
		return set
	}
	set.notFoundText = saysNotFound(fn.info, call.Args[0])
	format := ""
	if tv, ok := fn.info.Types[call.Args[0]]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		format = constant.StringVal(tv.Value)
		if !strings.Contains(format, "%w") {
			set.invalid = rejectedInput(fn, call, call.Args[0])
			return set
		}
	}
	classified := false
	for _, arg := range call.Args[1:] {
		if implementsError(fn.info.TypeOf(arg)) {
			set.add(f.exprErrors(fn, arg, at, 0), nil)
			classified = classified || sentinelVar(fn.info, ast.Unparen(arg)) != nil
		}
	}
	// An input check wrapped together with a sentinel (%w: %w, ErrInvalid,
	// err) is told apart by it.
	if classified {
		set.invalid = nil
	}
	return set
}

// saysNotFound reports a constant error text that says "not found".
func saysNotFound(info *types.Info, expr ast.Expr) bool {
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	return strings.Contains(strings.ToLower(constant.StringVal(tv.Value)), "not found")
}

// inputRejection is an error text refusing an input value.
var inputRejection = regexp.MustCompile(`(?i)\b(?:is|are) required\b|\bmust (?:be|not|have|contain)\b|\b(?:cannot|can't|must not) be empty\b|\bis empty\b`)

// inputCheck is an error refusing an input value: its text, and the field
// of the parameter the check reads ("" for the parameter itself).
type inputCheck struct {
	text  string
	field string
}

// rejectedInput returns the error a call makes when it refuses an input
// value - a constant text, under an if testing a parameter of fn (name == "",
// req.Amount <= 0): a check of the caller's input, not of the server's own
// state (s.repo == nil); nil for any other error.
func rejectedInput(fn typedFunc, made *ast.CallExpr, text ast.Expr) []inputCheck {
	tv, ok := fn.info.Types[text]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String || !inputRejection.MatchString(constant.StringVal(tv.Value)) {
		return nil
	}
	path, _ := astutil.PathEnclosingInterval(fn.file.GoAST, made.Pos(), made.End())
	for _, node := range path {
		check, ok := node.(*ast.IfStmt)
		if !ok || made.Pos() < check.Body.Pos() {
			continue
		}
		if field, ok := testedParameter(fn, check.Cond); ok {
			return []inputCheck{{text: constant.StringVal(tv.Value), field: field}}
		}
		return nil
	}
	return nil
}

// testedParameter reports a condition reading a parameter of fn other than
// by a nil comparison, and the field of it the condition reads.
func testedParameter(fn typedFunc, cond ast.Expr) (string, bool) {
	sig := funcSignature(fn)
	if sig == nil {
		return "", false
	}
	params := map[types.Object]bool{}
	for i := range sig.Params().Len() {
		params[sig.Params().At(i)] = true
	}
	found, field := false, ""
	ast.Inspect(cond, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if isNilIdent(ast.Unparen(node.X)) || isNilIdent(ast.Unparen(node.Y)) {
				return false
			}
		case *ast.SelectorExpr:
			if id, ok := ast.Unparen(node.X).(*ast.Ident); ok && params[fn.info.Uses[id]] {
				found, field = true, node.Sel.Name
			}
		case *ast.Ident:
			found = found || params[fn.info.Uses[node]]
		}
		return !found
	})
	return field, found
}

// maxErrorTrace bounds the local assignments followed back from one value.
const maxErrorTrace = 6

// exprErrors returns what an expression may hold as an error at a node.
func (f *errorFlow) exprErrors(fn typedFunc, expr ast.Expr, at ast.Node, depth int) *errorSet {
	if depth > maxErrorTrace {
		return unknownErrors()
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if e.Name == "nil" {
			if _, isNil := fn.info.Uses[e].(*types.Nil); isNil {
				return newErrorSet()
			}
		}
		return f.identErrors(fn, e, at, depth)
	case *ast.SelectorExpr:
		if sentinel := sentinelVar(fn.info, e); sentinel != nil {
			set := newErrorSet()
			set.sentinels[f.canonical(sentinel)] = true
			return set
		}
	case *ast.CallExpr:
		return f.callErrors(fn, e, at)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return f.exprErrors(fn, e.X, at, depth)
		}
	case *ast.CompositeLit:
		set := newErrorSet()
		if t := fn.info.TypeOf(e); t == nil || hasErrorChainMethod(t) || hasErrorChainMethod(types.NewPointer(t)) {
			set.opaque = true
		}
		return set
	}
	return unknownErrors()
}

// identErrors returns what a variable may hold at a node: a sentinel, a
// parameter, or the values assigned to a local before the node, minus the
// sentinels a guard before the node handled.
func (f *errorFlow) identErrors(fn typedFunc, ident *ast.Ident, at ast.Node, depth int) *errorSet {
	v, ok := fn.info.Uses[ident].(*types.Var)
	if !ok {
		return unknownErrors()
	}
	return f.varErrors(fn, v, at, depth)
}

// varErrors is identErrors for a variable.
func (f *errorFlow) varErrors(fn typedFunc, v *types.Var, at ast.Node, depth int) *errorSet {
	set := newErrorSet()
	if isPackageLevelVar(v) {
		// A package error variable not named as a sentinel holds state: its
		// value is whatever was last stored.
		if !implementsError(v.Type()) || !sentinelName(v.Name()) {
			return unknownErrors()
		}
		set.sentinels[f.canonical(v)] = true
		return set
	}
	handled := f.handledBefore(fn, v, at)
	if index, ok := paramIndex(fn, v); ok {
		set.params[index] = handled
		return set
	}
	if assignedAgainInLoop(fn, v, at) {
		return unknownErrors()
	}
	defs, complete := f.reachingDefs(fn, v, at)
	if !complete {
		return unknownErrors()
	}
	for _, def := range defs {
		set.add(f.defErrors(fn, def, depth), handled)
	}
	return set
}

// varDef is one assignment of a variable: the value at index of a statement.
type varDef struct {
	node   ast.Node // *ast.AssignStmt or *ast.ValueSpec
	lhs    []ast.Expr
	values []ast.Expr
	index  int
}

// defErrors returns what one assignment stores.
func (f *errorFlow) defErrors(fn typedFunc, def varDef, depth int) *errorSet {
	switch {
	case len(def.values) == 0:
		return newErrorSet() // var err error
	case len(def.values) == len(def.lhs):
		return f.exprErrors(fn, def.values[def.index], def.node, depth+1)
	case len(def.values) == 1:
		if call, ok := ast.Unparen(def.values[0]).(*ast.CallExpr); ok {
			return f.callErrors(fn, call, def.node)
		}
	}
	return unknownErrors()
}

// reachingDefs returns the assignments of a variable that reach the node:
// the nearest one every path passes, and those in branches between it and
// the node. complete is false when no assignment dominates the node.
func (f *errorFlow) reachingDefs(fn typedFunc, v *types.Var, at ast.Node) ([]varDef, bool) {
	var defs []varDef
	path, _ := astutil.PathEnclosingInterval(fn.file.GoAST, at.Pos(), at.Pos())
	for i := 1; i < len(path); i++ {
		child := path[i-1]
		var list []ast.Stmt
		var init ast.Stmt
		switch parent := path[i].(type) {
		case *ast.BlockStmt:
			list = parent.List
		case *ast.CaseClause:
			list = parent.Body
		case *ast.CommClause:
			list = parent.Body
		case *ast.IfStmt:
			init = parent.Init
		case *ast.SwitchStmt:
			init = parent.Init
		case *ast.TypeSwitchStmt:
			init = parent.Init
		case *ast.ForStmt:
			init = parent.Init
		case *ast.FuncDecl, *ast.FuncLit:
			return defs, false
		}
		if init != nil && init != child {
			if direct := directDefs(fn.info, init, v); len(direct) > 0 {
				return append(defs, direct...), true
			}
		}
		for j := len(list) - 1; j >= 0; j-- {
			stmt := list[j]
			if stmt.End() > child.Pos() {
				continue
			}
			if direct := directDefs(fn.info, stmt, v); len(direct) > 0 {
				return append(defs, direct...), true
			}
			if _, ok := stmt.(*ast.RangeStmt); ok && mentionsVar(fn.info, stmt, v) && assignsVar(fn.info, stmt, v) {
				return defs, false
			}
			defs = append(defs, nestedDefs(fn.info, stmt, v)...)
		}
	}
	return defs, false
}

// directDefs returns the assignments of the variable a statement itself makes.
func directDefs(info *types.Info, stmt ast.Stmt, v *types.Var) []varDef {
	var defs []varDef
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		for i, lhs := range s.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && info.ObjectOf(ident) == v {
				defs = append(defs, varDef{node: s, lhs: s.Lhs, values: s.Rhs, index: i})
			}
		}
	case *ast.DeclStmt:
		gen, ok := s.Decl.(*ast.GenDecl)
		if !ok {
			return nil
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			lhs := make([]ast.Expr, len(vs.Names))
			for i, name := range vs.Names {
				lhs[i] = name
			}
			for i, name := range vs.Names {
				if info.Defs[name] == v {
					defs = append(defs, varDef{node: vs, lhs: lhs, values: vs.Values, index: i})
				}
			}
		}
	}
	return defs
}

// nestedDefs returns the assignments of the variable inside a compound
// statement, outside function literals.
func nestedDefs(info *types.Info, stmt ast.Stmt, v *types.Var) []varDef {
	var defs []varDef
	ast.Inspect(stmt, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case ast.Stmt:
			defs = append(defs, directDefs(info, node, v)...)
		}
		return true
	})
	return defs
}

// assignedAgainInLoop reports a variable assigned after the node inside a
// loop that holds both: the next iteration brings that value to the node.
func assignedAgainInLoop(fn typedFunc, v *types.Var, at ast.Node) bool {
	found := false
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		var body *ast.BlockStmt
		switch loop := n.(type) {
		case *ast.ForStmt:
			body = loop.Body
		case *ast.RangeStmt:
			body = loop.Body
		default:
			return true
		}
		if body.Pos() > at.Pos() || body.End() < at.End() {
			return true
		}
		ast.Inspect(body, func(m ast.Node) bool {
			if assign, ok := m.(*ast.AssignStmt); ok && assign.Pos() > at.Pos() && assignsVar(fn.info, assign, v) {
				found = true
			}
			return !found
		})
		return !found
	})
	return found
}

// mentionsVar reports a node that defines or uses the variable.
func mentionsVar(info *types.Info, node ast.Node, v *types.Var) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && info.ObjectOf(ident) == v {
			found = true
		}
		return !found
	})
	return found
}

// paramIndex returns the position of a parameter of the function.
func paramIndex(fn typedFunc, v *types.Var) (int, bool) {
	index := 0
	for _, field := range fn.decl.Type.Params.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, name := range field.Names {
			if fn.info.Defs[name] == v {
				return index, true
			}
			index++
		}
	}
	return 0, false
}

// summary returns what a project function may return as its error.
func (f *errorFlow) summary(callee *types.Func) *errorSet {
	if set, ok := f.summaries[callee]; ok {
		return set
	}
	fn, ok := f.funcs[callee]
	if !ok || f.visiting[callee] {
		return unknownErrors()
	}
	f.visiting[callee] = true
	defer delete(f.visiting, callee)

	sig, _ := callee.Type().(*types.Signature)
	var errIndexes []int
	if sig != nil {
		for i := range sig.Results().Len() {
			if isErrorType(sig.Results().At(i).Type()) {
				errIndexes = append(errIndexes, i)
			}
		}
	}
	set := newErrorSet()
	if len(errIndexes) == 0 {
		set.unknown = true
		f.summaries[callee] = set
		return set
	}
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			set.add(f.returnErrors(fn, sig, node, errIndexes), nil)
		}
		return true
	})
	f.summaries[callee] = set
	return set
}

// returnErrors returns what a return statement hands back as errors.
func (f *errorFlow) returnErrors(fn typedFunc, sig *types.Signature, ret *ast.ReturnStmt, errIndexes []int) *errorSet {
	set := newErrorSet()
	switch {
	case len(ret.Results) == 0:
		for _, index := range errIndexes {
			named := sig.Results().At(index)
			if named.Name() == "" {
				return unknownErrors()
			}
			set.add(f.varErrors(fn, named, ret, 0), nil)
		}
	case len(ret.Results) == sig.Results().Len():
		for _, index := range errIndexes {
			set.add(f.exprErrors(fn, ret.Results[index], ret, 0), nil)
		}
	case len(ret.Results) == 1:
		call, ok := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
		if !ok {
			return unknownErrors()
		}
		set.add(f.callErrors(fn, call, ret), nil)
	default:
		return unknownErrors()
	}
	return set
}

// handledBefore returns the sentinels a guard before the node already took
// out of the variable: if v == S { return }, if errors.Is(v, S) { return },
// or the else branch of such a check.
func (f *errorFlow) handledBefore(fn typedFunc, v *types.Var, at ast.Node) map[*types.Var]bool {
	handled := map[*types.Var]bool{}
	path, _ := astutil.PathEnclosingInterval(fn.file.GoAST, at.Pos(), at.Pos())
	for i := 1; i < len(path); i++ {
		child := path[i-1]
		switch parent := path[i].(type) {
		case *ast.IfStmt:
			if parent.Else == child {
				for _, s := range f.guardSentinels(fn, v, parent.Cond) {
					handled[s] = true
				}
			}
		case *ast.BlockStmt:
			for j := len(parent.List) - 1; j >= 0; j-- {
				stmt := parent.List[j]
				if stmt.Pos() >= child.Pos() {
					continue
				}
				if assignsVar(fn.info, stmt, v) {
					break
				}
				guard, ok := stmt.(*ast.IfStmt)
				if !ok || guard.Else != nil || !terminates(guard.Body) {
					continue
				}
				for _, s := range f.guardSentinels(fn, v, guard.Cond) {
					handled[s] = true
				}
			}
		case *ast.FuncLit, *ast.FuncDecl:
			return handled
		}
	}
	return handled
}

// guardSentinels returns the sentinels a condition tests the variable for,
// alone or joined by ||.
func (f *errorFlow) guardSentinels(fn typedFunc, v *types.Var, cond ast.Expr) []*types.Var {
	switch c := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		switch c.Op {
		case token.LOR:
			return append(f.guardSentinels(fn, v, c.X), f.guardSentinels(fn, v, c.Y)...)
		case token.EQL:
			if variableOf(fn.info, ast.Unparen(c.X)) == v {
				if s := sentinelVar(fn.info, c.Y); s != nil {
					return []*types.Var{f.canonical(s)}
				}
			}
		}
	case *ast.CallExpr:
		if len(c.Args) == 2 && isPackageFuncCall(fn.file.GoAST, fn.info, c, "errors", "Is") && variableOf(fn.info, ast.Unparen(c.Args[0])) == v {
			if s := sentinelVar(fn.info, c.Args[1]); s != nil {
				return []*types.Var{f.canonical(s)}
			}
		}
	}
	return nil
}

// assignsVar reports a statement assigning the variable.
func assignsVar(info *types.Info, stmt ast.Stmt, v *types.Var) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && info.ObjectOf(ident) == v {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
