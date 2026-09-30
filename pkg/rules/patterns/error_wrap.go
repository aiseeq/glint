package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"path"
	"slices"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorWrapRule())
}

// ErrorWrapRule detects errors from foreign code returned without context:
// the project's own functions are checked where their errors arise.
type ErrorWrapRule struct {
	*rules.BaseRule
}

// NewErrorWrapRule creates the rule
func NewErrorWrapRule() *ErrorWrapRule {
	return &ErrorWrapRule{
		BaseRule: rules.NewBaseRule(
			"error-wrap",
			"patterns",
			"Detects errors from the standard library or other modules returned without adding context (should use fmt.Errorf with %w)",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
// Outside a project only the standard library is known to be foreign code.
func (r *ErrorWrapRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil, projectCode{})
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ErrorWrapRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, test files included; parameter types
// are resolved wherever the project declares them.
func (r *ErrorWrapRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	own := newProjectCode(ctx)
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, own)
	})
}

// analyze checks for unwrapped error returns. info is nil for a file without
// type information; own tells the project's packages from foreign ones.
func (r *ErrorWrapRule) analyze(ctx *core.FileContext, info *types.Info, own projectCode) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !r.returnsError(fn) {
			continue
		}
		// Error branches anywhere in the body — loops, switch cases, nested
		// ifs; a closure returns through its own signature.
		forEachOwnStatementList(fn.Body, func(list []ast.Stmt) {
			for i, stmt := range list {
				ifStmt, ok := stmt.(*ast.IfStmt)
				if !ok {
					continue
				}
				violations = append(violations, r.checkErrorBranch(ctx, info, own, fn, ifStmt, list[:i])...)
			}
		})
	}

	return violations
}

// checkErrorBranch reports bare returns of the checked error from an
// `if err != nil` branch; before holds the statements preceding the if in its
// block, where the error was produced.
func (r *ErrorWrapRule) checkErrorBranch(ctx *core.FileContext, info *types.Info, own projectCode, fn *ast.FuncDecl, ifStmt *ast.IfStmt, before []ast.Stmt) []*core.Violation {
	errName := errNilCheckName(ifStmt.Cond)
	if errName == "" {
		return nil
	}

	// Delegating to the same method on an embedded type is a pass
	// through, not a lost context: the caller of this method adds the
	// context, and wrapping here would duplicate it.
	call := errorSourceCall(info, fn, ifStmt, before, errName)
	if callee := callName(call); callee != "" && callee == fn.Name.Name {
		return nil
	}
	// Closure-runners (RunInTx-style calls taking a func literal) and
	// caller-supplied callback parameters are transparent pass-throughs:
	// context is added inside the closure/callback, and wrapping outside
	// would prefix every propagated error and obscure sentinel errors.
	if isClosureRunnerCall(call) || callsCallbackParam(call, fn, info) {
		return nil
	}
	// Only an error from foreign code lacks context: a function of the
	// project is checked by this rule where its own errors arise.
	origin, crosses := errorFromForeignCode(ctx.GoAST, info, own, call)
	if !crosses || returnsToCallingPackage(info, fn, call) {
		return nil
	}

	var violations []*core.Violation
	for i, bodyStmt := range ifStmt.Body.List {
		retStmt, ok := bodyStmt.(*ast.ReturnStmt)
		if !ok || !isBareErrorReturn(retStmt, errName) {
			continue
		}
		// `err = fmt.Errorf("...: %w", err)` earlier in the branch: the
		// returned variable no longer holds the bare error.
		if reassignsName(ifStmt.Body.List[:i], errName) {
			return violations
		}
		pos := ctx.PositionFor(retStmt)
		v := r.CreateViolation(ctx.RelPath, pos.Line, fmt.Sprintf(
			"Error from %s returned without context; say what failed with fmt.Errorf", origin))
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Use fmt.Errorf(\"context: %w\", err) to add context")
		violations = append(violations, v)
	}
	return violations
}

// reassignsName reports whether any of the statements, nested blocks included
// and function literals excluded, assigns the named variable.
func reassignsName(stmts []ast.Stmt, name string) bool {
	found := false
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.AssignStmt:
				if assignsName(node, name) {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

// returnsToCallingPackage reports whether fn is a hook of the package that
// produced the error — a method implementing an interface that package
// declares, such as json.Unmarshaler around json.Unmarshal — so the error
// goes back to that package, which reports it with its own context.
func returnsToCallingPackage(info *types.Info, fn *ast.FuncDecl, call *ast.CallExpr) bool {
	if info == nil || fn.Recv == nil {
		return false
	}
	method, ok := info.Defs[fn.Name].(*types.Func)
	callee := typeutil.Callee(info, call)
	if !ok || callee == nil || callee.Pkg() == nil {
		return false
	}
	recv := method.Signature().Recv().Type()
	scope := callee.Pkg().Scope()
	for _, name := range scope.Names() {
		typeName, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || !typeName.Exported() {
			continue
		}
		iface, ok := typeName.Type().Underlying().(*types.Interface)
		if !ok || !declaresMethod(iface, method.Name()) {
			continue
		}
		if types.Implements(recv, iface) {
			return true
		}
	}
	return false
}

// declaresMethod reports whether the interface has a method of that name.
func declaresMethod(iface *types.Interface, name string) bool {
	for i := range iface.NumMethods() {
		if iface.Method(i).Name() == name {
			return true
		}
	}
	return false
}

// returnsError checks if function has error in return types
func (r *ErrorWrapRule) returnsError(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}

	for _, result := range fn.Type.Results.List {
		if ident, ok := result.Type.(*ast.Ident); ok {
			if ident.Name == "error" {
				return true
			}
		}
	}

	return false
}

// isBareErrorReturn checks if the return hands the checked error back as is:
// its last result is the error variable itself.
func isBareErrorReturn(ret *ast.ReturnStmt, errName string) bool {
	if len(ret.Results) == 0 {
		return false
	}
	ident, ok := ret.Results[len(ret.Results)-1].(*ast.Ident)
	return ok && ident.Name == errName
}

// errorSourceCall returns the call that produced the error the if-statement
// checks, looking at the statement's own initializer first and then at the
// preceding statements of its block. With type information an error assigned
// outside that block is found as the latest earlier assignment to the same
// variable in the function. It returns nil when the source is not a call or
// cannot be identified.
func errorSourceCall(info *types.Info, fn *ast.FuncDecl, ifStmt *ast.IfStmt, before []ast.Stmt, errName string) *ast.CallExpr {
	if init, ok := ifStmt.Init.(*ast.AssignStmt); ok && assignsName(init, errName) {
		return assignedCall(init)
	}
	for i := len(before) - 1; i >= 0; i-- {
		previous, ok := before[i].(*ast.AssignStmt)
		if !ok || !assignsName(previous, errName) {
			continue
		}
		return assignedCall(previous)
	}
	if info == nil {
		return nil
	}
	return latestAssignedCall(info, fn, ifStmt, errName)
}

// latestAssignedCall finds the last assignment before ifStmt that binds the
// error variable ifStmt checks, and returns its call.
func latestAssignedCall(info *types.Info, fn *ast.FuncDecl, ifStmt *ast.IfStmt, errName string) *ast.CallExpr {
	target := errVarObject(info, ifStmt, errName)
	if target == nil {
		return nil
	}
	var latest *ast.AssignStmt
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Pos() >= ifStmt.Pos() {
			return true
		}
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && info.ObjectOf(ident) == target {
				latest = assign
			}
		}
		return true
	})
	if latest == nil {
		return nil
	}
	return assignedCall(latest)
}

// errVarObject returns the variable the `errName != nil` condition reads.
func errVarObject(info *types.Info, ifStmt *ast.IfStmt, errName string) types.Object {
	bin, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok {
		return nil
	}
	ident, ok := bin.X.(*ast.Ident)
	if !ok || ident.Name != errName {
		return nil
	}
	return info.Uses[ident]
}

// errorFromForeignCode reports whether the error returned by call comes from
// code outside the project: the standard library or another module, called as
// a function, a method (an interface method counts where its interface is
// declared) or a func-typed field. The project's own functions are left out:
// this rule checks them where their errors arise, so an error they wrapped is
// not reported again at every caller. Calls whose callee cannot be resolved
// and errors that describe themselves (constructors, context cancellation)
// are not reported either. Without type information only a call qualified by
// an imported package name counts. The first result names the callee.
func errorFromForeignCode(file *ast.File, info *types.Info, own projectCode, call *ast.CallExpr) (string, bool) {
	if call == nil {
		return "", false
	}
	if info == nil {
		return untypedForeignCall(file, own, call)
	}
	callee := typeutil.Callee(info, call)
	if callee == nil || callee.Pkg() == nil || isSelfDescribingError(callee.Pkg().Path(), callee.Name()) {
		return "", false
	}
	if !own.isForeign(callee.Pkg().Path()) {
		return "", false
	}
	return calleeLabel(callee), true
}

// calleeLabel names a callee the way a reader writes it: pkg.Func or
// (Recv).Method with package names, not paths.
func calleeLabel(callee types.Object) string {
	byName := func(p *types.Package) string { return p.Name() }
	if fn, ok := callee.(*types.Func); ok {
		if recv := fn.Signature().Recv(); recv != nil {
			return "(" + types.TypeString(recv.Type(), byName) + ")." + fn.Name()
		}
	}
	return callee.Pkg().Name() + "." + callee.Name()
}

// selfDescribingErrors are the callees whose error needs no call-site context:
// constructors build the context themselves, and a context's Err reports the
// caller's own cancellation.
var selfDescribingErrors = map[string]map[string]bool{
	"fmt":     {"Errorf": true},
	"errors":  {"New": true, "Join": true, "Unwrap": true},
	"context": {"Err": true, "Cause": true},
	"github.com/pkg/errors": {
		"New": true, "Errorf": true, "Wrap": true, "Wrapf": true,
		"WithMessage": true, "WithMessagef": true, "WithStack": true,
	},
	"golang.org/x/xerrors": {"New": true, "Errorf": true},
}

// isSelfDescribingError reports whether the callee pkgPath.name returns an
// error that needs no call-site context.
func isSelfDescribingError(pkgPath, name string) bool {
	return selfDescribingErrors[pkgPath][name]
}

// untypedForeignCall reports whether call is qualified by a name the file
// imports from foreign code: an explicit alias or the last element of the
// import path. A package whose name differs from its path is not guessed at.
func untypedForeignCall(file *ast.File, own projectCode, call *ast.CallExpr) (string, bool) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || file == nil {
		return "", false
	}
	qualifier, ok := sel.X.(*ast.Ident)
	if !ok || qualifier.Obj != nil {
		return "", false
	}
	for _, spec := range file.Imports {
		// The parser admits only a plain string literal as an import path.
		importPath := strings.Trim(spec.Path.Value, "\"`")
		name := path.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != qualifier.Name {
			continue
		}
		if isSelfDescribingError(importPath, sel.Sel.Name) || !own.isForeign(importPath) {
			return "", false
		}
		return qualifier.Name + "." + sel.Sel.Name, true
	}
	return "", false
}

// callName returns the (selector) name of the called function, "" if unknown.
func callName(call *ast.CallExpr) string {
	if call == nil {
		return ""
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// isClosureRunnerCall reports whether the call takes a func literal argument
// (RunInTx-style runner executing caller-provided code).
func isClosureRunnerCall(call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	for _, arg := range call.Args {
		if _, ok := arg.(*ast.FuncLit); ok {
			return true
		}
	}
	return false
}

// callsCallbackParam reports whether the call invokes a parameter of the
// enclosing function (the callback owns its error context). A parameter that
// is called is func-typed whatever its type is named or wherever that type is
// declared, so a named func type needs no resolution. Type information only
// tells a parameter from a local variable that shadows it.
func callsCallbackParam(call *ast.CallExpr, fn *ast.FuncDecl, info *types.Info) bool {
	if call == nil || fn.Type.Params == nil {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	if info != nil {
		param, ok := info.Uses[ident].(*types.Var)
		return ok && param.Pos() >= fn.Type.Params.Pos() && param.Pos() < fn.Type.Params.End()
	}
	for _, param := range fn.Type.Params.List {
		for _, name := range param.Names {
			if name.Name == ident.Name {
				return true
			}
		}
	}
	return false
}

// assignsName reports whether the assignment binds the named variable.
func assignsName(assign *ast.AssignStmt, name string) bool {
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name == name {
			return true
		}
	}
	return false
}

// assignedCall returns the call on the right-hand side of an assignment.
func assignedCall(assign *ast.AssignStmt) *ast.CallExpr {
	if len(assign.Rhs) != 1 {
		return nil
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil
	}
	return call
}

// projectCode tells the project's own packages from foreign ones: the modules
// and packages the analysis loaded. Empty, it knows no project, and only the
// standard library is foreign.
type projectCode struct {
	modules  []string
	packages map[string]bool
}

// newProjectCode collects the modules and packages of a loaded project.
func newProjectCode(ctx *core.GoProjectContext) projectCode {
	own := projectCode{packages: make(map[string]bool)}
	if ctx == nil {
		return own
	}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		own.packages[pkg.Package.PkgPath] = true
		if mod := pkg.Package.Module; mod != nil && mod.Path != "" && !slices.Contains(own.modules, mod.Path) {
			own.modules = append(own.modules, mod.Path)
		}
	}
	return own
}

// isForeign reports whether the package at pkgPath lies outside the project.
func (own projectCode) isForeign(pkgPath string) bool {
	if own.packages[pkgPath] {
		return false
	}
	for _, mod := range own.modules {
		if pkgPath == mod || strings.HasPrefix(pkgPath, mod+"/") {
			return false
		}
	}
	if len(own.packages) == 0 {
		return isStandardLibraryPath(pkgPath)
	}
	return true
}

// isStandardLibraryPath reports whether an import path names a standard
// library package: its first element has no dot, unlike a module host.
func isStandardLibraryPath(pkgPath string) bool {
	first, _, _ := strings.Cut(pkgPath, "/")
	return !strings.Contains(first, ".")
}
