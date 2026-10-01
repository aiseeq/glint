package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewCloserNeverClosedRule())
}

// CloserNeverClosedRule detects a local variable that receives a closable
// value from a call and lets it go without closing it:
//
//	client := NewAPIClient(baseURL)
//	resp, err := client.Get("/health")
//	...
//	return nil // client.Close() never runs
//
// The value's type has Close() or Close() error, so it owns something —
// connections, a file, a goroutine — that only Close gives back. A variable
// that is closed, returned, stored, passed to a parameter that can be closed
// or captured by a function literal is someone else's to close and is not
// reported. Neither is a value the caller does not own: one a project
// function returns from a package variable or a field (a shared instance),
// one whose constructor registers a test Cleanup, a pipe of an exec.Cmd
// (Wait closes it), a reflect.Value, or anything opened in func main.
//
// Tests are checked too: a test client that is never closed keeps its
// connections for the rest of the run. In a test file, outside the typed
// load, only calls of the package functions of typed packages are resolved.
type CloserNeverClosedRule struct {
	*rules.BaseRule
}

// NewCloserNeverClosedRule creates the rule
func NewCloserNeverClosedRule() *CloserNeverClosedRule {
	return &CloserNeverClosedRule{BaseRule: rules.NewBaseRule(
		"closer-never-closed",
		"patterns",
		"Detects a local closable value from a call that is never closed, returned, stored, passed on or captured",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: a test file needs the project's typed packages to
// know what its calls return.
func (r *CloserNeverClosedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *CloserNeverClosedRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, tests included.
func (r *CloserNeverClosedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	project := &closerProject{index: newConstructorIndex(ctx), callees: newCloserCallees(ctx)}
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, project)
	})
}

// closerProject is what the rule knows about the project's functions.
type closerProject struct {
	index   *constructorIndex
	callees *closerCallees
}

// openedCloser is a local variable holding a closable value from a call.
type openedCloser struct {
	def      *ast.Ident
	at       ast.Node
	typeName string
	callee   string
	closed   bool
	escaped  bool
}

// closerScope names an untyped variable: by its function and name.
type closerScope struct {
	fn   *ast.FuncDecl
	name string
}

// closerUse is what one mention of the variable does with it.
type closerUse int

const (
	closerUseNone    closerUse = iota // reads it, compares it, calls its methods
	closerUseClosed                   // x.Close, called or as a method value
	closerUseEscapes                  // returned, stored, passed on
	closerUseOther                    // a field or key spelled like it (untyped files)
)

func (r *CloserNeverClosedRule) analyze(ctx *core.FileContext, info *types.Info, project *closerProject) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}
	if info == nil && !ctx.IsTestFile() {
		return nil // a production file outside the typed load is broken; its package rules say so
	}
	tracker := &closerTracker{ctx: ctx, info: info, project: project, byKey: make(map[any]*openedCloser)}
	var stack []ast.Node
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		tracker.visit(n, stack)
		return true
	})

	var violations []*core.Violation
	for _, c := range tracker.opened {
		if c.closed || c.escaped {
			continue
		}
		line := ctx.LineFor(c.at)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, fmt.Sprintf(
			"%s (%s) from %s is never closed, returned, stored or passed on — what it holds stays open",
			c.def.Name, c.typeName, c.callee))
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion(fmt.Sprintf("Close it where it is no longer needed: defer %s.Close() (t.Cleanup in a test)", c.def.Name))
		v.WithContext("variable", c.def.Name)
		violations = append(violations, v)
	}
	return violations
}

// closerTracker follows the closable variables of one file through their
// definitions and mentions.
type closerTracker struct {
	ctx     *core.FileContext
	info    *types.Info
	project *closerProject
	opened  []*openedCloser
	byKey   map[any]*openedCloser
}

// visit handles the node at the top of the stack.
func (t *closerTracker) visit(n ast.Node, stack []ast.Node) {
	switch node := n.(type) {
	case *ast.AssignStmt:
		if node.Tok == token.DEFINE && len(node.Rhs) == 1 {
			t.record(node.Lhs[0], node.Rhs[0], node, stack)
		}
	case *ast.ValueSpec:
		if len(node.Values) == 1 {
			t.record(node.Names[0], node.Values[0], node, stack)
		}
	case *ast.Ident:
		t.mention(node, stack)
	}
}

func (t *closerTracker) record(target ast.Expr, value ast.Expr, at ast.Node, stack []ast.Node) {
	ident, ok := target.(*ast.Ident)
	if !ok || ident.Name == "_" {
		return
	}
	call, ok := ast.Unparen(value).(*ast.CallExpr)
	if !ok {
		return
	}
	fn := enclosingFuncDecl(stack)
	if fn == nil || (fn.Recv == nil && fn.Name.Name == "main" && t.ctx.GoAST.Name.Name == "main") {
		return // package level, or func main: the process exit releases it
	}
	key, typeName := t.definition(ident, call, fn)
	if key == nil || t.byKey[key] != nil {
		return
	}
	c := &openedCloser{def: ident, at: at, typeName: typeName, callee: types.ExprString(call.Fun)}
	t.byKey[key] = c
	t.opened = append(t.opened, c)
}

// definition returns the key a definition of a closable value from a call is
// tracked by, and the value's type; a nil key when the variable is not one
// this rule follows.
func (t *closerTracker) definition(ident *ast.Ident, call *ast.CallExpr, fn *ast.FuncDecl) (any, string) {
	if t.info != nil {
		variable, ok := t.info.Defs[ident].(*types.Var)
		if !ok {
			return nil, ""
		}
		if tv, ok := t.info.Types[call.Fun]; ok && tv.IsType() {
			return nil, "" // a conversion: the value came from elsewhere
		}
		if !isCloserType(variable.Type()) {
			return nil, ""
		}
		// An interface method counts too: its package says whether it is
		// the project's.
		if callee, ok := typeutil.Callee(t.info, call).(*types.Func); ok && t.project.callees.notCallersToClose(callee) {
			return nil, ""
		}
		return variable, types.TypeString(variable.Type(), (*types.Package).Name)
	}
	// In an external test package an unqualified call names the test
	// package's own function, which the typed load does not have.
	if _, unqualified := call.Fun.(*ast.Ident); unqualified && strings.HasSuffix(t.ctx.GoAST.Name.Name, "_test") {
		return nil, ""
	}
	callee := t.project.index.resolveUntyped(t.ctx, call)
	if callee == nil || t.project.callees.notCallersToClose(callee) {
		return nil, ""
	}
	sig, ok := callee.Type().(*types.Signature)
	if !ok || sig.Results().Len() == 0 || !isCloserType(sig.Results().At(0).Type()) {
		return nil, ""
	}
	result := sig.Results().At(0).Type()
	return closerScope{fn: fn, name: ident.Name}, types.TypeString(result, (*types.Package).Name)
}

// lookup returns the tracked variable an identifier mentions, or nil.
func (t *closerTracker) lookup(ident *ast.Ident, stack []ast.Node) *openedCloser {
	if t.info != nil {
		return t.byKey[t.info.Uses[ident]]
	}
	fn := enclosingFuncDecl(stack)
	if fn == nil {
		return nil
	}
	c := t.byKey[closerScope{fn: fn, name: ident.Name}]
	if c == nil || ident == c.def || ident.Pos() < c.def.Pos() {
		return nil
	}
	return c
}

// mention notes what the identifier at the top of the stack does with the
// variable it names.
func (t *closerTracker) mention(ident *ast.Ident, stack []ast.Node) {
	c := t.lookup(ident, stack)
	if c == nil {
		return
	}
	use := closerUseOf(stack, t.info)
	if use == closerUseOther {
		return
	}
	if use != closerUseClosed && capturedFrom(stack, c.def.Pos()) {
		use = closerUseEscapes
	}
	switch use {
	case closerUseClosed:
		c.closed = true
	case closerUseEscapes:
		c.escaped = true
	}
}

// isCloserType reports a type whose values have Close() or Close() error,
// other than the SQL row cursors sql-rows-close follows and reflect.Value,
// whose Close closes the channel it holds.
func isCloserType(t types.Type) bool {
	if isRowsType(t) || isNamedFrom(derefType(t), "reflect") {
		return false
	}
	obj, _, _ := types.LookupFieldOrMethod(t, true, nil, "Close")
	method, ok := obj.(*types.Func)
	if !ok {
		return false
	}
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 {
		return false
	}
	switch sig.Results().Len() {
	case 0:
		return true
	case 1:
		return types.Identical(sig.Results().At(0).Type(), types.Universe.Lookup("error").Type())
	}
	return false
}

// isNamedFrom reports a named type declared in the package.
func isNamedFrom(t types.Type, pkgPath string) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == pkgPath
}

// closerUseOf classifies the mention of a tracked variable at the top of the
// stack. Without type information an argument always escapes; with it, only
// an argument bound to a parameter that can be closed does. A closable field
// of the variable carries it on: db := client.DB; defer db.Close().
func closerUseOf(stack []ast.Node, info *types.Info) closerUse {
	current := stack[len(stack)-1]
	viaField := false
	for i := len(stack) - 2; i >= 0; i-- {
		switch parent := stack[i].(type) {
		case *ast.ParenExpr:
			current = parent
			continue
		case *ast.SelectorExpr:
			if parent.X != current {
				return closerUseOther
			}
			if parent.Sel.Name == "Close" {
				return closerUseClosed
			}
			if !closerField(parent, info) {
				return closerUseNone
			}
			current, viaField = parent, true
			continue
		case *ast.KeyValueExpr:
			if parent.Key == current && info == nil {
				return closerUseOther
			}
			return closerUseEscapes
		case *ast.BinaryExpr, *ast.IncDecStmt, *ast.StarExpr, *ast.IndexExpr:
			return closerUseNone
		case *ast.AssignStmt:
			return closerAssignUse(parent, current)
		case *ast.CallExpr:
			if parent.Fun == current {
				return closerUseNone
			}
			return closerArgUse(parent, current, info)
		case *ast.ReturnStmt, *ast.CompositeLit, *ast.SendStmt, *ast.UnaryExpr, *ast.ValueSpec:
			return closerUseEscapes
		}
		if viaField {
			return closerUseNone // a field read in a condition or a switch
		}
		return closerUseEscapes
	}
	return closerUseNone
}

// closerField reports a selector that reads a field able to carry the
// resource on. Without type information any selector might.
func closerField(sel *ast.SelectorExpr, info *types.Info) bool {
	if info == nil {
		return true
	}
	selection, ok := info.Selections[sel]
	return ok && selection.Kind() == types.FieldVal && isCloserType(selection.Type())
}

// closerAssignUse classifies a mention inside an assignment: a target is
// overwritten, a value is stored.
func closerAssignUse(assign *ast.AssignStmt, current ast.Node) closerUse {
	for _, lhs := range assign.Lhs {
		if lhs == current {
			return closerUseNone
		}
	}
	return closerUseEscapes
}

// closerArgUse classifies a tracked variable passed as an argument: a
// parameter that can be closed takes it over, one typed as any or io.Reader
// only looks at it.
func closerArgUse(call *ast.CallExpr, arg ast.Node, info *types.Info) closerUse {
	if info == nil {
		return closerUseEscapes
	}
	if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
		return closerUseEscapes // a conversion carries the value on
	}
	for index, candidate := range call.Args {
		if candidate != arg {
			continue
		}
		param := parameterType(info, call, index)
		if param != nil && !hasCloseMethod(param) {
			return closerUseNone
		}
	}
	return closerUseEscapes
}

// capturedFrom reports whether the mention at the top of the stack sits in
// a function literal that does not also hold the definition at pos.
func capturedFrom(stack []ast.Node, pos token.Pos) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		if lit, ok := stack[i].(*ast.FuncLit); ok && (pos < lit.Pos() || pos >= lit.End()) {
			return true
		}
	}
	return false
}

// enclosingFuncDecl returns the declared function the stack runs through.
func enclosingFuncDecl(stack []ast.Node) *ast.FuncDecl {
	for i := len(stack) - 1; i >= 0; i-- {
		if fn, ok := stack[i].(*ast.FuncDecl); ok {
			return fn
		}
	}
	return nil
}

// closerCallees answers whether the closable value a function returns is the
// caller's to close: by the body for the functions of the typed packages, by
// the name for the rest.
type closerCallees struct {
	decls    map[*types.Func]closerCalleeDecl
	memo     map[*types.Func]bool
	packages map[string]bool // import paths of the typed packages
}

type closerCalleeDecl struct {
	decl *ast.FuncDecl
	info *types.Info
}

func newCloserCallees(ctx *core.GoProjectContext) *closerCallees {
	callees := &closerCallees{
		decls:    make(map[*types.Func]closerCalleeDecl),
		memo:     make(map[*types.Func]bool),
		packages: make(map[string]bool),
	}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		callees.packages[pkg.Package.PkgPath] = true
		info := pkg.Package.TypesInfo
		for _, fileCtx := range pkg.Files {
			if fileCtx == nil || fileCtx.GoAST == nil {
				continue
			}
			for _, decl := range fileCtx.GoAST.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				if fn, ok := info.Defs[fd.Name].(*types.Func); ok {
					callees.decls[fn] = closerCalleeDecl{decl: fd, info: info}
				}
			}
		}
	}
	return callees
}

// notCallersToClose reports a callee whose result the caller does not own:
// a method of exec.Cmd (Wait closes its pipes), a function outside the
// project whose name does not say it creates the value (a shared connection
// getter), a project function that returns a shared instance or hands the
// value to a test Cleanup itself.
func (c *closerCallees) notCallersToClose(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	fn = fn.Origin()
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil && isNamedFrom(derefType(sig.Recv().Type()), "os/exec") {
		return true
	}
	if fn.Pkg() != nil && !c.packages[fn.Pkg().Path()] {
		return !createsResource(fn.Name())
	}
	if known, ok := c.memo[fn]; ok {
		return known
	}
	d, ok := c.decls[fn]
	keeps := ok && (registersCleanup(d.decl.Body) || returnsSharedValue(d.decl.Body, d.info))
	c.memo[fn] = keeps
	return keeps
}

// resourceCreatingPrefixes start the names of the functions that hand the
// caller a value of its own to close.
var resourceCreatingPrefixes = []string{"New", "Open", "Dial", "Connect", "Create", "Acquire", "Begin"}

func createsResource(name string) bool {
	for _, prefix := range resourceCreatingPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func derefType(t types.Type) types.Type {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		return ptr.Elem()
	}
	return t
}

// registersCleanup reports a body that calls a Cleanup method — a test
// helper that closes what it returns when the test ends.
func registersCleanup(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Cleanup" {
				found = true
			}
		}
		return !found
	})
	return found
}

// returnsSharedValue reports a body whose every return of a value hands out
// one that outlives the call: a package variable, a field, or a local the
// body also stored somewhere.
func returnsSharedValue(body *ast.BlockStmt, info *types.Info) bool {
	decided, shared := false, true
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) == 0 {
				return true
			}
			result := ast.Unparen(node.Results[0])
			if ident, ok := result.(*ast.Ident); ok && ident.Name == "nil" {
				return true
			}
			decided = true
			if !sharedValue(result, body, info) {
				shared = false
			}
		}
		return true
	})
	return decided && shared
}

func sharedValue(expr ast.Expr, body *ast.BlockStmt, info *types.Info) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		variable, ok := info.Uses[e].(*types.Var)
		if !ok {
			return false
		}
		return isPackageLevelVar(variable) || storedOutside(body, info, variable)
	case *ast.SelectorExpr:
		if selection, ok := info.Selections[e]; ok {
			return selection.Kind() == types.FieldVal
		}
		variable, ok := info.Uses[e.Sel].(*types.Var)
		return ok && isPackageLevelVar(variable)
	}
	return false
}

// storedOutside reports a local the body also assigns to a field, an
// element or a package variable.
func storedOutside(body *ast.BlockStmt, info *types.Info, variable *types.Var) bool {
	stored := false
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return !stored
		}
		for i, rhs := range assign.Rhs {
			if ident, ok := ast.Unparen(rhs).(*ast.Ident); !ok || info.Uses[ident] != variable {
				continue
			}
			switch target := assign.Lhs[i].(type) {
			case *ast.SelectorExpr, *ast.IndexExpr:
				stored = true
			case *ast.Ident:
				if v, ok := info.Uses[target].(*types.Var); ok && isPackageLevelVar(v) {
					stored = true
				}
			}
		}
		return !stored
	})
	return stored
}
