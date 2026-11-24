package qarules

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewSelfExecInTestRule())
}

// SelfExecInTestRule reports a start of the process's own executable on a
// path a test of the module reaches.
//
// Under go test the own executable - os.Executable(), os.Args[0] - is the
// package's .test binary. Started with a subcommand, it stops parsing flags
// at the positional argument and runs every test again; the test that started
// it runs in the child too and starts the next copy. A real case: a check
// handed os.Executable() to the detached launcher of another package to run
// a cleanup subcommand, a test reached the check, and the copies took down
// the machine.
//
// The value is followed from os.Executable(), os.Args[0], a function of the
// module returning one of them, and filepath.Clean, Abs or EvalSymlinks of
// one, through local variables and the parameters of module functions, to
// exec.Command, exec.CommandContext, an exec.Cmd literal's Path,
// os.StartProcess and syscall.Exec, ForkExec and StartProcess. The reach
// starts at the Test, Benchmark, Fuzz and run Example functions and TestMain
// of the module's test files and follows static calls; a call from a test
// file is resolved by name, as the typed load holds no test files. Calls in a
// function literal the code only stores - a field of a command, a variable -
// are not followed.
//
// Not reported: a path where testing.Testing() is true refuses the launch (in
// the launching function, a caller or the launcher); a function that starts
// itself with -test.run in its arguments (the helper process runs one test),
// and the child branch of such a test, which runs in that helper;
// a test binary whose TestMain answers the child by its arguments or
// environment and exits before m.Run; a launch of another binary. The own
// executable as the fallback of an environment variable - read into the
// same variable, or returned by the same function - is reported only from a
// test that does not set the variable to a value (t.Setenv or os.Setenv, in
// the test or a function of the test files it calls): the tests of a tool
// point it at a stand-in binary that way. A test that names the function of
// a multi-call binary by a constant reaches only that case of the switch on
// the name.
type SelfExecInTestRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewSelfExecInTestRule creates the rule.
func NewSelfExecInTestRule() *SelfExecInTestRule {
	return &SelfExecInTestRule{BaseRule: rules.NewBaseRule("self-exec-in-test", "patterns",
		"Detects a start of the process's own executable (os.Executable, os.Args[0]) on a path a test reaches — under go test that is the test binary, which runs every test again and starts the next copy",
		core.SeverityHigh)}
}

// AnalyzeFile is a no-op: the check needs the whole project.
func (r *SelfExecInTestRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough.
func (r *SelfExecInTestRule) RequiresSSA() bool { return false }

// AnalyzeGoProject follows the own executable to the launches the tests reach.
func (r *SelfExecInTestRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	decls, err := patternkit.FuncDeclsByObject(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	a := newSelfExecAnalysis(ctx, decls)
	if !a.mentionsSelf() {
		return nil, nil
	}
	a.summarize()
	var violations []*core.Violation
	for _, found := range a.reached() {
		if v := r.violation(ctx, found); v != nil {
			violations = append(violations, v)
		}
	}
	slices.SortFunc(violations, func(x, y *core.Violation) int {
		return cmp.Or(cmp.Compare(x.File, y.File), cmp.Compare(x.Line, y.Line))
	})
	return violations, nil
}

func (r *SelfExecInTestRule) violation(ctx *core.GoProjectContext, found selfExecFinding) *core.Violation {
	// A start outside the files of the project has no file to report in.
	if fileCtx, err := ctx.FileForPosition(found.point.call.Pos()); err == nil && ctx.IsReportFile(fileCtx) {
		return r.violationIn(fileCtx, found)
	}
	return nil
}

func (r *SelfExecInTestRule) violationIn(fileCtx *core.FileContext, found selfExecFinding) *core.Violation {
	line := fileCtx.LineFor(found.point.call)
	v := r.CreateViolation(fileCtx.RelPath, line, fmt.Sprintf(
		"%s starts its own test binary: %s passes the process's own executable to %s, reached through %s — under go test that binary runs every test again, and each copy starts the next",
		found.chain[0], found.chain[len(found.chain)-1], found.point.via, strings.Join(found.chain, " → ")))
	v.WithCode(fileCtx.GetLine(line))
	v.WithSuggestion("Refuse the launch when testing.Testing() is true, let the tests replace the launcher, or start a helper process: -test.run=TestHelperProcess in its arguments, or a TestMain that answers the child by its argument or environment before m.Run")
	v.WithContext("test", found.chain[0])
	return v
}

// selfExecBody is a function body the analysis reads: a typed function of
// the module, or a function of a test file, which has no type information.
type selfExecBody struct {
	decl *ast.FuncDecl
	// info is the type information of a typed body, nil in a test file.
	info *types.Info
	// file is the syntax of a test file, nil for a typed body.
	file *ast.File
	// tests is the test package of a test file body.
	tests *selfExecTestPkg
	// pkg is the import path of a typed body, pkgName the name of its package.
	pkg, pkgName string
	params       []any
	variadic     bool
	facts        *selfExecFacts
	state        *selfExecState
	// locals are the names a test file body declares, found on first use.
	locals map[string]bool
}

// name is the body's name in a chain, qualified by its package when the
// package is not the one of the previous element.
func (b *selfExecBody) name(prev *selfExecBody) string {
	name := patternkit.QualifiedFuncName(b.decl)
	if prev != nil && prev.pkgName != b.pkgName {
		return b.pkgName + "." + name
	}
	return name
}

// key identifies a variable a body names: its object in a typed body, its
// name in a test file.
func (b *selfExecBody) key(expr ast.Expr) any {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok || id.Name == "_" {
		return nil
	}
	if b.info == nil {
		return id.Name
	}
	if v, ok := b.info.ObjectOf(id).(*types.Var); ok {
		return v
	}
	return nil
}

// paramKeys lists the keys of the parameters in order.
func (b *selfExecBody) paramKeys() {
	params := b.decl.Type.Params
	if params == nil {
		return
	}
	for _, field := range params.List {
		if _, ok := field.Type.(*ast.Ellipsis); ok {
			b.variadic = true
		}
		if len(field.Names) == 0 {
			b.params = append(b.params, nil)
		}
		for _, name := range field.Names {
			b.params = append(b.params, b.key(name))
		}
	}
}

// selfExecFacts is what a path a test can take through a body does: the
// assignments, returns, calls and exec.Cmd literals on it.
type selfExecFacts struct {
	assigns []selfExecAssign
	returns [][]ast.Expr
	calls   []*ast.CallExpr
	cmdLits []*ast.CompositeLit
	// helper reports a body that passes -test.run: it starts a helper process.
	helper bool
}

type selfExecAssign struct {
	lhs []any
	rhs []ast.Expr
}

// selfExecState is what a body's variables hold: the own executable, with
// the environment variables it is the fallback of, or a parameter.
type selfExecState struct {
	self    map[any][]string
	paramOf map[any][]int
	// envOf holds the environment variables a variable is read from.
	envOf map[any][]string
}

// selfExecValue is what an expression holds: the own executable, standing
// in for the environment variables in env when they are empty, and the
// parameters of the body it copies.
type selfExecValue struct {
	self   bool
	env    []string
	params []int
}

// selfExecPoint is a call of a body that starts the own executable: a launch
// given it as the path, or a call that passes it to a launcher parameter.
// env names the environment variables a test sets to start another binary.
type selfExecPoint struct {
	call ast.Node
	via  string
	env  []string
}

type selfExecFinding struct {
	point selfExecPoint
	chain []string
}

type selfExecAnalysis struct {
	ctx      *core.GoProjectContext
	decls    map[*types.Func]patternkit.TypedFuncDecl
	typed    map[*types.Func]*selfExecBody
	bodies   []*selfExecBody
	pkgLevel []*selfExecBody
	index    *selfExecIndex
	resolved map[*ast.CallExpr][]*selfExecBody

	// selfVars are the package variables that hold the own executable.
	selfVars map[any]bool
	// selfResult holds the functions that return the own executable, with
	// the environment variables it is the fallback of.
	selfResult map[*selfExecBody][]string
	sinks      map[*selfExecBody]map[int]bool
	// setsEnv holds the environment variables a test body sets to a value,
	// itself or through the functions of the test files it calls.
	setsEnv map[*selfExecBody]map[string]bool
	// dispatchInfo holds the switches on a name, found on first use.
	dispatchInfo *selfExecDispatch
}

func newSelfExecAnalysis(ctx *core.GoProjectContext, decls map[*types.Func]patternkit.TypedFuncDecl) *selfExecAnalysis {
	a := &selfExecAnalysis{
		ctx: ctx, decls: decls,
		typed:      map[*types.Func]*selfExecBody{},
		resolved:   map[*ast.CallExpr][]*selfExecBody{},
		selfVars:   map[any]bool{},
		selfResult: map[*selfExecBody][]string{},
		sinks:      map[*selfExecBody]map[int]bool{},
		setsEnv:    map[*selfExecBody]map[string]bool{},
	}
	a.index = newSelfExecIndex(a)
	return a
}

// mentionsSelf reports whether any body names os.Executable or os.Args:
// without them there is nothing to follow.
func (a *selfExecAnalysis) mentionsSelf() bool {
	var nodes []ast.Node
	for _, b := range a.bodies {
		nodes = append(nodes, b.decl.Body)
	}
	for _, level := range a.pkgLevel {
		for _, assign := range level.facts.assigns {
			for _, value := range assign.rhs {
				nodes = append(nodes, value)
			}
		}
	}
	return slices.ContainsFunc(nodes, func(node ast.Node) bool {
		found := false
		ast.Inspect(node, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Executable" || sel.Sel.Name == "Args") {
				found = true
			}
			return !found
		})
		return found
	})
}

// summarize finds, to a fixed point, the functions that return the own
// executable and the parameters that reach a launch.
func (a *selfExecAnalysis) summarize() {
	for changed := true; changed; {
		changed = false
		for _, b := range a.pkgLevel {
			changed = a.updateSelf(b) || changed
		}
		for _, b := range a.bodies {
			changed = a.updateSelf(b) || changed
			changed = a.updateSummary(b) || changed
		}
	}
}

// updateSelf recomputes the variables of a body that hold the own
// executable and reports a package variable newly found to hold it.
func (a *selfExecAnalysis) updateSelf(b *selfExecBody) bool {
	facts := a.facts(b)
	if b.state == nil {
		b.state = &selfExecState{self: map[any][]string{}, paramOf: a.paramAliases(b, facts), envOf: selfExecEnvVars(b, facts)}
	}
	changed := false
	for grown := true; grown; {
		grown = false
		for _, assign := range facts.assigns {
			for i, key := range assign.lhs {
				if key == nil || b.state.self[key] != nil || a.selfVars[key] {
					continue
				}
				value := a.origin(b, selfExecAssigned(assign, i))
				if !value.self {
					continue
				}
				b.state.self[key], grown = selfExecUnion([]string{}, value.env, b.state.envOf[key]), true
				if v, ok := key.(*types.Var); ok && v.Parent() == v.Pkg().Scope() {
					a.selfVars[key], changed = true, true
				}
			}
		}
	}
	return changed
}

// selfExecAssigned returns the expression the i-th target of an assignment
// receives, or the first result of the call that is assigned to it; nil for
// a later result.
func selfExecAssigned(assign selfExecAssign, i int) ast.Expr {
	if len(assign.rhs) == len(assign.lhs) {
		return assign.rhs[i]
	}
	if len(assign.rhs) == 1 && i == 0 {
		return assign.rhs[0]
	}
	return nil
}

// selfExecEnvVars maps the variables of a body read from the environment
// to the names of the variables they are read from.
func selfExecEnvVars(b *selfExecBody, facts *selfExecFacts) map[any][]string {
	envOf := map[any][]string{}
	for _, assign := range facts.assigns {
		for i, key := range assign.lhs {
			if name, ok := selfExecEnvRead(b, selfExecAssigned(assign, i)); ok && key != nil {
				envOf[key] = selfExecUnion(envOf[key], []string{name})
			}
		}
	}
	return envOf
}

// selfExecEnvRead returns the name of the environment variable an
// os.Getenv or os.LookupEnv call reads.
func selfExecEnvRead(b *selfExecBody, expr ast.Expr) (string, bool) {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return "", false
	}
	if name, ok := patternkit.PackageFuncName(b.file, b.info, call, "os"); !ok || (name != "Getenv" && name != "LookupEnv") {
		return "", false
	}
	return selfExecString(b, call.Args[0])
}

// selfExecString returns the value of a string constant.
func selfExecString(b *selfExecBody, expr ast.Expr) (string, bool) {
	if b.info != nil {
		if tv, ok := b.info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
			return constant.StringVal(tv.Value), true
		}
		return "", false
	}
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

// selfExecUnion adds the names of extra to names, once each.
func selfExecUnion(names []string, extra ...[]string) []string {
	for _, list := range extra {
		for _, name := range list {
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}

// paramAliases maps the variables of a body that copy a parameter to the
// parameter's index.
func (a *selfExecAnalysis) paramAliases(b *selfExecBody, facts *selfExecFacts) map[any][]int {
	aliases := map[any][]int{}
	for i, key := range b.params {
		if key != nil {
			aliases[key] = append(aliases[key], i)
		}
	}
	for grown := true; grown; {
		grown = false
		for _, assign := range facts.assigns {
			if len(assign.lhs) != len(assign.rhs) {
				continue
			}
			for i, key := range assign.lhs {
				from := aliases[b.key(selfExecPathOperand(b, assign.rhs[i]))]
				if key == nil || len(from) == 0 || len(aliases[key]) > 0 {
					continue
				}
				aliases[key], grown = from, true
			}
		}
	}
	return aliases
}

// updateSummary records whether a body returns the own executable and which
// of its parameters reach a launch; it reports a change.
func (a *selfExecAnalysis) updateSummary(b *selfExecBody) bool {
	changed := false
	if a.selfResult[b] == nil {
		if env, ok := a.returnsSelf(b); ok {
			a.selfResult[b], changed = env, true
		}
	}
	a.eachLaunchArg(b, func(arg ast.Expr, _ string) {
		for _, p := range a.origin(b, arg).params {
			if !a.sinks[b][p] {
				if a.sinks[b] == nil {
					a.sinks[b] = map[int]bool{}
				}
				a.sinks[b][p], changed = true, true
			}
		}
	})
	return changed
}

// returnsSelf reports whether a body returns the own executable, with the
// environment variables it is the fallback of: those of the own path and
// those another return of the body hands back instead.
func (a *selfExecAnalysis) returnsSelf(b *selfExecBody) ([]string, bool) {
	self := false
	env := []string{}
	for _, results := range a.facts(b).returns {
		if len(results) == 0 {
			continue
		}
		value := a.origin(b, results[0])
		self = self || value.self
		env = selfExecUnion(env, value.env)
		if name, ok := selfExecEnvRead(b, results[0]); ok {
			env = selfExecUnion(env, []string{name})
		}
		if key := b.key(results[0]); key != nil && b.state.self[key] == nil {
			env = selfExecUnion(env, b.state.envOf[key])
		}
	}
	return env, self
}

// eachLaunchArg hands visit every expression a body gives a launch as the
// path of the binary, directly or through a parameter of a module function
// that reaches one, with the name of the call.
func (a *selfExecAnalysis) eachLaunchArg(b *selfExecBody, visit func(arg ast.Expr, via string)) {
	facts := a.facts(b)
	for _, call := range facts.calls {
		if path, via, ok := selfExecLaunchPath(b, call); ok {
			visit(path, via)
		}
		for _, callee := range a.resolve(b, call) {
			for i, arg := range call.Args {
				if callee.sinkAt(a, i) {
					visit(arg, callee.name(b))
				}
			}
		}
	}
	for _, lit := range facts.cmdLits {
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Path" {
					visit(kv.Value, "exec.Cmd")
				}
			}
		}
	}
}

// sinkAt reports whether the i-th argument of a call lands in a parameter
// that reaches a launch.
func (b *selfExecBody) sinkAt(a *selfExecAnalysis, i int) bool {
	if i >= len(b.params) || (b.variadic && i >= len(b.params)-1) {
		return false
	}
	return a.sinks[b][i]
}

// points returns the calls of a body that start the own executable.
func (a *selfExecAnalysis) points(b *selfExecBody) []selfExecPoint {
	if a.facts(b).helper {
		return nil
	}
	var points []selfExecPoint
	seen := map[ast.Node]bool{}
	a.eachLaunchArg(b, func(arg ast.Expr, via string) {
		if value := a.origin(b, arg); value.self {
			call := selfExecEnclosingCall(b, arg)
			if !seen[call] {
				seen[call] = true
				points = append(points, selfExecPoint{call: call, via: via, env: value.env})
			}
		}
	})
	return points
}

// selfExecEnclosingCall returns the call or literal a launch argument
// belongs to, the node a finding names.
func selfExecEnclosingCall(b *selfExecBody, arg ast.Expr) ast.Node {
	var found ast.Node
	ast.Inspect(b.decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if slices.Contains(node.Args, arg) {
				found = node
			}
		case *ast.KeyValueExpr:
			if node.Value == arg {
				found = node
			}
		}
		return found == nil
	})
	if found == nil {
		return arg
	}
	return found
}

// origin says what an expression holds.
func (a *selfExecAnalysis) origin(b *selfExecBody, expr ast.Expr) selfExecValue {
	switch node := ast.Unparen(expr).(type) {
	case *ast.Ident:
		key := b.key(node)
		if key == nil {
			return selfExecValue{}
		}
		if a.selfVars[key] {
			return selfExecValue{self: true}
		}
		if b.state == nil {
			return selfExecValue{}
		}
		if env := b.state.self[key]; env != nil {
			return selfExecValue{self: true, env: env}
		}
		return selfExecValue{params: b.state.paramOf[key]}
	case *ast.IndexExpr:
		return selfExecValue{self: selfExecArgsZero(b, node)}
	case *ast.CallExpr:
		return a.callOrigin(b, node)
	}
	return selfExecValue{}
}

func (a *selfExecAnalysis) callOrigin(b *selfExecBody, call *ast.CallExpr) selfExecValue {
	if name, ok := patternkit.PackageFuncName(b.file, b.info, call, "os"); ok && name == "Executable" {
		return selfExecValue{self: true}
	}
	if operand := selfExecPathOperand(b, call); operand != call {
		return a.origin(b, operand)
	}
	for _, callee := range a.resolve(b, call) {
		if env := a.selfResult[callee]; env != nil {
			return selfExecValue{self: true, env: env}
		}
	}
	return selfExecValue{}
}

// selfExecPathOperand returns the path a call of filepath.Clean, Abs or
// EvalSymlinks keeps; any other expression is returned as is.
func selfExecPathOperand(b *selfExecBody, expr ast.Expr) ast.Expr {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return expr
	}
	if name, ok := patternkit.PackageFuncName(b.file, b.info, call, "path/filepath"); ok && (name == "Clean" || name == "Abs" || name == "EvalSymlinks") {
		return call.Args[0]
	}
	return expr
}

// selfExecArgsZero reports os.Args[0].
func selfExecArgsZero(b *selfExecBody, index *ast.IndexExpr) bool {
	sel, ok := ast.Unparen(index.X).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Args" || !selfExecPackageMember(b, sel, "os") {
		return false
	}
	lit, ok := ast.Unparen(index.Index).(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}

// selfExecPackageMember reports whether a selector of a body names a member
// of the package at path.
func selfExecPackageMember(b *selfExecBody, sel *ast.SelectorExpr, path string) bool {
	return selfExecMember(b.file, b.info, sel, path)
}

// selfExecMember reports whether a selector names a member of the package at
// path: by its object with type information, through the imports of the
// file without it.
func selfExecMember(file *ast.File, info *types.Info, sel *ast.SelectorExpr, path string) bool {
	if info != nil {
		obj := info.Uses[sel.Sel]
		return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == path
	}
	qualifier, ok := sel.X.(*ast.Ident)
	if !ok || file == nil {
		return false
	}
	for _, imp := range patternkit.FileImports(file) {
		if imp.Name == qualifier.Name && imp.Path == path {
			return true
		}
	}
	return false
}

// selfExecLaunches lists the standard functions that start a binary, with
// the index of the path argument.
var selfExecLaunches = []struct {
	pkg, name string
	arg       int
}{
	{"os/exec", "Command", 0},
	{"os/exec", "CommandContext", 1},
	{"os", "StartProcess", 0},
	{"syscall", "Exec", 0},
	{"syscall", "ForkExec", 0},
	{"syscall", "StartProcess", 0},
}

// selfExecLaunchPath returns the path argument of a standard launch.
func selfExecLaunchPath(b *selfExecBody, call *ast.CallExpr) (ast.Expr, string, bool) {
	for _, launch := range selfExecLaunches {
		name, ok := patternkit.PackageFuncName(b.file, b.info, call, launch.pkg)
		if ok && name == launch.name && len(call.Args) > launch.arg {
			return call.Args[launch.arg], launch.pkg[strings.LastIndex(launch.pkg, "/")+1:] + "." + name, true
		}
	}
	return nil, "", false
}

// selfExecCmdLit reports an exec.Cmd literal.
func selfExecCmdLit(b *selfExecBody, lit *ast.CompositeLit) bool {
	if b.info != nil {
		return patternkit.IsNamedType(b.info.TypeOf(lit), "os/exec", "Cmd")
	}
	sel, ok := lit.Type.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Cmd" && selfExecPackageMember(b, sel, "os/exec")
}

// selfExecTestingOutcome says whether a condition can be true and whether it can be
// false in a test binary, where testing.Testing() is true.
func selfExecTestingOutcome(b *selfExecBody, cond ast.Expr) (canTrue, canFalse bool) {
	switch node := ast.Unparen(cond).(type) {
	case *ast.CallExpr:
		if name, ok := patternkit.PackageFuncName(b.file, b.info, node, "testing"); ok && name == "Testing" {
			return true, false
		}
	case *ast.UnaryExpr:
		if node.Op == token.NOT {
			t, f := selfExecTestingOutcome(b, node.X)
			return f, t
		}
	case *ast.BinaryExpr:
		lt, lf := selfExecTestingOutcome(b, node.X)
		rt, rf := selfExecTestingOutcome(b, node.Y)
		switch node.Op {
		case token.LAND:
			return lt && rt, lf || rf
		case token.LOR:
			return lt || rt, lf && rf
		}
	}
	return true, true
}

// facts walks the paths a test binary can take through a body, once.
func (a *selfExecAnalysis) facts(b *selfExecBody) *selfExecFacts {
	if b.facts != nil {
		return b.facts
	}
	c := &selfExecCollector{body: b, facts: &selfExecFacts{}, stored: map[*ast.FuncLit]bool{}}
	if b.decl != nil {
		c.walk(b.decl.Body.List, false)
		c.facts.helper = selfExecPassesTestRun(b.decl.Body)
	}
	b.facts = c.facts
	return b.facts
}

type selfExecCollector struct {
	body   *selfExecBody
	facts  *selfExecFacts
	stored map[*ast.FuncLit]bool
}

func (c *selfExecCollector) walk(stmts []ast.Stmt, inLit bool) {
	branch := func(cond ast.Expr) (bool, bool) { return selfExecTestingOutcome(c.body, cond) }
	patternkit.WalkReachableStatementsWhere(stmts, c.body.info, c.body.file, branch, func(n ast.Node) { c.visit(n, inLit) })
}

func (c *selfExecCollector) visit(n ast.Node, inLit bool) {
	ast.Inspect(n, func(x ast.Node) bool {
		switch node := x.(type) {
		case *ast.FuncLit:
			if !c.stored[node] {
				c.walk(node.Body.List, true)
			}
			return false
		case *ast.AssignStmt:
			c.store(node.Rhs...)
			c.assign(node.Lhs, node.Rhs)
		case *ast.ValueSpec:
			c.store(node.Values...)
			lhs := make([]ast.Expr, len(node.Names))
			for i, name := range node.Names {
				lhs[i] = name
			}
			c.assign(lhs, node.Values)
		case *ast.ReturnStmt:
			c.store(node.Results...)
			if !inLit {
				c.facts.returns = append(c.facts.returns, node.Results)
			}
		case *ast.CompositeLit:
			c.storeElements(node)
		case *ast.CallExpr:
			c.facts.calls = append(c.facts.calls, node)
		}
		return true
	})
}

func (c *selfExecCollector) assign(lhs, rhs []ast.Expr) {
	keys := make([]any, len(lhs))
	for i, target := range lhs {
		keys[i] = c.body.key(target)
	}
	c.facts.assigns = append(c.facts.assigns, selfExecAssign{lhs: keys, rhs: rhs})
}

// store marks the function literals a statement keeps for later rather than
// runs: they are not followed.
func (c *selfExecCollector) store(exprs ...ast.Expr) {
	for _, expr := range exprs {
		if lit, ok := ast.Unparen(expr).(*ast.FuncLit); ok {
			c.stored[lit] = true
		}
	}
}

func (c *selfExecCollector) storeElements(lit *ast.CompositeLit) {
	if selfExecCmdLit(c.body, lit) {
		c.facts.cmdLits = append(c.facts.cmdLits, lit)
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			elt = kv.Value
		}
		c.store(elt)
	}
}

// selfExecPassesTestRun reports a body that names -test.run: the binary it
// starts runs the helper test it names, not the suite.
func selfExecPassesTestRun(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "-test.run") {
			found = true
		}
		return !found
	})
	return found
}
