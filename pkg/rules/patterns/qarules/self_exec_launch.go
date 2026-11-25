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

func (r *SelfExecInTestRule) violation(ctx *core.GoProjectContext, found *selfExecFinding) *core.Violation {
	// A start outside the files of the project has no file to report in.
	if fileCtx, err := ctx.FileForPosition(found.point.call.Pos()); err == nil && ctx.IsReportFile(fileCtx) {
		return r.violationIn(fileCtx, found)
	}
	return nil
}

func (r *SelfExecInTestRule) violationIn(fileCtx *core.FileContext, found *selfExecFinding) *core.Violation {
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
	// testLevel marks the package variables of a test file.
	testLevel bool
	// locals are the names a test file body declares, found on first use.
	locals []selfExecLocal
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
	if b.decl == nil || b.decl.Type.Params == nil {
		return
	}
	params := b.decl.Type.Params
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
	// fields are the assignments to a field of a variable: cmd.Path, cmd.Env.
	fields []selfExecField
}

type selfExecAssign struct {
	lhs []any
	rhs []ast.Expr
	// targets are the assigned expressions, decl the statement or the
	// specification.
	targets []ast.Expr
	decl    ast.Node
}

// selfExecField is an assignment to a field of a variable, x.field = rhs.
type selfExecField struct {
	x     any
	field string
	rhs   ast.Expr
	stmt  *ast.AssignStmt
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
//
// env also holds the labels of the package variables the path or the
// launcher comes from ("var:" labels): a test that sets them first starts
// what it set.
type selfExecPoint struct {
	call   ast.Node
	via    string
	env    []string
	body   *selfExecBody
	launch selfExecLaunch
}

// selfExecLaunch is what a start passes the binary: the arguments after the
// path (argv when they hold the program name first), the variable of the
// command, whose Env field the start takes, or the list of the environment.
type selfExecLaunch struct {
	args     []ast.Expr
	ellipsis bool
	argv     bool
	known    bool
	cmdVar   any
	envList  ast.Expr
	labels   []string
	// in is the body the launch sits in when it is not the body of the
	// point, a launcher the point calls with via.
	in  *selfExecBody
	via *ast.CallExpr
}

type selfExecFinding struct {
	point *selfExecPoint
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

	// selfVars are the package variables that hold the own executable: a
	// *types.Var, or a selfExecTestVar of a test file.
	selfVars map[any]bool
	// selfResult holds the functions that return the own executable, with
	// the environment variables it is the fallback of.
	selfResult map[*selfExecBody][]string
	sinks      map[*selfExecBody]map[int]bool
	// dispatchInfo holds the switches on a name, found on first use.
	dispatchInfo *selfExecDispatch

	pointsOf map[*selfExecBody][]*selfExecPoint
	forwards map[selfExecForward]int
	runs     map[string]*selfExecRun
	markers  map[string]bool
	spans    map[selfExecModeKey][][2]token.Pos
	setterOf map[*selfExecBody][]selfExecSetter
	setsOf   map[*selfExecBody][]string
	// callSites holds the calls of each function, found on first use;
	// escaped the functions also used other than by a call.
	callSites  map[*selfExecBody][]selfExecCallSite
	escaped    map[*selfExecBody]bool
	paramConst map[selfExecParam]selfExecParamValue
	// following holds the parameters whose calls are being read.
	following map[selfExecParam]bool
	// succeeds holds whether the string result of a function is never empty
	// where its error is nil.
	succeeds map[*selfExecBody]bool
	// bound holds, per body, the constants its parameters hold where the
	// analysis knows them: from the path to the node being checked, or from
	// the call being followed.
	bound map[*selfExecBody]map[string][]string
	// guardsOf holds the branches of each body on the environment.
	guardsOf map[*selfExecBody][]selfExecGuard
	// boundBy holds the call being followed into a body.
	boundBy map[*selfExecBody]selfExecCallSite
	// relevant holds the bodies that start the own executable or call one
	// that does; labels the labels of the starts.
	relevant map[*selfExecBody]bool
	labels   map[string]bool
	helpers  map[selfExecHelperKey]int
	reported map[ast.Node]bool
	findings []*selfExecFinding
}

// selfExecTestVar is a package variable of a test file.
type selfExecTestVar struct {
	tests *selfExecTestPkg
	name  string
}

func newSelfExecAnalysis(ctx *core.GoProjectContext, decls map[*types.Func]patternkit.TypedFuncDecl) *selfExecAnalysis {
	a := &selfExecAnalysis{
		ctx: ctx, decls: decls,
		typed:      map[*types.Func]*selfExecBody{},
		resolved:   map[*ast.CallExpr][]*selfExecBody{},
		selfVars:   map[any]bool{},
		selfResult: map[*selfExecBody][]string{},
		sinks:      map[*selfExecBody]map[int]bool{},
		pointsOf:   map[*selfExecBody][]*selfExecPoint{},
		forwards:   map[selfExecForward]int{},
		runs:       map[string]*selfExecRun{},
		spans:      map[selfExecModeKey][][2]token.Pos{},
		setterOf:   map[*selfExecBody][]selfExecSetter{},
		setsOf:     map[*selfExecBody][]string{},
		paramConst: map[selfExecParam]selfExecParamValue{},
		helpers:    map[selfExecHelperKey]int{},
		reported:   map[ast.Node]bool{},
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
			switch x := n.(type) {
			case *ast.SelectorExpr:
				found = found || x.Sel.Name == "Executable" || x.Sel.Name == "Args"
			case *ast.BasicLit:
				found = found || strings.Contains(x.Value, selfExecProcExe)
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
				if name, ok := key.(string); ok && b.testLevel {
					a.selfVars[selfExecTestVar{b.tests, name}], changed = true, true
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

// selfExecString returns the value of a string constant: by its type
// information, or in a test file a literal, a constant of the test files or
// of a package of the module, and their concatenation.
func selfExecString(b *selfExecBody, expr ast.Expr) (string, bool) {
	return selfExecStringAt(b, expr, 0)
}

func selfExecStringAt(b *selfExecBody, expr ast.Expr, depth int) (string, bool) {
	if b.info != nil {
		if tv, ok := b.info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
			return constant.StringVal(tv.Value), true
		}
		return "", false
	}
	if depth > 8 {
		return "", false
	}
	switch node := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		if node.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(node.Value)
		return value, err == nil
	case *ast.BinaryExpr:
		x, okX := selfExecStringAt(b, node.X, depth+1)
		y, okY := selfExecStringAt(b, node.Y, depth+1)
		return x + y, node.Op == token.ADD && okX && okY
	case *ast.Ident:
		if b.tests == nil {
			return "", false
		}
		if b.decl != nil {
			if local := b.localAt(node.Name, node.Pos()); local != nil {
				return selfExecLocalConst(b, local, depth)
			}
		}
		if value, ok := b.tests.consts[node.Name]; ok {
			return selfExecStringAt(b, value, depth+1)
		}
		if b.tests.internal() {
			return b.tests.idx.constOf(b.tests.idx.pkgOfDir[b.tests.dir], node.Name)
		}
	case *ast.SelectorExpr:
		if importPath, ok := b.tests.idx.qualifier(b, node); ok {
			return b.tests.idx.constOf(importPath, node.Sel.Name)
		}
	}
	return "", false
}

// selfExecLocalConst returns the value of a string constant a test file
// function declares.
func selfExecLocalConst(b *selfExecBody, local *selfExecLocal, depth int) (string, bool) {
	spec, ok := local.decl.(*ast.ValueSpec)
	if !ok || !local.konst || len(spec.Values) != len(spec.Names) {
		return "", false
	}
	for i, id := range spec.Names {
		if id.Name == local.name {
			return selfExecStringAt(b, spec.Values[i], depth+1)
		}
	}
	return "", false
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
	a.eachLaunchArg(b, func(arg ast.Expr, _ string, _ ast.Node, _ func() selfExecLaunch) {
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
// that reaches one, with the name of the call, the node a finding names and
// what the start passes the binary.
func (a *selfExecAnalysis) eachLaunchArg(b *selfExecBody, visit func(arg ast.Expr, via string, at ast.Node, launch func() selfExecLaunch)) {
	facts := a.facts(b)
	for _, call := range facts.calls {
		if path, via, launch, ok := a.launchPath(b, call); ok {
			visit(path, via, call, launch)
		}
		for _, callee := range a.resolve(b, call) {
			for i, arg := range call.Args {
				if callee.sinkAt(a, i) {
					visit(arg, callee.name(b), call, func() selfExecLaunch { return a.forwarded(call, callee, i) })
				}
			}
		}
	}
	for _, lit := range facts.cmdLits {
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Path" {
					visit(kv.Value, "exec.Cmd", kv, func() selfExecLaunch { return a.literalLaunch(b, lit) })
				}
			}
		}
	}
	for _, field := range facts.fields {
		if field.field != "Path" {
			continue
		}
		if launch, ok := a.commandOf(b, field); ok {
			visit(field.rhs, "exec.Cmd", field.stmt, func() selfExecLaunch { return launch })
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

// points returns the calls of a body that start the own executable, found
// once the summaries are done.
func (a *selfExecAnalysis) points(b *selfExecBody) []*selfExecPoint {
	if points, ok := a.pointsOf[b]; ok {
		return points
	}
	points := []*selfExecPoint{}
	seen := map[ast.Node]bool{}
	a.eachLaunchArg(b, func(arg ast.Expr, via string, at ast.Node, launch func() selfExecLaunch) {
		value := a.origin(b, arg)
		if !value.self || seen[at] {
			return
		}
		seen[at] = true
		l := launch()
		points = append(points, &selfExecPoint{call: at, via: via, env: selfExecUnion([]string{}, value.env, l.labels), body: b, launch: l})
	})
	a.pointsOf[b] = points
	return points
}

// selfExecProcExe is the path of the running executable on Linux.
const selfExecProcExe = "/proc/self/exe"

// origin says what an expression holds.
func (a *selfExecAnalysis) origin(b *selfExecBody, expr ast.Expr) selfExecValue {
	expr = ast.Unparen(expr)
	if value, ok := selfExecString(b, expr); ok {
		return selfExecValue{self: value == selfExecProcExe}
	}
	switch node := expr.(type) {
	case *ast.Ident:
		if b.info == nil && b.tests != nil && (b.decl == nil || !b.declaresAt(node.Name, node.Pos())) {
			return a.packageVarOrigin(b, node)
		}
		key := b.key(node)
		if key == nil {
			return selfExecValue{}
		}
		if v, ok := key.(*types.Var); ok && a.selfVars[key] {
			return selfExecValue{self: true, env: []string{selfExecVarLabel(v)}}
		}
		if b.state == nil {
			return selfExecValue{}
		}
		if env := b.state.self[key]; env != nil {
			return selfExecValue{self: true, env: env}
		}
		return selfExecValue{params: b.state.paramOf[key]}
	case *ast.SelectorExpr:
		return a.packageVarOrigin(b, node)
	case *ast.IndexExpr:
		return selfExecValue{self: a.argsZero(b, node)}
	case *ast.CallExpr:
		return a.callOrigin(b, node)
	}
	return selfExecValue{}
}

// packageVarOrigin says whether a package variable a name or a selector
// names holds the own executable, labelled so a test can set it first.
func (a *selfExecAnalysis) packageVarOrigin(b *selfExecBody, expr ast.Expr) selfExecValue {
	key, label, ok := a.packageVar(b, expr)
	if !ok || !a.selfVars[key] {
		return selfExecValue{}
	}
	return selfExecValue{self: true, env: []string{label}}
}

// selfExecVarLabel is the label of a package variable of the module.
func selfExecVarLabel(v *types.Var) string {
	return "var:" + v.Pkg().Path() + "." + v.Name()
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

// selfExecPathOperand returns the path a call keeps: filepath.Clean, Abs or
// EvalSymlinks, exec.LookPath, a conversion to a string type; any other
// expression is returned as is.
func selfExecPathOperand(b *selfExecBody, expr ast.Expr) ast.Expr {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return expr
	}
	if name, ok := patternkit.PackageFuncName(b.file, b.info, call, "path/filepath"); ok && (name == "Clean" || name == "Abs" || name == "EvalSymlinks") {
		return call.Args[0]
	}
	if name, ok := patternkit.PackageFuncName(b.file, b.info, call, "os/exec"); ok && name == "LookPath" {
		return call.Args[0]
	}
	if selfExecStringConversion(b, call) {
		return call.Args[0]
	}
	return expr
}

// selfExecStringConversion reports a conversion to a type whose underlying
// type is string: by type information, or string(x) in a test file.
func selfExecStringConversion(b *selfExecBody, call *ast.CallExpr) bool {
	if b.info == nil {
		id, ok := call.Fun.(*ast.Ident)
		return ok && id.Name == "string" && (b.decl == nil || !b.declaresAt(id.Name, id.Pos()))
	}
	tv, ok := b.info.Types[call.Fun]
	if !ok || !tv.IsType() {
		return false
	}
	basic, ok := tv.Type.Underlying().(*types.Basic)
	if ok {
		return basic.Info()&types.IsString != 0
	}
	_, param := types.Unalias(tv.Type).(*types.TypeParam)
	return param
}

// argsZero reports os.Args[0], or element 0 of a variable the body assigns
// os.Args to once and does not write the first element of.
func (a *selfExecAnalysis) argsZero(b *selfExecBody, index *ast.IndexExpr) bool {
	lit, ok := ast.Unparen(index.Index).(*ast.BasicLit)
	if !ok || lit.Kind != token.INT || lit.Value != "0" {
		return false
	}
	if selfExecOSArgs(b, index.X) {
		return true
	}
	key := b.key(index.X)
	if key == nil || slices.Contains(b.params, key) || selfExecHeadWritten(b, key) {
		return false
	}
	if id, ok := ast.Unparen(index.X).(*ast.Ident); ok && b.info == nil && b.decl != nil && !b.declaresAt(id.Name, id.Pos()) {
		return false
	}
	value, count := a.assignedOnce(b, key)
	return count == 1 && value != nil && selfExecOSArgs(b, value)
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

// launchPath returns the path argument of a standard launch, or of a call
// of a package variable that holds exec.Command or exec.CommandContext,
// with what the launch passes the binary.
func (a *selfExecAnalysis) launchPath(b *selfExecBody, call *ast.CallExpr) (ast.Expr, string, func() selfExecLaunch, bool) {
	for _, launch := range selfExecLaunches {
		name, ok := patternkit.PackageFuncName(b.file, b.info, call, launch.pkg)
		if ok && name == launch.name && len(call.Args) > launch.arg {
			via := launch.pkg[strings.LastIndex(launch.pkg, "/")+1:] + "." + name
			return call.Args[launch.arg], via, func() selfExecLaunch { return a.standardLaunch(b, call, launch.pkg+"."+name, launch.arg) }, true
		}
	}
	v, name := a.launcherVar(b, call)
	if v == nil {
		return nil, "", nil, false
	}
	arg := 0
	if name == "CommandContext" {
		arg = 1
	}
	if len(call.Args) <= arg {
		return nil, "", nil, false
	}
	return call.Args[arg], v.Name(), func() selfExecLaunch {
		launch := a.standardLaunch(b, call, "os/exec."+name, arg)
		launch.labels = []string{selfExecVarLabel(v)}
		return launch
	}, true
}

// standardLaunch tells what a standard launch passes the binary.
func (a *selfExecAnalysis) standardLaunch(b *selfExecBody, call *ast.CallExpr, name string, arg int) selfExecLaunch {
	switch name {
	case "os/exec.Command", "os/exec.CommandContext":
		return selfExecLaunch{args: call.Args[arg+1:], ellipsis: call.Ellipsis.IsValid(), known: true, cmdVar: a.assignedTo(b, call)}
	case "syscall.Exec":
		if len(call.Args) == 3 {
			return selfExecLaunch{args: call.Args[1:2], ellipsis: true, argv: true, known: true, envList: call.Args[2]}
		}
	default:
		if len(call.Args) > 1 {
			return selfExecLaunch{args: call.Args[1:2], ellipsis: true, argv: true, known: true}
		}
	}
	return selfExecLaunch{}
}

// launcherVar returns the package variable a call calls when it holds
// exec.Command or exec.CommandContext, with the name of the function.
func (a *selfExecAnalysis) launcherVar(b *selfExecBody, call *ast.CallExpr) (*types.Var, string) {
	if b.info == nil {
		return nil, ""
	}
	var id *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fun
	case *ast.SelectorExpr:
		id = fun.Sel
	default:
		return nil, ""
	}
	v, ok := b.info.Uses[id].(*types.Var)
	if !ok || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
		return nil, ""
	}
	for _, level := range a.pkgLevel {
		for _, assign := range level.facts.assigns {
			for i, key := range assign.lhs {
				sel, ok := ast.Unparen(selfExecAssigned(assign, i)).(*ast.SelectorExpr)
				if key != v || !ok || !selfExecMember(level.file, level.info, sel, "os/exec") {
					continue
				}
				if sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext" {
					return v, sel.Sel.Name
				}
			}
		}
	}
	return nil, ""
}

// assignedTo returns the variable a body assigns an expression to.
func (a *selfExecAnalysis) assignedTo(b *selfExecBody, expr ast.Expr) any {
	for _, assign := range a.facts(b).assigns {
		for i, key := range assign.lhs {
			value := ast.Unparen(selfExecAssigned(assign, i))
			if addr, ok := value.(*ast.UnaryExpr); ok && addr.Op == token.AND {
				value = ast.Unparen(addr.X)
			}
			if value == expr && key != nil {
				return key
			}
		}
	}
	return nil
}

// literalLaunch tells what an exec.Cmd literal passes the binary.
func (a *selfExecAnalysis) literalLaunch(b *selfExecBody, lit *ast.CompositeLit) selfExecLaunch {
	launch := selfExecLaunch{argv: true, known: true, ellipsis: true, cmdVar: a.assignedTo(b, lit)}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		switch key, _ := kv.Key.(*ast.Ident); {
		case key == nil:
		case key.Name == "Args":
			launch.args = []ast.Expr{kv.Value}
		case key.Name == "Env":
			launch.envList = kv.Value
		}
	}
	if launch.args == nil {
		launch.known = false
	}
	return launch
}

// commandOf tells what the command whose Path a body sets passes the
// binary: the variable holds exec.Command or an exec.Cmd literal.
func (a *selfExecAnalysis) commandOf(b *selfExecBody, field selfExecField) (selfExecLaunch, bool) {
	if field.x == nil {
		return selfExecLaunch{}, false
	}
	value, count := a.assignedOnce(b, field.x)
	if count != 1 || value == nil {
		return selfExecLaunch{}, false
	}
	value = ast.Unparen(value)
	if addr, ok := value.(*ast.UnaryExpr); ok && addr.Op == token.AND {
		value = ast.Unparen(addr.X)
	}
	switch node := value.(type) {
	case *ast.CallExpr:
		for _, name := range []string{"Command", "CommandContext"} {
			if found, ok := patternkit.PackageFuncName(b.file, b.info, node, "os/exec"); ok && found == name {
				arg := 0
				if name == "CommandContext" {
					arg = 1
				}
				if len(node.Args) <= arg {
					return selfExecLaunch{}, false
				}
				launch := a.standardLaunch(b, node, "os/exec."+name, arg)
				launch.cmdVar = field.x
				return launch, true
			}
		}
	case *ast.CompositeLit:
		if selfExecCmdLit(b, node) {
			launch := a.literalLaunch(b, node)
			launch.cmdVar = field.x
			return launch, true
		}
	}
	return selfExecLaunch{}, false
}

// forwarded tells what a call of a launcher passes the binary: the
// arguments after the path, where the launcher hands its variadic rest to
// the launch as the arguments, and sets no environment of its own.
func (a *selfExecAnalysis) forwarded(call *ast.CallExpr, callee *selfExecBody, i int) selfExecLaunch {
	if a.forwardsAt(callee, i) {
		return selfExecLaunch{args: call.Args[i+1:], ellipsis: call.Ellipsis.IsValid(), known: true}
	}
	// The one launch of the launcher that starts the path parameter, read
	// with the parameters the call gives it.
	var found []selfExecLaunch
	a.eachLaunchArg(callee, func(arg ast.Expr, _ string, _ ast.Node, launch func() selfExecLaunch) {
		if slices.Contains(a.origin(callee, arg).params, i) {
			found = append(found, launch())
		}
	})
	if len(found) != 1 || !found[0].known || found[0].in != nil {
		return selfExecLaunch{}
	}
	launch := found[0]
	launch.in, launch.via = callee, call
	return launch
}

type selfExecForward struct {
	body *selfExecBody
	at   int
}

// forwardsAt reports a launcher whose path parameter is the one before its
// variadic parameter and which launches path with that rest as the
// arguments, directly or through another launcher that does.
func (a *selfExecAnalysis) forwardsAt(b *selfExecBody, i int) bool {
	key := selfExecForward{b, i}
	if state, ok := a.forwards[key]; ok {
		return state == 2
	}
	a.forwards[key] = 1
	forwards := false
	if b.variadic && i == len(b.params)-2 && b.params[i+1] != nil {
		a.eachLaunchArg(b, func(arg ast.Expr, _ string, at ast.Node, launch func() selfExecLaunch) {
			l := launch()
			if !slices.Contains(a.origin(b, arg).params, i) || !l.known || l.argv || !l.ellipsis || len(l.args) != 1 || l.envList != nil {
				return
			}
			if b.key(l.args[0]) == b.params[i+1] && !a.setsEnv(b, l) {
				forwards = true
			}
		})
	}
	if forwards {
		a.forwards[key] = 2
	}
	return forwards
}

// setsEnv reports a launch whose command gets an Env.
func (a *selfExecAnalysis) setsEnv(b *selfExecBody, launch selfExecLaunch) bool {
	return launch.cmdVar != nil && slices.ContainsFunc(a.facts(b).fields, func(f selfExecField) bool {
		return f.x == launch.cmdVar && f.field == "Env"
	})
}

// selfExecCmdLit reports an exec.Cmd literal.
func selfExecCmdLit(b *selfExecBody, lit *ast.CompositeLit) bool {
	if b.info != nil {
		return patternkit.IsNamedType(b.info.TypeOf(lit), "os/exec", "Cmd")
	}
	sel, ok := lit.Type.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Cmd" && selfExecPackageMember(b, sel, "os/exec")
}

// testingOutcome says whether a condition can be true and whether it can be
// false in a test binary, where testing.Testing() is true and the test
// flags are registered: flag.Lookup("test.v") is not nil. A function of the
// module that only returns such a condition tells it as well.
func (a *selfExecAnalysis) testingOutcome(b *selfExecBody, cond ast.Expr, depth int) (canTrue, canFalse bool) {
	if depth > 4 {
		return true, true
	}
	switch node := ast.Unparen(cond).(type) {
	case *ast.CallExpr:
		if name, ok := patternkit.PackageFuncName(b.file, b.info, node, "testing"); ok && name == "Testing" {
			return true, false
		}
		if callees := a.resolve(b, node); len(callees) == 1 {
			if result := selfExecOnlyResult(callees[0]); result != nil {
				return a.testingOutcome(callees[0], result, depth+1)
			}
		}
	case *ast.UnaryExpr:
		if node.Op == token.NOT {
			t, f := a.testingOutcome(b, node.X, depth+1)
			return f, t
		}
	case *ast.BinaryExpr:
		if registered, ok := selfExecTestFlag(b, node); ok {
			return registered, !registered
		}
		lt, lf := a.testingOutcome(b, node.X, depth+1)
		rt, rf := a.testingOutcome(b, node.Y, depth+1)
		switch node.Op {
		case token.LAND:
			return lt && rt, lf || rf
		case token.LOR:
			return lt || rt, lf && rf
		}
	}
	return true, true
}

// selfExecOnlyResult returns the result of a function whose body is one
// return of one value.
func selfExecOnlyResult(b *selfExecBody) ast.Expr {
	if b.decl == nil || len(b.decl.Body.List) != 1 {
		return nil
	}
	ret, ok := b.decl.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil
	}
	return ret.Results[0]
}

// selfExecTestFlag tells a comparison of flag.Lookup of a test flag with
// nil: whether it holds in a test binary.
func selfExecTestFlag(b *selfExecBody, cmp *ast.BinaryExpr) (bool, bool) {
	if cmp.Op != token.EQL && cmp.Op != token.NEQ {
		return false, false
	}
	call, ok := ast.Unparen(cmp.X).(*ast.CallExpr)
	other := cmp.Y
	if !ok {
		call, ok = ast.Unparen(cmp.Y).(*ast.CallExpr)
		other = cmp.X
	}
	if nilID, isIdent := ast.Unparen(other).(*ast.Ident); !ok || !isIdent || nilID.Name != "nil" || len(call.Args) != 1 {
		return false, false
	}
	name, ok := patternkit.PackageFuncName(b.file, b.info, call, "flag")
	if !ok || name != "Lookup" {
		return false, false
	}
	flagName, ok := selfExecString(b, call.Args[0])
	if !ok || !strings.HasPrefix(flagName, "test.") {
		return false, false
	}
	return cmp.Op == token.NEQ, true
}

// facts walks the paths a test binary can take through a body, once.
func (a *selfExecAnalysis) facts(b *selfExecBody) *selfExecFacts {
	if b.facts != nil {
		return b.facts
	}
	c := &selfExecCollector{a: a, body: b, facts: &selfExecFacts{}, stored: map[*ast.FuncLit]bool{}, called: map[any]bool{}}
	b.facts = c.facts
	if b.decl != nil {
		ast.Inspect(b.decl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if key := b.key(call.Fun); key != nil {
					c.called[key] = true
				}
			}
			return true
		})
		c.walk(b.decl.Body.List, false)
	}
	return b.facts
}

type selfExecCollector struct {
	a      *selfExecAnalysis
	body   *selfExecBody
	facts  *selfExecFacts
	stored map[*ast.FuncLit]bool
	// called holds the variables the body calls as functions: a literal
	// assigned to one runs where it is called.
	called map[any]bool
}

func (c *selfExecCollector) walk(stmts []ast.Stmt, inLit bool) {
	branch := func(cond ast.Expr) (bool, bool) { return c.a.testingOutcome(c.body, cond, 0) }
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
			c.storeAssigned(node.Lhs, node.Rhs)
			c.assign(node, node.Lhs, node.Rhs)
			c.fields(node)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, len(node.Names))
			for i, name := range node.Names {
				lhs[i] = name
			}
			c.storeAssigned(lhs, node.Values)
			c.assign(node, lhs, node.Values)
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

func (c *selfExecCollector) assign(decl ast.Node, lhs, rhs []ast.Expr) {
	keys := make([]any, len(lhs))
	for i, target := range lhs {
		keys[i] = selfExecTarget(c.body, target)
	}
	c.facts.assigns = append(c.facts.assigns, selfExecAssign{lhs: keys, rhs: rhs, targets: lhs, decl: decl})
}

// fields records the assignments to a field of a variable.
func (c *selfExecCollector) fields(assign *ast.AssignStmt) {
	if len(assign.Lhs) != len(assign.Rhs) {
		return
	}
	for i, lhs := range assign.Lhs {
		if sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok {
			c.facts.fields = append(c.facts.fields, selfExecField{x: selfExecTarget(c.body, sel.X), field: sel.Sel.Name, rhs: assign.Rhs[i], stmt: assign})
		}
	}
}

// storeAssigned marks the function literals an assignment keeps, except
// one assigned to a variable the body calls: that one runs.
func (c *selfExecCollector) storeAssigned(lhs, rhs []ast.Expr) {
	for i, value := range rhs {
		if len(lhs) == len(rhs) && c.called[c.body.key(lhs[i])] {
			continue
		}
		c.store(value)
	}
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
