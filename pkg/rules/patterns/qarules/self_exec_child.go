package qarules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// A start of the own executable is safe only where it is proven safe for
// that start: the TestMain of the test binary answers the child by what the
// start passes it - its arguments, its environment - and exits before m.Run,
// or the start is a helper process (-test.run in its arguments) and no test
// the child runs starts it again. The child is followed as the parent is,
// with what the start sets: a branch on it is decided where the condition
// is, and the branch the child does not take is not followed.

// selfExecStr is a string the analysis knows: whole, or only its prefix,
// and then whether something always follows the prefix.
type selfExecStr struct {
	s        string
	complete bool
	more     bool
}

// selfExecArgs is a list of strings: the elements the analysis knows, in
// order, and whether more may follow.
type selfExecArgs struct {
	elems []selfExecStr
	open  bool
}

// selfExecRun is what a process of the test binary is started with: the
// environment variables the analysis knows and the arguments after the
// program name.
type selfExecRun struct {
	env map[string]selfExecStr
	// envClosed: a variable not in env is empty.
	envClosed bool
	args      selfExecArgs
	argsKnown bool
	// argv0 is os.Args[0] where the start sets it through the Args of its
	// command.
	argv0 selfExecStr
}

// key encodes a run for a node of the reach.
func (r *selfExecRun) key() string {
	var parts []string
	for _, name := range slices.Sorted(maps.Keys(r.env)) {
		value := r.env[name]
		parts = append(parts, "e"+name+"="+value.s+strconv.FormatBool(value.complete)+strconv.FormatBool(value.more))
	}
	parts = append(parts, "c"+strconv.FormatBool(r.envClosed), "z"+r.argv0.s+strconv.FormatBool(r.argv0.complete))
	if r.argsKnown {
		for _, arg := range r.args.elems {
			parts = append(parts, "a"+arg.s+strconv.FormatBool(arg.complete))
		}
		parts = append(parts, "o"+strconv.FormatBool(r.args.open))
	}
	return strings.Join(parts, "\x00")
}

// run returns the run a node of the reach is in; "" is the run go test
// starts: the variables only the starts of the module set are empty there.
func (a *selfExecAnalysis) run(mode string) *selfExecRun {
	if run, ok := a.runs[mode]; ok {
		return run
	}
	run := &selfExecRun{env: map[string]selfExecStr{}}
	for name := range a.childMarkers() {
		run.env[name] = selfExecStr{complete: true}
	}
	a.runs[mode] = run
	return run
}

// childMarkers returns the environment variables a start of the own
// executable sets that no test or function sets with Setenv: go test does
// not set them, so a branch that needs one is the child's.
func (a *selfExecAnalysis) childMarkers() map[string]bool {
	if a.markers != nil {
		return a.markers
	}
	a.markers = map[string]bool{}
	set := map[string]bool{}
	for _, b := range a.bodies {
		for _, call := range a.facts(b).calls {
			if name, ok := a.setenvName(b, call); ok {
				set[name] = true
			}
		}
		for _, point := range a.points(b) {
			for name := range a.launchEnv(point).env {
				a.markers[name] = true
			}
		}
		a.envNames(b, a.markers)
	}
	for name := range set {
		delete(a.markers, name)
	}
	for name := range a.markers {
		if selfExecStandardVariable(name) {
			delete(a.markers, name)
		}
	}
	return a.markers
}

// envNames adds the variables a body sets in the Env of any command: one
// started through a shell is the own executable as often. Where a name is a
// parameter, each call of the body names its own.
func (a *selfExecAnalysis) envNames(b *selfExecBody, names map[string]bool) {
	add := func() bool {
		open := false
		for _, fa := range a.facts(b).fields {
			if fa.field != "Env" {
				continue
			}
			for _, elem := range a.sliceElems(b, fa.rhs, 0, true).elems {
				name, _, ok := strings.Cut(elem.s, "=")
				if !ok || name == "" {
					open = true
					continue
				}
				names[name] = true
			}
		}
		return open
	}
	if !add() || b.decl == nil {
		return
	}
	for _, site := range a.callSitesOf(b) {
		unbind := a.bindCall(site.body, site.call, b)
		add()
		unbind()
	}
}

// selfExecStandardVariable reports a variable the environment of a user or
// of a build has, which a start may set for its child only to isolate it.
func selfExecStandardVariable(name string) bool {
	switch name {
	case "HOME", "PATH", "USER", "LOGNAME", "SHELL", "PWD", "TERM", "LANG", "TZ",
		"TMPDIR", "TMP", "TEMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "SYSTEMROOT",
		"GOPATH", "GOROOT", "GOCACHE", "GOFLAGS", "GOMODCACHE", "GOTMPDIR", "CI":
		return true
	}
	return strings.HasPrefix(name, "XDG_") || strings.HasPrefix(name, "LC_")
}

// childRun returns the run a start makes from the run of its parent.
func (a *selfExecAnalysis) childRun(parent *selfExecRun, point *selfExecPoint) *selfExecRun {
	child := &selfExecRun{env: maps.Clone(parent.env), envClosed: parent.envClosed}
	if set := a.launchEnv(point); set.given {
		if !set.open {
			child.env, child.envClosed = map[string]selfExecStr{}, true
		}
		maps.Copy(child.env, set.env)
	}
	child.args, child.argsKnown = a.launchArgs(point)
	a.commandArgs(point, child)
	key := child.key()
	if known, ok := a.runs[key]; ok {
		return known
	}
	a.runs[key] = child
	return child
}

// selfExecEnvSet is the environment a start gives: the variables it names
// and whether it passes the rest of its own on (open).
type selfExecEnvSet struct {
	given bool
	env   map[string]selfExecStr
	open  bool
}

// launchEnv returns the environment a start sets: the Env of its command or
// the list it passes, by the strings of the form NAME=value it holds.
func (a *selfExecAnalysis) launchEnv(point *selfExecPoint) selfExecEnvSet {
	b := point.body
	if point.launch.in != nil {
		defer a.bindCall(b, point.launch.via, point.launch.in)()
		b = point.launch.in
	}
	var lists []ast.Expr
	if point.launch.envList != nil {
		lists = append(lists, point.launch.envList)
	}
	if point.launch.cmdVar != nil {
		for _, fa := range a.facts(b).fields {
			if fa.x == point.launch.cmdVar && fa.field == "Env" {
				lists = append(lists, fa.rhs)
			}
		}
	}
	set := selfExecEnvSet{given: len(lists) > 0, env: map[string]selfExecStr{}}
	for _, list := range lists {
		elems := a.sliceElems(b, list, 0, true)
		set.open = set.open || elems.open || len(lists) > 1
		for _, elem := range elems.elems {
			name, value, ok := strings.Cut(elem.s, "=")
			if !ok || name == "" {
				set.open = true
				continue
			}
			set.env[name] = selfExecStr{s: value, complete: elem.complete, more: elem.more}
		}
	}
	return set
}

// inits returns the init functions of the test binary of a directory: of
// the package under test and of its test files.
func (a *selfExecAnalysis) inits(dir string) []*selfExecBody {
	pkg := a.index.pkgOfDir[dir]
	var inits []*selfExecBody
	for _, b := range a.bodies {
		if b.decl == nil || b.decl.Recv != nil || b.decl.Name.Name != "init" || b.decl.Body == nil {
			continue
		}
		if (b.tests != nil && b.tests.dir == dir) || (b.tests == nil && pkg != "" && b.pkg == pkg) {
			inits = append(inits, b)
		}
	}
	return inits
}

// commandArgs applies the Args a start sets on its command: argv[0] and the
// arguments after it. Args set more than once, or to a list the analysis
// cannot tell, leaves the arguments unknown.
func (a *selfExecAnalysis) commandArgs(point *selfExecPoint, run *selfExecRun) {
	b := point.body
	if point.launch.in != nil {
		defer a.bindCall(b, point.launch.via, point.launch.in)()
		b = point.launch.in
	}
	if point.launch.cmdVar == nil {
		return
	}
	var lists []ast.Expr
	for _, fa := range a.facts(b).fields {
		if fa.x == point.launch.cmdVar && fa.field == "Args" {
			lists = append(lists, fa.rhs)
		}
	}
	if len(lists) == 0 {
		return
	}
	var elems selfExecArgs
	if len(lists) == 1 {
		elems = a.sliceElems(b, lists[0], 0, false)
	}
	if len(elems.elems) == 0 {
		run.args, run.argsKnown = selfExecArgs{}, false
		return
	}
	run.argv0 = elems.elems[0]
	run.args, run.argsKnown = selfExecArgs{elems: elems.elems[1:], open: elems.open}, true
}

// launchArgs returns the arguments a start passes after the program name.
func (a *selfExecAnalysis) launchArgs(point *selfExecPoint) (selfExecArgs, bool) {
	launch := point.launch
	if !launch.known {
		return selfExecArgs{}, false
	}
	b := point.body
	if launch.in != nil {
		defer a.bindCall(b, launch.via, launch.in)()
		b = launch.in
	}
	args := a.argList(b, launch.args, launch.ellipsis, 0)
	if launch.argv {
		if len(args.elems) == 0 {
			return selfExecArgs{open: true}, true
		}
		args.elems = args.elems[1:]
	}
	return args, true
}

// argList returns the strings a list of arguments holds; the last one is
// spread when ellipsis is set.
func (a *selfExecAnalysis) argList(b *selfExecBody, exprs []ast.Expr, ellipsis bool, depth int) selfExecArgs {
	return a.argListOf(b, exprs, ellipsis, depth, false)
}

func (a *selfExecAnalysis) argListOf(b *selfExecBody, exprs []ast.Expr, ellipsis bool, depth int, unordered bool) selfExecArgs {
	var args selfExecArgs
	for i, expr := range exprs {
		if ellipsis && i == len(exprs)-1 {
			more := a.sliceElems(b, expr, depth+1, unordered)
			args.elems = append(args.elems, more.elems...)
			args.open = more.open
			break
		}
		args.elems = append(args.elems, a.str(b, expr, depth+1))
	}
	return args
}

// sliceElems returns the strings a slice expression holds: a literal, an
// append, a variable assigned once, the one return of a module function.
// Unordered keeps the elements appended after an unknown head, where their
// place does not matter (an environment).
func (a *selfExecAnalysis) sliceElems(b *selfExecBody, expr ast.Expr, depth int, unordered bool) selfExecArgs {
	open := selfExecArgs{open: true}
	if depth > 6 {
		return open
	}
	switch node := ast.Unparen(expr).(type) {
	case *ast.CompositeLit:
		var args selfExecArgs
		for _, elt := range node.Elts {
			if _, ok := elt.(*ast.KeyValueExpr); ok {
				return open
			}
			args.elems = append(args.elems, a.str(b, elt, depth+1))
		}
		return args
	case *ast.Ident:
		key := b.key(node)
		if key != nil && a.isParam(b, node, key) {
			if args, ok := a.boundSlice(b, key, depth, unordered); ok {
				return args
			}
			return open
		}
		if key == nil || (b.tests != nil && b.decl != nil && !b.declaresAt(node.Name, node.Pos())) {
			return open
		}
		value, count := a.assignedOnce(b, key)
		if count != 1 || value == nil {
			return open
		}
		args := a.sliceElems(b, value, depth+1, unordered)
		if a.appended(b, key) {
			args.open = true
		}
		return args
	case *ast.CallExpr:
		return a.callElems(b, node, depth, unordered)
	}
	return open
}

func (a *selfExecAnalysis) callElems(b *selfExecBody, call *ast.CallExpr, depth int, unordered bool) selfExecArgs {
	open := selfExecArgs{open: true}
	if fun, ok := call.Fun.(*ast.Ident); ok && fun.Name == "append" && len(call.Args) > 0 {
		args := a.sliceElems(b, call.Args[0], depth+1, unordered)
		if args.open && !unordered {
			return args
		}
		more := a.argListOf(b, call.Args[1:], call.Ellipsis.IsValid(), depth+1, unordered)
		args.elems = append(args.elems, more.elems...)
		args.open = args.open || more.open
		return args
	}
	callees := a.resolve(b, call)
	if len(callees) != 1 {
		return open
	}
	callee := callees[0]
	returns := a.facts(callee).returns
	if len(returns) != 1 || len(returns[0]) == 0 {
		return open
	}
	defer a.bindCall(b, call, callee)()
	return a.sliceElems(callee, returns[0][0], depth+1, unordered)
}

// appended reports a variable a body appends to after its assignment.
func (a *selfExecAnalysis) appended(b *selfExecBody, key any) bool {
	for _, assign := range a.facts(b).assigns {
		for i, target := range assign.lhs {
			if target == key && selfExecAppendsTo(b, assign, i, key) {
				return true
			}
		}
	}
	return false
}

// str returns what the analysis knows of a string expression: a constant,
// a concatenation, a variable assigned once.
func (a *selfExecAnalysis) str(b *selfExecBody, expr ast.Expr, depth int) selfExecStr {
	if value, ok := selfExecString(b, expr); ok {
		return selfExecStr{s: value, complete: true}
	}
	if depth > 6 {
		return selfExecStr{}
	}
	switch node := ast.Unparen(expr).(type) {
	case *ast.BinaryExpr:
		if node.Op != token.ADD {
			return selfExecStr{}
		}
		left := a.str(b, node.X, depth+1)
		if !left.complete {
			return left
		}
		right := a.str(b, node.Y, depth+1)
		return selfExecStr{s: left.s + right.s, complete: right.complete, more: right.more}
	case *ast.Ident:
		return a.identStr(b, node, depth)
	case *ast.CallExpr:
		if a.nonEmptyCall(b, node, depth) {
			return selfExecStr{more: true}
		}
	case *ast.SelectorExpr:
		return a.tableField(b, node)
	}
	return selfExecStr{}
}

// helperPattern returns the -test.run pattern a start passes: helper is set
// when it passes the flag, known when the pattern is a constant.
func (a *selfExecAnalysis) helperPattern(point *selfExecPoint) (pattern string, known, helper bool) {
	args, ok := a.launchArgs(point)
	if !ok {
		return "", false, false
	}
	for i, arg := range args.elems {
		for _, flag := range []string{"-test.run", "--test.run"} {
			if rest, found := strings.CutPrefix(arg.s, flag+"="); found {
				return rest, arg.complete, true
			}
			if arg.complete && arg.s == flag {
				if i+1 < len(args.elems) {
					next := args.elems[i+1]
					return next.s, next.complete, true
				}
				return "", false, true
			}
		}
	}
	return "", false, false
}

// childRoots returns the functions of the test binary a helper child runs:
// TestMain and the tests, fuzz targets and examples the pattern matches,
// every one when the pattern is not known.
func (a *selfExecAnalysis) childRoots(dir, pattern string, known bool) []*selfExecBody {
	matches := func(string) bool { return true }
	if known {
		first, _, _ := strings.Cut(pattern, "/")
		match, err := regexp.Compile(first)
		matches = func(name string) bool {
			// The cut at the first slash ignores the brackets the testing
			// package respects: a part that does not compile keeps every test.
			return err != nil || match.MatchString(name)
		}
	}
	var roots []*selfExecBody
	for _, root := range a.index.rootsOf[dir] {
		kind := a.index.kinds[root]
		if kind == goBenchmark {
			continue
		}
		if kind == goTestMain || matches(root.decl.Name.Name) {
			roots = append(roots, root)
		}
	}
	return roots
}

// answered reports whether the TestMain of the test binary in a directory
// answers a child started with the run: a branch it takes there exits or
// returns before m.Run.
func (a *selfExecAnalysis) answered(dir string, run *selfExecRun) bool {
	for _, init := range a.inits(dir) {
		// A return ends only the init: the tests run after it.
		e := &selfExecEval{a: a, run: run, bind: map[any]selfExecVal{}, visiting: map[*selfExecBody]bool{}, init: true}
		if answer, _ := e.answers(init, init.decl.Body.List, ""); answer {
			return true
		}
	}
	main := a.index.mains[dir]
	if main == nil {
		return false
	}
	m := ""
	if params := main.decl.Type.Params.List; len(params) == 1 && len(params[0].Names) == 1 {
		m = params[0].Names[0].Name
	}
	e := &selfExecEval{a: a, run: run, bind: map[any]selfExecVal{}, visiting: map[*selfExecBody]bool{}}
	answer, _ := e.answers(main, main.decl.Body.List, m)
	return answer
}

// answers walks statements of TestMain in the child: it reports an answer
// when a taken branch exits or returns, and stops at m.Run.
func (e *selfExecEval) answers(b *selfExecBody, list []ast.Stmt, m string) (answered, stop bool) {
	for _, stmt := range list {
		if selfExecRunsSuite(stmt, m) {
			return false, true
		}
		if _, ok := stmt.(*ast.ReturnStmt); ok {
			return !e.init, true
		}
		if patternkit.StmtNoReturn(stmt, b.info, b.file) != patternkit.CallReturns || e.a.neverReturns(b, stmt) {
			return true, true
		}
		var taken []ast.Stmt
		switch node := stmt.(type) {
		case *ast.RangeStmt:
			taken = e.firstIteration(b, node)
		default:
			branch, decided := e.branch(b, stmt)
			if e.ended {
				return true, true
			}
			if !decided || branch == nil {
				continue
			}
			taken = selfExecStmts(branch)
		}
		if answered, stop := e.answers(b, taken, m); answered || stop {
			return answered, stop
		}
	}
	return false, false
}

// firstIteration binds the value of a range over os.Args[1:] to the first
// argument of the run and returns the body; nil when it does not apply.
func (e *selfExecEval) firstIteration(b *selfExecBody, rng *ast.RangeStmt) []ast.Stmt {
	slice, ok := ast.Unparen(rng.X).(*ast.SliceExpr)
	if !ok || rng.Value == nil || !selfExecOSArgs(b, slice.X) || slice.High != nil || !selfExecIntIs(slice.Low, 1) {
		return nil
	}
	if !e.run.argsKnown || len(e.run.args.elems) == 0 {
		return nil
	}
	key := b.key(rng.Value)
	if key == nil {
		return nil
	}
	e.bind[key] = selfExecVal{kind: selfExecString_, s: e.run.args.elems[0]}
	return rng.Body.List
}

// selfExecStmts returns the statements of a branch.
func selfExecStmts(branch ast.Node) []ast.Stmt {
	switch node := branch.(type) {
	case *ast.BlockStmt:
		return node.List
	case *ast.CaseClause:
		return node.Body
	case ast.Stmt:
		return []ast.Stmt{node}
	}
	return nil
}

// selfExecIntIs reports an integer literal of the value.
func selfExecIntIs(expr ast.Expr, value int) bool {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == strconv.Itoa(value)
}

// neverReturns reports a statement that calls a function of the module
// which has no return and ends in an exit: main that ends in os.Exit.
func (a *selfExecAnalysis) neverReturns(b *selfExecBody, stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := ast.Unparen(expr.X).(*ast.CallExpr)
	if !ok {
		return false
	}
	callees := a.resolve(b, call)
	if len(callees) != 1 || callees[0].decl == nil || callees[0].decl.Body == nil {
		return false
	}
	callee := callees[0]
	returns := false
	ast.Inspect(callee.decl.Body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			returns = true
		}
		return !returns
	})
	return !returns && selfExecTerminates(callee, callee.decl.Body)
}

// selfExecTerminates reports a branch whose every path exits or returns.
func selfExecTerminates(b *selfExecBody, node ast.Node) bool {
	list := selfExecStmts(node)
	if len(list) == 0 {
		return false
	}
	switch last := list[len(list)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BlockStmt:
		return selfExecTerminates(b, last)
	case *ast.IfStmt:
		return last.Else != nil && selfExecTerminates(b, last.Body) && selfExecTerminates(b, last.Else)
	case *ast.ExprStmt:
		return patternkit.StmtNoReturn(last, b.info, b.file) != patternkit.CallReturns || selfExecEndsTest(b, last.X)
	case *ast.SelectStmt:
		// An empty select blocks for ever.
		return len(last.Body.List) == 0
	case *ast.ForStmt:
		return last.Cond == nil && !selfExecBreaks(last)
	}
	return false
}

// selfExecBreaks reports a loop with a break or a goto in its body that may
// leave it: one in a nested loop, switch or select counts unless it is a
// plain break, which leaves only the nested statement.
func selfExecBreaks(loop *ast.ForStmt) bool {
	breaks := false
	var walk func(n ast.Node, nested bool) bool
	walk = func(n ast.Node, nested bool) bool {
		ast.Inspect(n, func(x ast.Node) bool {
			switch node := x.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				if x != n {
					walk(x, true)
					return false
				}
			case *ast.BranchStmt:
				switch node.Tok {
				case token.GOTO:
					breaks = true
				case token.BREAK:
					breaks = breaks || node.Label != nil || !nested
				}
			}
			return true
		})
		return breaks
	}
	return walk(loop.Body, false)
}

// selfExecEndsTest reports a call that ends the test it runs in: t.Fatal,
// t.Skip and their kin stop its goroutine.
func selfExecEndsTest(b *selfExecBody, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return patternkit.TestingMethodNoReturn(sel.Sel.Name) && selfExecTestingValue(b, sel.X)
}

// modeSpans returns the spans of a test file body a run does not take: the
// branches a condition on the run rules out, and what follows a taken
// branch that exits or returns.
func (a *selfExecAnalysis) modeSpans(b *selfExecBody, mode, names string) [][2]token.Pos {
	if b.decl == nil {
		return nil
	}
	key := selfExecModeKey{b, mode, names}
	if spans, ok := a.spans[key]; ok {
		return spans
	}
	defer a.bind(b, selfExecNames(names))()
	e := &selfExecEval{a: a, run: a.run(mode), bind: map[any]selfExecVal{}, visiting: map[*selfExecBody]bool{}}
	var spans [][2]token.Pos
	e.prune(b, b.decl.Body.List, &spans)
	a.spans[key] = spans
	return spans
}

type selfExecModeKey struct {
	body        *selfExecBody
	mode, names string
}

func (e *selfExecEval) prune(b *selfExecBody, list []ast.Stmt, spans *[][2]token.Pos) bool {
	for i, stmt := range list {
		branch, decided := e.branch(b, stmt)
		if !decided {
			continue
		}
		*spans = append(*spans, selfExecOtherBranches(stmt, branch)...)
		if branch == nil {
			continue
		}
		taken := selfExecStmts(branch)
		if e.prune(b, taken, spans) || selfExecTerminates(b, branch) {
			if i+1 < len(list) {
				*spans = append(*spans, [2]token.Pos{list[i+1].Pos(), list[len(list)-1].End()})
			}
			return true
		}
	}
	return false
}

// selfExecOtherBranches returns the spans of the branches of a statement
// other than the taken one.
func selfExecOtherBranches(stmt ast.Stmt, taken ast.Node) [][2]token.Pos {
	var others []ast.Node
	switch node := stmt.(type) {
	case *ast.IfStmt:
		others = []ast.Node{node.Body}
		if node.Else != nil {
			others = append(others, node.Else)
		}
	case *ast.SwitchStmt:
		for _, clause := range node.Body.List {
			others = append(others, clause)
		}
	}
	var spans [][2]token.Pos
	for _, other := range others {
		if other != taken {
			spans = append(spans, [2]token.Pos{other.Pos(), other.End()})
		}
	}
	return spans
}

// branch returns the branch of an if or a switch the run takes: decided
// when the condition is known; the branch is nil when none is taken.
func (e *selfExecEval) branch(b *selfExecBody, stmt ast.Stmt) (ast.Node, bool) {
	switch node := stmt.(type) {
	case *ast.IfStmt:
		cond := e.eval(b, node.Cond, 0)
		if cond.kind != selfExecBool {
			return nil, false
		}
		if cond.b {
			return node.Body, true
		}
		if node.Else == nil {
			return nil, true
		}
		return node.Else, true
	case *ast.SwitchStmt:
		return e.switchBranch(b, node)
	}
	return nil, false
}

func (e *selfExecEval) switchBranch(b *selfExecBody, stmt *ast.SwitchStmt) (ast.Node, bool) {
	var tag selfExecVal
	if stmt.Tag != nil {
		tag = e.eval(b, stmt.Tag, 0)
		if tag.kind != selfExecString_ || !tag.s.complete {
			return nil, false
		}
	}
	var fallback ast.Node
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CaseClause)
		if !ok {
			return nil, false
		}
		if clause.List == nil {
			fallback = clause
			continue
		}
		for _, expr := range clause.List {
			value := e.eval(b, expr, 0)
			match := selfExecVal{}
			if stmt.Tag == nil {
				match = value
			} else if value.kind == selfExecString_ && value.s.complete {
				match = selfExecVal{kind: selfExecBool, b: value.s.s == tag.s.s}
			}
			if match.kind != selfExecBool {
				return nil, false
			}
			if match.b {
				return selfExecNoFallthrough(clause)
			}
		}
	}
	if fallback == nil {
		return nil, true
	}
	clause, _ := fallback.(*ast.CaseClause)
	return selfExecNoFallthrough(clause)
}

// selfExecNoFallthrough decides a clause only when it does not fall through.
func selfExecNoFallthrough(clause *ast.CaseClause) (ast.Node, bool) {
	if n := len(clause.Body); n > 0 {
		if br, ok := clause.Body[n-1].(*ast.BranchStmt); ok && br.Tok == token.FALLTHROUGH {
			return nil, false
		}
	}
	return clause, true
}

// selfExecVal is what an expression evaluates to in a run.
type selfExecVal struct {
	kind    int
	b       bool
	s       selfExecStr
	n       int
	atLeast bool
}

const (
	selfExecUnknown = iota
	selfExecBool
	selfExecString_
	selfExecInt
)

// selfExecEval evaluates conditions in a run: the environment and the
// arguments it knows, variables assigned once, results of functions of the
// module with no branch the run leaves open.
type selfExecEval struct {
	a        *selfExecAnalysis
	run      *selfExecRun
	bind     map[any]selfExecVal
	visiting map[*selfExecBody]bool
	// ended is set when a call evaluated on the path panics or exits in the
	// run: the statement that makes it does not finish.
	ended bool
	// init marks the walk of an init, where a return does not answer.
	init bool
}

func (e *selfExecEval) eval(b *selfExecBody, expr ast.Expr, depth int) selfExecVal {
	if depth > 8 {
		return selfExecVal{}
	}
	expr = ast.Unparen(expr)
	if value, ok := selfExecConstant(b, expr); ok {
		return value
	}
	switch node := expr.(type) {
	case *ast.Ident:
		return e.ident(b, node, depth)
	case *ast.CallExpr:
		return e.call(b, node, 0, depth)
	case *ast.IndexExpr:
		lit, ok := ast.Unparen(node.Index).(*ast.BasicLit)
		if !ok || lit.Kind != token.INT || !selfExecOSArgs(b, node.X) || !e.run.argsKnown {
			return selfExecVal{}
		}
		i, exact := constant.Int64Val(constant.MakeFromLiteral(lit.Value, token.INT, 0))
		if exact && i == 0 && e.run.argv0.complete {
			return selfExecVal{kind: selfExecString_, s: e.run.argv0}
		}
		if !exact || i < 1 || i > int64(len(e.run.args.elems)) {
			return selfExecVal{}
		}
		return selfExecVal{kind: selfExecString_, s: e.run.args.elems[i-1]}
	case *ast.UnaryExpr:
		value := e.eval(b, node.X, depth+1)
		if node.Op == token.NOT && value.kind == selfExecBool {
			return selfExecVal{kind: selfExecBool, b: !value.b}
		}
	case *ast.BinaryExpr:
		return e.binary(b, node, depth)
	}
	return selfExecVal{}
}

// selfExecConstant returns the value of a constant: by type information, or
// a literal and true or false in a test file.
func selfExecConstant(b *selfExecBody, expr ast.Expr) (selfExecVal, bool) {
	if b.info != nil {
		tv, ok := b.info.Types[expr]
		if !ok || tv.Value == nil {
			return selfExecVal{}, false
		}
		switch tv.Value.Kind() {
		case constant.Bool:
			return selfExecVal{kind: selfExecBool, b: constant.BoolVal(tv.Value)}, true
		case constant.String:
			return selfExecVal{kind: selfExecString_, s: selfExecStr{s: constant.StringVal(tv.Value), complete: true}}, true
		case constant.Int:
			if n, exact := constant.Int64Val(tv.Value); exact {
				return selfExecVal{kind: selfExecInt, n: int(n)}, true
			}
		}
		return selfExecVal{}, false
	}
	if value, ok := selfExecString(b, expr); ok {
		return selfExecVal{kind: selfExecString_, s: selfExecStr{s: value, complete: true}}, true
	}
	switch node := expr.(type) {
	case *ast.BasicLit:
		if n, err := strconv.Atoi(node.Value); err == nil && node.Kind == token.INT {
			return selfExecVal{kind: selfExecInt, n: n}, true
		}
	case *ast.Ident:
		if (node.Name == "true" || node.Name == "false") && (b.decl == nil || !b.declaresAt(node.Name, node.Pos())) {
			return selfExecVal{kind: selfExecBool, b: node.Name == "true"}, true
		}
	}
	return selfExecVal{}, false
}

func (e *selfExecEval) ident(b *selfExecBody, id *ast.Ident, depth int) selfExecVal {
	key := b.key(id)
	if key == nil {
		return selfExecVal{}
	}
	if value, ok := e.bind[key]; ok {
		return value
	}
	if e.a.isParam(b, id, key) {
		if values, ok := e.a.paramValues(b, key); ok {
			return selfExecVal{kind: selfExecString_, s: selfExecMergeValues(values)}
		}
		return selfExecVal{}
	}
	if v, ok := key.(*types.Var); ok && v.Parent() == v.Pkg().Scope() {
		return selfExecVal{}
	}
	assign, i, count := e.a.localAssign(b, id, key)
	if count != 1 {
		return selfExecVal{}
	}
	if len(assign.rhs) == len(assign.lhs) {
		return e.eval(b, assign.rhs[i], depth+1)
	}
	if len(assign.rhs) != 1 {
		return selfExecVal{}
	}
	call, ok := ast.Unparen(assign.rhs[0]).(*ast.CallExpr)
	if !ok {
		return selfExecVal{}
	}
	return e.call(b, call, i, depth+1)
}

// call evaluates the i-th result of a call.
func (e *selfExecEval) call(b *selfExecBody, call *ast.CallExpr, i, depth int) selfExecVal {
	for _, pkg := range []string{"os", "testing", "strings"} {
		if name, ok := patternkit.PackageFuncName(b.file, b.info, call, pkg); ok {
			return e.std(b, call, pkg+"."+name, i, depth)
		}
	}
	if fun, ok := call.Fun.(*ast.Ident); ok && fun.Name == "len" && len(call.Args) == 1 && selfExecOSArgs(b, call.Args[0]) && i == 0 {
		if !e.run.argsKnown {
			return selfExecVal{}
		}
		return selfExecVal{kind: selfExecInt, n: 1 + len(e.run.args.elems), atLeast: e.run.args.open}
	}
	callees := e.a.resolve(b, call)
	if len(callees) != 1 || e.visiting[callees[0]] || depth > 6 {
		return selfExecVal{}
	}
	callee := callees[0]
	e.visiting[callee] = true
	defer delete(e.visiting, callee)
	ret, ok := e.returnOf(callee, callee.decl.Body.List, depth+1)
	if !ok || i >= len(ret.Results) || (len(ret.Results) == 1 && i > 0) {
		return selfExecVal{}
	}
	return e.eval(callee, ret.Results[i], depth+1)
}

// std evaluates a call of the standard library the run tells.
func (e *selfExecEval) std(b *selfExecBody, call *ast.CallExpr, name string, i, depth int) selfExecVal {
	switch name {
	case "testing.Testing":
		return selfExecVal{kind: selfExecBool, b: true}
	case "os.Getenv", "os.LookupEnv":
		if len(call.Args) != 1 {
			return selfExecVal{}
		}
		env, ok := selfExecString(b, call.Args[0])
		if !ok {
			return selfExecVal{}
		}
		value, set := e.run.env[env]
		if !set && !e.run.envClosed {
			return selfExecVal{}
		}
		if !set {
			// A variable the whole environment of the start leaves out is
			// empty in the child.
			value = selfExecStr{complete: true}
		}
		if name == "os.LookupEnv" && i == 1 {
			if !set {
				return selfExecVal{kind: selfExecBool}
			}
			if value.complete && value.s == "" {
				return selfExecVal{}
			}
			return selfExecVal{kind: selfExecBool, b: true}
		}
		return selfExecVal{kind: selfExecString_, s: value}
	case "strings.HasPrefix", "strings.HasSuffix", "strings.Contains":
		if len(call.Args) != 2 {
			return selfExecVal{}
		}
		s, sub := e.eval(b, call.Args[0], depth+1), e.eval(b, call.Args[1], depth+1)
		if s.kind != selfExecString_ || sub.kind != selfExecString_ || !sub.s.complete {
			return selfExecVal{}
		}
		if name == "strings.HasPrefix" && (s.s.complete || len(s.s.s) >= len(sub.s.s)) {
			return selfExecVal{kind: selfExecBool, b: strings.HasPrefix(s.s.s, sub.s.s)}
		}
		if !s.s.complete {
			return selfExecVal{}
		}
		if name == "strings.HasSuffix" {
			return selfExecVal{kind: selfExecBool, b: strings.HasSuffix(s.s.s, sub.s.s)}
		}
		return selfExecVal{kind: selfExecBool, b: strings.Contains(s.s.s, sub.s.s)}
	}
	return selfExecVal{}
}

// returnOf walks statements to the return the run takes; ok is false where
// a branch is not known or the path does not end in a return.
func (e *selfExecEval) returnOf(b *selfExecBody, list []ast.Stmt, depth int) (*ast.ReturnStmt, bool) {
	for _, stmt := range list {
		switch node := stmt.(type) {
		case *ast.ReturnStmt:
			return node, true
		case *ast.BlockStmt:
			if ret, ok := e.returnOf(b, node.List, depth); ok || selfExecReturnsIn(node) {
				return ret, ok
			}
		case *ast.IfStmt, *ast.SwitchStmt:
			branch, decided := e.branch(b, node)
			if !decided {
				if selfExecReturnsIn(node) {
					return nil, false
				}
				continue
			}
			if branch == nil {
				continue
			}
			if ret, ok := e.returnOf(b, selfExecStmts(branch), depth); ok || selfExecReturnsIn(branch) {
				return ret, ok
			}
		case *ast.ExprStmt:
			if patternkit.StmtNoReturn(node, b.info, b.file) != patternkit.CallReturns {
				e.ended = true
				return nil, false
			}
		case *ast.ForStmt, *ast.RangeStmt, *ast.SelectStmt, *ast.TypeSwitchStmt, *ast.LabeledStmt, *ast.BranchStmt:
			if selfExecReturnsIn(node) {
				return nil, false
			}
		}
	}
	return nil, false
}

// selfExecReturnsIn reports a node that holds a return or a jump outside a
// function literal.
func selfExecReturnsIn(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt, *ast.BranchStmt:
			found = true
		}
		return !found
	})
	return found
}

func (e *selfExecEval) binary(b *selfExecBody, node *ast.BinaryExpr, depth int) selfExecVal {
	x := e.eval(b, node.X, depth+1)
	switch node.Op {
	case token.LAND, token.LOR:
		short := node.Op == token.LOR
		if x.kind == selfExecBool && x.b == short {
			return x
		}
		y := e.eval(b, node.Y, depth+1)
		if y.kind == selfExecBool && y.b == short {
			return y
		}
		if x.kind == selfExecBool && y.kind == selfExecBool {
			return selfExecVal{kind: selfExecBool, b: !short}
		}
		return selfExecVal{}
	}
	y := e.eval(b, node.Y, depth+1)
	switch node.Op {
	case token.EQL, token.NEQ:
		equal, ok := selfExecEqual(x, y)
		if !ok {
			return selfExecVal{}
		}
		return selfExecVal{kind: selfExecBool, b: equal == (node.Op == token.EQL)}
	case token.GTR, token.GEQ, token.LSS, token.LEQ:
		return selfExecCompare(x, y, node.Op)
	case token.ADD:
		if x.kind == selfExecString_ && y.kind == selfExecString_ && x.s.complete {
			return selfExecVal{kind: selfExecString_, s: selfExecStr{s: x.s.s + y.s.s, complete: y.s.complete, more: y.s.more}}
		}
	}
	return selfExecVal{}
}

// selfExecEqual compares two values where the analysis knows enough.
func selfExecEqual(x, y selfExecVal) (bool, bool) {
	switch {
	case x.kind == selfExecBool && y.kind == selfExecBool:
		return x.b == y.b, true
	case x.kind == selfExecInt && y.kind == selfExecInt && !x.atLeast && !y.atLeast:
		return x.n == y.n, true
	case x.kind == selfExecString_ && y.kind == selfExecString_:
		if x.s.complete && y.s.complete {
			return x.s.s == y.s.s, true
		}
		if !x.s.complete && y.s.complete && (!strings.HasPrefix(y.s.s, x.s.s) || (x.s.more && y.s.s == x.s.s)) {
			return false, true
		}
		if x.s.complete && !y.s.complete && (!strings.HasPrefix(x.s.s, y.s.s) || (y.s.more && x.s.s == y.s.s)) {
			return false, true
		}
	}
	return false, false
}

// selfExecCompare orders an integer the analysis may know only from below.
func selfExecCompare(x, y selfExecVal, op token.Token) selfExecVal {
	if x.kind != selfExecInt || y.kind != selfExecInt || y.atLeast {
		return selfExecVal{}
	}
	var holds bool
	switch op {
	case token.GTR:
		holds = x.n > y.n
	case token.GEQ:
		holds = x.n >= y.n
	case token.LSS:
		holds = x.n < y.n
	default:
		holds = x.n <= y.n
	}
	// Known only from below, x keeps a bound that holds as it grows and
	// breaks one that does not.
	if grows := op == token.GTR || op == token.GEQ; x.atLeast && holds != grows {
		return selfExecVal{}
	}
	return selfExecVal{kind: selfExecBool, b: holds}
}
