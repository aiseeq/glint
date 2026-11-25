package qarules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// The message of a finding says why the child reaches the launch again, and
// claims only what the analysis proves:
//
//   - a child the TestMain or an init answers after it reaches the launch
//     is told so first;
//   - a branch is named only where the child surely passes it on the way to
//     the launch - a statement of an init, of the TestMain before m.Run, or
//     of a function on the way before the call that leads on, taken in the
//     run of the child and not surely in the run go test starts - and
//     nothing in it may end the child; and only where it is the one place
//     of the test binary that reads what the launch passes, so no other
//     answer is missed;
//   - otherwise a launch pinned by -test.run says which test the child runs,
//     and one that is not keeps the message of a run of every test.
//
// What the rule reports does not depend on this: it is told only for the
// finding.

// selfExecAnswer is a branch that answers the child of a launch and does not
// end it: the statement, the body it is in, and what its condition reads.
type selfExecAnswer struct {
	stmt ast.Stmt
	body *selfExecBody
	on   string
	// kind is the kind of the body: a test, TestMain, or an init.
	kind selfExecAnswerKind
}

type selfExecAnswerKind int

const (
	answerInFunc selfExecAnswerKind = iota
	answerInTest
	answerInMain
	answerInInit
	// answerInMainOnWay: the TestMain that starts the child itself.
	answerInMainOnWay
)

// describe tells the finding why its child reaches the launch again.
func (a *selfExecAnalysis) describe(found *selfExecFinding, dir string, run *selfExecRun, bodies []*selfExecBody, pattern string, known, helper bool) {
	// A child the TestMain or an init answers runs no test: it reached the
	// launch on its way to the answer.
	if a.answered(dir, run) {
		found.beforeAnswer = true
		return
	}
	if helper && known {
		found.pattern = pattern
	}
	if answer := a.answerBranch(dir, run, bodies, found.point); answer != nil && !a.readsBeside(dir, run, answer.stmt) {
		found.answer = answer
	}
}

// answerBranch returns the first branch the child takes and the run go test
// starts does not, in the inits, the TestMain before m.Run, and the bodies on
// the way to the launch before the call that leads on; nil when there is
// none, or when a branch the child takes first may end it.
func (a *selfExecAnalysis) answerBranch(dir string, run *selfExecRun, bodies []*selfExecBody, point *selfExecPoint) *selfExecAnswer {
	child := &selfExecEval{a: a, run: run, bind: map[any]selfExecVal{}, visiting: map[*selfExecBody]bool{}}
	top := &selfExecEval{a: a, run: a.run(""), bind: map[any]selfExecVal{}, visiting: map[*selfExecBody]bool{}}
	limits := map[*selfExecBody]token.Pos{}
	for i, body := range bodies {
		limits[body] = point.call.Pos()
		if i+1 < len(bodies) {
			limits[body] = a.callOf(body, bodies[i+1])
		}
	}
	walk := func(body *selfExecBody, m string, kind selfExecAnswerKind) (*selfExecAnswer, bool) {
		answer, ended := a.answerIn(child, top, body, m, limits[body])
		if answer != nil {
			answer.kind = kind
		}
		return answer, answer != nil || ended
	}
	for _, init := range a.inits(dir) {
		if answer, stop := walk(init, "", answerInInit); stop {
			return answer
		}
	}
	// A TestMain on the way to the launch is walked up to the launch, past
	// m.Run; one off the way up to m.Run, where the tests start.
	main := a.index.mains[dir]
	if _, onTheWay := limits[main]; main != nil && !onTheWay {
		m := ""
		if params := main.decl.Type.Params.List; len(params) == 1 && len(params[0].Names) == 1 {
			m = params[0].Names[0].Name
		}
		if answer, stop := walk(main, m, answerInMain); stop {
			return answer
		}
	}
	for _, body := range bodies {
		kind := answerInFunc
		switch a.index.kinds[body] {
		case goTestCase:
			kind = answerInTest
		case goTestMain:
			kind = answerInMainOnWay
		}
		if answer, stop := walk(body, "", kind); stop {
			return answer
		}
	}
	return nil
}

// callOf returns the position of the first call of a body that may run the
// next one; NoPos, which limits nothing, when there is none.
func (a *selfExecAnalysis) callOf(b, next *selfExecBody) token.Pos {
	for _, call := range a.facts(b).calls {
		if slices.Contains(a.resolve(b, call), next) {
			return call.Pos()
		}
	}
	return token.NoPos
}

// answerIn walks the statements of a body up to m.Run and the limit: an if
// or a switch whose branch the child takes and the run go test starts does
// not take for sure is the answer. ended is set where a branch the child
// takes before it may end the child: past it nothing is sure.
func (a *selfExecAnalysis) answerIn(child, top *selfExecEval, b *selfExecBody, m string, limit token.Pos) (answer *selfExecAnswer, ended bool) {
	for _, stmt := range b.decl.Body.List {
		if (limit.IsValid() && stmt.End() > limit) || (m != "" && selfExecRunsSuite(stmt, m)) {
			return nil, false
		}
		branch, decided := child.branch(b, stmt)
		if !decided || branch == nil {
			continue
		}
		if selfExecTerminates(b, branch) || selfExecReturnsIn(branch) || a.mayStop(b, branch, 0, map[*selfExecBody]bool{}) {
			return nil, true
		}
		// The run go test starts knows no variable and no argument: a branch
		// it takes for sure is taken by every run and answers nothing.
		if _, sure := top.branch(b, stmt); !sure {
			return &selfExecAnswer{stmt: stmt, body: b, on: a.answerOn(b, stmt)}, false
		}
	}
	return nil, false
}

// mayStop reports a node with a call that may end the process or the test:
// any call but one proven to return.
func (a *selfExecAnalysis) mayStop(b *selfExecBody, node ast.Node, depth int, seen map[*selfExecBody]bool) bool {
	stops := false
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if stops || !ok {
			return !stops
		}
		stops = !a.callReturns(b, call, depth, seen)
		return !stops
	})
	return stops
}

// callReturns reports a call proven to return: of a function of the module
// whose body returns, of a function literal, whose body is walked with the
// node, or of a builtin but panic, a conversion, or a function or method of
// a package of the standard library that cannot end the process or the test.
func (a *selfExecAnalysis) callReturns(b *selfExecBody, call *ast.CallExpr, depth int, seen map[*selfExecBody]bool) bool {
	if _, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
		return true
	}
	callees, proven := a.provenCallees(b, call)
	if !proven {
		return a.stdCall(b, call)
	}
	for _, callee := range callees {
		if seen[callee] {
			continue
		}
		seen[callee] = true
		if depth >= 4 || callee.decl == nil || callee.decl.Body == nil || a.mayStop(callee, callee.decl.Body, depth+1, seen) {
			return false
		}
	}
	return true
}

// provenCallees returns the module functions a call runs, where they are
// proven: by the object of the callee with type information; in a test
// file, a function by its name, and a method by the type of its receiver
// the test file tells, not by its name alone.
func (a *selfExecAnalysis) provenCallees(b *selfExecBody, call *ast.CallExpr) ([]*selfExecBody, bool) {
	callees := a.resolve(b, call)
	if len(callees) == 0 {
		return nil, false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if b.info != nil || !ok {
		return callees, true
	}
	if q, ok := sel.X.(*ast.Ident); ok && !b.declaresAt(q.Name, q.Pos()) {
		if _, ok := a.index.importPath(b.file, q.Name); ok {
			return callees, true
		}
	}
	kind := a.index.receiverType(b, sel.X).kind
	return callees, kind == recvModule || kind == recvTestLocal
}

// stdCall reports a call of a builtin but panic, a conversion, or a function
// or a method of the standard library outside the packages that may end the
// process or the test (see selfExecStopsPkg): by the object of the callee
// with type information, a method of an interface aside; in a test file, a
// builtin name, a type literal, or a member of an imported package.
func (a *selfExecAnalysis) stdCall(b *selfExecBody, call *ast.CallExpr) bool {
	fun := ast.Unparen(call.Fun)
	if b.info != nil {
		if tv, ok := b.info.Types[fun]; ok && tv.IsType() {
			return true
		}
		if id, ok := fun.(*ast.Ident); ok {
			if builtin, ok := b.info.Uses[id].(*types.Builtin); ok {
				return builtin.Name() != "panic"
			}
		}
		fn := patternkit.StaticFunc(b.info, call)
		if fn == nil || fn.Pkg() == nil {
			return false
		}
		recv := fn.Signature().Recv()
		if recv != nil && types.IsInterface(recv.Type()) {
			return false
		}
		return selfExecStdReturns(fn.Pkg().Path(), fn.Name())
	}
	switch fun := fun.(type) {
	case *ast.Ident:
		return fun.Name != "panic" && !b.declaresAt(fun.Name, fun.Pos()) && types.Universe.Lookup(fun.Name) != nil
	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.FuncType, *ast.InterfaceType:
		return true
	case *ast.SelectorExpr:
		if q, ok := fun.X.(*ast.Ident); ok && !b.declaresAt(q.Name, q.Pos()) {
			if path, ok := a.index.importPath(b.file, q.Name); ok {
				return selfExecStdReturns(path, fun.Sel.Name)
			}
		}
	}
	return false
}

// selfExecStdReturns reports a function or a method of a package that
// returns: of the standard library outside the packages that may end the
// process or the test, or a function of them the answer to a child calls
// that does not.
func selfExecStdReturns(path, name string) bool {
	if !patternkit.StdlibPath(path) {
		return false
	}
	if !selfExecStopsPkg(path) {
		return true
	}
	return selfExecReturningFuncs[path+"."+name]
}

// selfExecStopsPkg reports a package of the standard library whose functions
// or methods may end the process or the test: os and its subpackages,
// syscall, runtime, log, testing and theirs.
func selfExecStopsPkg(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return first == "os" || first == "syscall" || first == "runtime" || first == "log" || first == "testing"
}

// selfExecReturningFuncs are the functions of those packages an answer to a
// child calls that return.
var selfExecReturningFuncs = map[string]bool{
	"os.Getenv": true, "os.LookupEnv": true, "os.Setenv": true,
	"os.ReadFile": true, "os.WriteFile": true, "os.Getpid": true,
	"syscall.Setpgid": true,
}

// readsBeside reports whether the test binary of a directory reads, outside
// the statement, what a child of the run may be answered by: a variable of
// the run, an environment variable it cannot name, an argument (os.Args past
// the program name, the flag package).
func (a *selfExecAnalysis) readsBeside(dir string, run *selfExecRun, stmt ast.Stmt) bool {
	reads, ok := a.readsOf[dir]
	if !ok {
		reads = a.binaryReads(dir)
		a.readsOf[dir] = reads
	}
	outside := func(pos token.Pos) bool { return pos < stmt.Pos() || pos >= stmt.End() }
	if slices.ContainsFunc(reads[""], outside) {
		return true
	}
	for env := range run.env {
		if slices.ContainsFunc(reads[env], outside) {
			return true
		}
	}
	return false
}

// binaryReads returns where the test binary of a directory - the package,
// its test files and the functions of the module they call - reads what a
// child may be answered by, by the environment variable it names, under ""
// where it reads any: an argument, or a variable it cannot name.
func (a *selfExecAnalysis) binaryReads(dir string) map[string][]token.Pos {
	pkg := a.index.pkgOfDir[dir]
	var queue []*selfExecBody
	seen := map[*selfExecBody]bool{}
	for _, b := range slices.Concat(a.bodies, a.pkgLevel) {
		if (b.tests != nil && b.tests.dir == dir) || (b.tests == nil && pkg != "" && b.pkg == pkg) {
			seen[b] = true
			queue = append(queue, b)
		}
	}
	reads := map[string][]token.Pos{}
	for len(queue) > 0 {
		b := queue[0]
		queue = queue[1:]
		// A package level body holds the values of the package variables.
		var nodes []ast.Node
		if b.decl != nil {
			nodes = append(nodes, b.decl.Body)
		} else {
			for _, assign := range b.facts.assigns {
				for _, rhs := range assign.rhs {
					nodes = append(nodes, rhs)
				}
			}
		}
		for _, node := range nodes {
			ast.Inspect(node, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.IndexExpr:
					// os.Args[0] is the program name the launch itself passes on.
					if selfExecOSArgs(b, x.X) && selfExecIntIs(x.Index, 0) {
						return false
					}
				case *ast.SelectorExpr:
					if selfExecOSArgs(b, x) || selfExecPackageMember(b, x, "flag") {
						reads[""] = append(reads[""], x.Pos())
					}
				case *ast.CallExpr:
					if name, ok := patternkit.PackageFuncName(b.file, b.info, x, "os"); ok && (name == "Getenv" || name == "LookupEnv") {
						env, named := selfExecEnvRead(b, x)
						if !named {
							env = ""
						}
						reads[env] = append(reads[env], x.Pos())
					}
					for _, callee := range a.resolve(b, x) {
						if !seen[callee] {
							seen[callee] = true
							queue = append(queue, callee)
						}
					}
				}
				return true
			})
		}
	}
	return reads
}

// answerOn names what the condition of a branch reads: the environment
// variable, or the element of os.Args; "" when it is neither.
func (a *selfExecAnalysis) answerOn(b *selfExecBody, stmt ast.Stmt) string {
	var exprs []ast.Node
	switch node := stmt.(type) {
	case *ast.IfStmt:
		exprs = append(exprs, node.Init, node.Cond)
	case *ast.SwitchStmt:
		exprs = append(exprs, node.Init, node.Tag)
	}
	on := ""
	for _, expr := range exprs {
		if expr == nil {
			continue
		}
		ast.Inspect(expr, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if name, ok := selfExecEnvRead(b, x); ok && on == "" {
					on = name
				}
			case *ast.IndexExpr:
				if lit, ok := ast.Unparen(x.Index).(*ast.BasicLit); ok && lit.Kind == token.INT && selfExecOSArgs(b, x.X) && on == "" {
					on = "os.Args[" + lit.Value + "]"
				}
			}
			return on == ""
		})
	}
	return on
}

// reason returns the part of the message after the chain and the
// suggestion, by what the finding proves of the child.
func (found *selfExecFinding) reason(fileCtx *core.FileContext) (reason, suggestion string) {
	if found.beforeAnswer {
		return "the child reaches this launch again on its way to the branch of TestMain or an init that answers it, and each copy starts the next",
			"Answer the child before the launch: move the branch that answers it above the start, or start the child from a test"
	}
	if answer := found.answer; answer != nil {
		return found.answerReason(fileCtx, answer)
	}
	if found.pattern != "" {
		return fmt.Sprintf("-test.run=%s runs %s in the child, and it reaches this launch again, and each copy starts the next", found.pattern, found.chain[0]),
			"Answer the child and end the test before the launch: a branch on what the launch passes that returns or calls os.Exit, or a TestHelperProcess that does not launch"
	}
	return "under go test that binary runs every test again, and each copy starts the next",
		"Refuse the launch when testing.Testing() is true, let the tests replace the launcher, or start a helper process: -test.run=TestHelperProcess in its arguments, or a TestMain that answers the child by its argument or environment before m.Run"
}

// answerReason names the branch that answers the child without an end.
func (found *selfExecFinding) answerReason(fileCtx *core.FileContext, answer *selfExecAnswer) (reason, suggestion string) {
	where := found.answerAt(fileCtx)
	branch := "the branch"
	if answer.on != "" {
		branch += " on " + answer.on
	}
	of := ""
	if answer.body != found.point.body {
		of = " of " + answer.body.decl.Name.Name
	}
	switch answer.kind {
	case answerInMain:
		return fmt.Sprintf("%s %s%s answers the child but does not exit before m.Run: the child goes on to the tests and reaches this launch again, and each copy starts the next", branch, where, of),
			fmt.Sprintf("End %s %s with os.Exit before m.Run, so the child never reaches the launch", branch, where)
	case answerInMainOnWay:
		return fmt.Sprintf("%s %s%s answers the child but does not exit: the child goes on and reaches this launch again, and each copy starts the next", branch, where, of),
			fmt.Sprintf("End %s %s with os.Exit, so the child never reaches the launch", branch, where)
	case answerInInit:
		return fmt.Sprintf("%s %s%s answers the child but does not exit: the child goes on to the tests and reaches this launch again, and each copy starts the next", branch, where, of),
			fmt.Sprintf("End %s %s with os.Exit, so the child never reaches the launch", branch, where)
	}
	end := "os.Exit"
	if answer.kind == answerInTest {
		end = "os.Exit or a return"
	}
	return fmt.Sprintf("%s %s%s answers the child but does not end the test: the child goes on and reaches this launch again, and each copy starts the next", branch, where, of),
		fmt.Sprintf("End %s %s with %s, so the child never reaches the launch", branch, where, end)
}

// answerAt places the answer: its line in the file of the launch, its file
// and line in another, by the path from the root of the project, which the
// path of the launch file ends with.
func (found *selfExecFinding) answerAt(launchFile *core.FileContext) string {
	at := launchFile.GoFileSet.Position(found.answer.stmt.Pos())
	line := strconv.Itoa(at.Line)
	if at.Filename == launchFile.Path {
		return "at line " + line
	}
	root := strings.TrimSuffix(launchFile.Path, filepath.FromSlash(launchFile.RelPath))
	return "at " + filepath.ToSlash(strings.TrimPrefix(at.Filename, root)) + ":" + line
}
