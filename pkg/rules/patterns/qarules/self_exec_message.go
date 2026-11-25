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
//   - a launch pinned by -test.run says which test the child runs, and that
//     nothing answers the child only where nothing in the test binary reads
//     the variables the launch knows or the arguments;
//   - otherwise the message of a run of every test stays.
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
	reads := a.launchReads(dir, run)
	found.reads = len(reads) > 0
	answer := a.answerBranch(dir, run, bodies, found.point)
	if answer != nil && !slices.ContainsFunc(reads, func(pos token.Pos) bool { return pos < answer.stmt.Pos() || pos >= answer.stmt.End() }) {
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
// os.Exit, log.Fatal, panic, t.Fatal and their kin, a call of a function
// value, or a call of a module function that may.
func (a *selfExecAnalysis) mayStop(b *selfExecBody, node ast.Node, depth int, seen map[*selfExecBody]bool) bool {
	stops := false
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if stops || !ok {
			return !stops
		}
		if patternkit.StmtNoReturn(&ast.ExprStmt{X: call}, b.info, b.file) != patternkit.CallReturns || selfExecEndsTest(b, call) || selfExecFuncValue(b, call) {
			stops = true
			return false
		}
		for _, callee := range a.resolve(b, call) {
			if seen[callee] || callee.decl == nil || callee.decl.Body == nil {
				continue
			}
			seen[callee] = true
			if depth >= 4 || a.mayStop(callee, callee.decl.Body, depth+1, seen) {
				stops = true
				return false
			}
		}
		return true
	})
	return stops
}

// selfExecFuncValue reports a call of a function value: a variable or a
// parameter, whose function the analysis does not follow.
func selfExecFuncValue(b *selfExecBody, call *ast.CallExpr) bool {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	if b.info != nil {
		_, isVar := b.info.Uses[id].(*types.Var)
		return isVar
	}
	return b.decl != nil && b.declaresAt(id.Name, id.Pos())
}

// launchReads returns where the test binary of a directory reads what a
// child may be answered by: a variable of the run of the child, an
// environment variable it cannot name, an argument (os.Args past the program
// name, the flag package). The binary is the package, its test files and the
// functions of the module they call.
func (a *selfExecAnalysis) launchReads(dir string, run *selfExecRun) []token.Pos {
	pkg := a.index.pkgOfDir[dir]
	var queue []*selfExecBody
	seen := map[*selfExecBody]bool{}
	for _, b := range slices.Concat(a.bodies, a.pkgLevel) {
		if (b.tests != nil && b.tests.dir == dir) || (b.tests == nil && pkg != "" && b.pkg == pkg) {
			seen[b] = true
			queue = append(queue, b)
		}
	}
	var reads []token.Pos
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
			reads = append(reads, a.readsIn(b, node, run)...)
			ast.Inspect(node, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					for _, callee := range a.resolve(b, call) {
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

// readsIn returns the reads of a node: see launchReads.
func (a *selfExecAnalysis) readsIn(b *selfExecBody, node ast.Node, run *selfExecRun) []token.Pos {
	var reads []token.Pos
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IndexExpr:
			// os.Args[0] is the program name the launch itself passes on.
			if selfExecOSArgs(b, x.X) && selfExecIntIs(x.Index, 0) {
				return false
			}
		case *ast.SelectorExpr:
			if selfExecOSArgs(b, x) || selfExecPackageMember(b, x, "flag") {
				reads = append(reads, x.Pos())
			}
		case *ast.CallExpr:
			name, ok := patternkit.PackageFuncName(b.file, b.info, x, "os")
			if !ok || (name != "Getenv" && name != "LookupEnv") {
				return true
			}
			env, named := selfExecEnvRead(b, x)
			if _, known := run.env[env]; !named || known {
				reads = append(reads, x.Pos())
			}
		}
		return true
	})
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
		test := found.chain[0]
		if !found.reads {
			return fmt.Sprintf("-test.run=%s runs %s in the child, and nothing in the test binary reads what the launch passes: %s reaches this launch again, and each copy starts the next", found.pattern, test, test),
				"Answer the child before the launch: set a variable in the command's Env and end the test with os.Exit or a return when it is set, or start a TestHelperProcess that does not launch"
		}
		return fmt.Sprintf("-test.run=%s runs %s in the child, and it reaches this launch again, and each copy starts the next", found.pattern, test),
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
