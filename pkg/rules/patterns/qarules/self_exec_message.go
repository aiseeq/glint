package qarules

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// The message of a finding says why the child reaches the launch again. A
// child the launch answers by its environment or its arguments - a branch of
// a test, TestMain or an init its run takes and the run go test starts does
// not - goes on past that branch when it does not end; a child pinned by
// -test.run runs only the tests the pattern names, not every test. What the
// rule reports does not depend on this: it is told only for the finding.

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

// describe tells the finding why its child reaches the launch again: the
// branch that answers the child without an end, or the tests -test.run pins
// the child to.
func (a *selfExecAnalysis) describe(found *selfExecFinding, dir string, run *selfExecRun, bodies []*selfExecBody, pattern string, known, helper bool) {
	found.answer = a.answerBranch(dir, run, bodies, found.point)
	// A child the TestMain or an init answers runs no test: it reached the
	// launch on its way to the answer.
	if a.answered(dir, run) {
		found.beforeAnswer = true
		return
	}
	if !helper || !known {
		return
	}
	found.pattern = pattern
	for _, root := range a.childRoots(dir, pattern, known) {
		if a.index.kinds[root] != goTestMain {
			found.pinned = append(found.pinned, root.decl.Name.Name)
		}
	}
}

// answerBranch returns the first branch the child takes and the run go test
// starts does not, in the inits, the TestMain before m.Run, and the bodies on
// the way to the launch before the call that leads on; nil when there is
// none, or when a branch the child takes first ends it.
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
// takes before it ends the child.
func (a *selfExecAnalysis) answerIn(child, top *selfExecEval, b *selfExecBody, m string, limit token.Pos) (answer *selfExecAnswer, ended bool) {
	for _, stmt := range b.decl.Body.List {
		if (limit.IsValid() && stmt.End() > limit) || (m != "" && selfExecRunsSuite(stmt, m)) {
			return nil, false
		}
		branch, decided := child.branch(b, stmt)
		if !decided || branch == nil {
			continue
		}
		if selfExecTerminates(b, branch) {
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
	for _, expr := range exprs {
		if on := a.readOf(b, expr, 0); on != "" {
			return on
		}
	}
	return ""
}

func (a *selfExecAnalysis) readOf(b *selfExecBody, node ast.Node, depth int) string {
	if node == nil || depth > 3 {
		return ""
	}
	on := ""
	ast.Inspect(node, func(n ast.Node) bool {
		if on != "" {
			return false
		}
		switch x := n.(type) {
		case *ast.CallExpr:
			if name, ok := selfExecEnvRead(b, x); ok {
				on = name
			}
		case *ast.IndexExpr:
			if lit, ok := ast.Unparen(x.Index).(*ast.BasicLit); ok && lit.Kind == token.INT && selfExecOSArgs(b, x.X) {
				on = "os.Args[" + lit.Value + "]"
			}
		case *ast.Ident:
			if key := b.key(x); key != nil && !a.isParam(b, x, key) {
				if assign, i, count := a.localAssign(b, x, key); count == 1 {
					if len(assign.rhs) == len(assign.lhs) {
						on = a.readOf(b, assign.rhs[i], depth+1)
					} else if len(assign.rhs) == 1 {
						on = a.readOf(b, assign.rhs[0], depth+1)
					}
				}
			}
		}
		return on == ""
	})
	return on
}

// reason returns the part of the message after the chain and the
// suggestion, by what the finding knows of the child.
func (found *selfExecFinding) reason(fileCtx *core.FileContext) (reason, suggestion string) {
	if answer := found.answer; answer != nil {
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
	if found.beforeAnswer {
		return "the child reaches this launch again on its way to the branch of TestMain or an init that answers it, and each copy starts the next",
			"Answer the child before the launch: move the branch that answers it above the start, or start the child from a test"
	}
	if len(found.pinned) > 0 {
		tests := strings.Join(found.pinned, ", ")
		return fmt.Sprintf("-test.run=%s runs only %s in the child, nothing there answers the child, so it reaches this launch again, and each copy starts the next", found.pattern, tests),
			fmt.Sprintf("Answer the child in %s before the launch: set a variable in the command's Env and end the test with os.Exit or a return when it is set, or start a TestHelperProcess that does not launch", tests)
	}
	return "under go test that binary runs every test again, and each copy starts the next",
		"Refuse the launch when testing.Testing() is true, let the tests replace the launcher, or start a helper process: -test.run=TestHelperProcess in its arguments, or a TestMain that answers the child by its argument or environment before m.Run"
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
