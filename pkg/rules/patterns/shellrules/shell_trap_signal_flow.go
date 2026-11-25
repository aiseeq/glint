package shellrules

import (
	"math"

	"mvdan.cc/sh/v3/syntax"
)

// stmtPlace is where a statement stands: its list and index, the compound
// statement whose following statements run when the list ends (an if or a
// case branch, a brace group), and the function whose body holds the list.
type stmtPlace struct {
	list []*syntax.Stmt
	idx  int
	up   *syntax.Stmt
	fn   string
	body bool
}

// trapFlow knows, for each statement in a statement list of the script,
// which statements can run after it, and what a call of a function of the
// script does to a trap: funcs tells which function a call runs, blocked
// holds those whose body is not followed, status finds the status a
// command goes on with and exits whether a handler exits. memo keeps the
// effects of the calls of each function, visiting the calls being
// followed; time is a place in the script that has surely run before the
// command being followed, the call at the top level that runs it as the
// latest known, and span the definitions run for which what has been
// followed so far holds; runs keeps the time for the body of each
// function.
type trapFlow struct {
	order    []*syntax.Stmt
	where    map[*syntax.Stmt]stmtPlace
	calls    map[string][]*syntax.Stmt
	funcs    *scriptFuncs
	blocked  map[string]bool
	status   *exitScan
	exits    *exitScan
	memo     map[string][]trapEntry
	visiting map[string]bool
	time     uint
	span     epochSpan
	runs     map[string]uint
}

// trapEntry is the effect of a call with the signals that keep the
// handler before it, while the number of definitions at the top level run
// is in span.
type trapEntry struct {
	signals uint8
	span    epochSpan
	effect  trapEffect
}

// epochSpan is a range [from, to) of numbers of definitions at the top
// level run.
type epochSpan struct{ from, to int }

var anyEpoch = epochSpan{from: 0, to: math.MaxInt}

func (e epochSpan) meet(o epochSpan) epochSpan {
	return epochSpan{from: max(e.from, o.from), to: min(e.to, o.to)}
}

func (e epochSpan) holds(epoch int) bool { return e.from <= epoch && epoch < e.to }

// flow follows the statements of the script whose functions s knows.
func (s *scriptFuncs) flow(file *syntax.File) *trapFlow {
	f := &trapFlow{
		where:    make(map[*syntax.Stmt]stmtPlace),
		calls:    make(map[string][]*syntax.Stmt),
		funcs:    s,
		blocked:  make(map[string]bool),
		status:   s.statusScan(),
		exits:    s.handlerExits(),
		memo:     make(map[string][]trapEntry),
		visiting: make(map[string]bool),
		span:     anyEpoch,
	}
	owner := make(map[syntax.Command]*syntax.Stmt)
	bodyOf := make(map[*syntax.Stmt]string)
	ifUp := make(map[*syntax.IfClause]*syntax.Stmt)
	var nodes []syntax.Node
	var fns []string
	syntax.Walk(file, func(n syntax.Node) bool {
		if n == nil {
			switch nodes[len(nodes)-1].(type) {
			case *syntax.FuncDecl, *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
				fns = fns[:len(fns)-1]
			}
			nodes = nodes[:len(nodes)-1]
			return true
		}
		nodes = append(nodes, n)
		fn := ""
		if len(fns) > 0 {
			fn = fns[len(fns)-1]
		}
		switch x := n.(type) {
		case *syntax.File:
			f.place(x.Stmts, stmtPlace{})
		case *syntax.Stmt:
			owner[x.Cmd] = x
			f.recordCall(x)
		case *syntax.FuncDecl:
			bodyOf[x.Body] = x.Name.Value
			fns = append(fns, x.Name.Value)
		case *syntax.Block:
			if name, ok := bodyOf[owner[x]]; ok {
				f.place(x.Stmts, stmtPlace{fn: name, body: true})
			} else {
				f.place(x.Stmts, stmtPlace{up: owner[x], fn: fn})
			}
		case *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
			fns = append(fns, "")
			f.place(childStmts(x), stmtPlace{})
		case *syntax.IfClause:
			up := ifUp[x]
			if up == nil {
				up = owner[x]
			}
			if x.Else != nil {
				ifUp[x.Else] = up
			}
			f.place(x.Cond, stmtPlace{fn: fn})
			f.place(x.Then, stmtPlace{up: up, fn: fn})
		case *syntax.CaseClause:
			for _, item := range x.Items {
				f.place(item.Stmts, stmtPlace{up: owner[x], fn: fn})
			}
		case *syntax.WhileClause:
			f.place(x.Cond, stmtPlace{fn: fn})
			f.place(x.Do, stmtPlace{fn: fn})
		case *syntax.ForClause:
			f.place(x.Do, stmtPlace{fn: fn})
		}
		return true
	})
	for name, fn := range s.decls {
		f.blocked[name] = returnsEarly(fn.decl.Body) || riskyRedirect(fn.decl.Body.Redirs)
	}
	return f
}

// returnsEarly finds a return other than the last command of a function
// body: the paths through the body after it do not run.
func returnsEarly(body *syntax.Stmt) bool {
	last := body
	if block, ok := body.Cmd.(*syntax.Block); ok && len(block.Stmts) > 0 {
		last = block.Stmts[len(block.Stmts)-1]
	}
	return foregroundWalk(body, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		return ok && callName(call) == "return" && syntax.Command(call) != last.Cmd
	})
}

// childStmts is the statement list of a subshell or a substitution.
func childStmts(n syntax.Node) []*syntax.Stmt {
	switch x := n.(type) {
	case *syntax.Subshell:
		return x.Stmts
	case *syntax.CmdSubst:
		return x.Stmts
	case *syntax.ProcSubst:
		return x.Stmts
	}
	return nil
}

func (f *trapFlow) place(stmts []*syntax.Stmt, at stmtPlace) {
	for i, stmt := range stmts {
		at.list, at.idx = stmts, i
		f.where[stmt] = at
		f.order = append(f.order, stmt)
	}
}

func (f *trapFlow) recordCall(stmt *syntax.Stmt) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Background || len(call.Args) == 0 {
		return
	}
	if name := wordLit(call.Args[0]); name != "" {
		f.calls[name] = append(f.calls[name], stmt)
	}
}

// followedByWork reports whether some sequence of statements that runs
// after the trap does work while the handler is still set.
func (f *trapFlow) followedByWork(stmt *syntax.Stmt, signals uint8) bool {
	for _, tail := range f.continuations(stmt, make(map[string]bool)) {
		if f.trapFollowedByWork(tail, signals) {
			return true
		}
	}
	return false
}

// continuations are the statement sequences that can run after stmt: the
// rest of its list, then what follows the branch or brace group that holds
// it, or what follows each plain call of the function whose body holds it.
// A return in the rest of a function skips to the caller.
func (f *trapFlow) continuations(stmt *syntax.Stmt, seen map[string]bool) [][]*syntax.Stmt {
	at, ok := f.where[stmt]
	if !ok {
		return nil
	}
	rest := at.list[at.idx+1:]
	if j := returnIndex(rest); j >= 0 && at.fn != "" {
		return joinTails(rest[:j], f.callTails(at.fn, seen))
	}
	switch {
	case at.up != nil:
		return joinTails(rest, f.continuations(at.up, seen))
	case at.body:
		return joinTails(rest, f.callTails(at.fn, seen))
	}
	return [][]*syntax.Stmt{rest}
}

func (f *trapFlow) callTails(fn string, seen map[string]bool) [][]*syntax.Stmt {
	if seen[fn] {
		return nil
	}
	seen[fn] = true
	var tails [][]*syntax.Stmt
	for _, call := range f.calls[fn] {
		tails = append(tails, f.continuations(call, seen)...)
	}
	return tails
}

func joinTails(rest []*syntax.Stmt, tails [][]*syntax.Stmt) [][]*syntax.Stmt {
	if len(tails) == 0 {
		return [][]*syntax.Stmt{rest}
	}
	out := make([][]*syntax.Stmt, 0, len(tails))
	for _, tail := range tails {
		joined := make([]*syntax.Stmt, 0, len(rest)+len(tail))
		out = append(out, append(append(joined, rest...), tail...))
	}
	return out
}

func returnIndex(stmts []*syntax.Stmt) int {
	for i, stmt := range stmts {
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && callName(call) == "return" {
			return i
		}
	}
	return -1
}

func callName(call *syntax.CallExpr) string {
	args := call.Args
	for len(args) > 0 && (wordLit(args[0]) == "builtin" || wordLit(args[0]) == "command") {
		args = args[1:]
	}
	if len(args) == 0 {
		return ""
	}
	return wordLit(args[0])
}

// trapFollowedByWork walks one sequence after the trap. A later trap
// replaces the handler for its signals. A loop that runs before the
// replacement is long-lived; other work counts on a path where the handler
// remains active afterwards or that ends with exit, return or exec of a
// command.
func (f *trapFlow) trapFollowedByWork(stmts []*syntax.Stmt, signals uint8) bool {
	if waitThenCleanup(stmts) {
		return false
	}
	defer func() { f.time = 0 }()
	out := trapEffect{left: signals}
	for _, stmt := range stmts {
		if stmt.Background {
			continue
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && callName(call) == "return" {
			return out.work
		}
		f.time = f.bodyRuns(f.where[stmt].fn)
		out = out.seq(f.afterTrap(stmt, out.left))
		if out.left == 0 {
			return out.found
		}
	}
	return out.work
}

// bodyRuns is a place in the script that has surely run before the body
// of fn runs: the earliest of its plain calls, each taken at the place
// that has run before the body holding it. It is zero, nothing known,
// for the top level and a function never called plainly, and a cycle of
// calls knows only its own calls. The times of all functions are found
// at once, so none depends on which function is asked first.
func (f *trapFlow) bodyRuns(fn string) uint {
	if f.runs == nil {
		f.runs = newCallGraph(f).bodyTimes()
	}
	return f.runs[fn]
}

// exitsShell holds for exit and for exec of a command, which replaces the
// shell; exec with redirections only goes on.
func exitsShell(call *syntax.CallExpr) bool {
	args := call.Args
	for len(args) > 0 && (wordLit(args[0]) == "builtin" || wordLit(args[0]) == "command") {
		args = args[1:]
	}
	if len(args) == 0 {
		return false
	}
	switch wordLit(args[0]) {
	case "exit":
		return true
	case "exec":
		return len(args) > 1
	}
	return false
}

// foregroundWalk visits what runs in the foreground of node, leaving out
// background commands and function definitions.
func foregroundWalk(node syntax.Node, visit func(syntax.Node) bool) bool {
	found := false
	syntax.Walk(node, func(n syntax.Node) bool {
		if found {
			return false
		}
		switch x := n.(type) {
		case *syntax.Stmt:
			if x.Background {
				return false
			}
		case *syntax.FuncDecl:
			return false
		}
		found = visit(n)
		return !found
	})
	return found
}

// trapEffect says what a command after the trap does to it: found holds
// where a loop runs while some of the trapped signals keep the handler, or
// a path does work and then exits with the handler on, and then nothing
// else matters; work holds where a path that keeps one of the signals does
// other work; exits holds where a path ends the script; left are the
// signals that keep the handler on some path that goes on after the
// command, none once found.
type trapEffect struct {
	found, work, exits bool
	left               uint8
}

// afterTrap follows stmt in the order it runs. Inside a brace group, the
// condition of an if, the left of && and || and every branch of an if or a
// case, a trap replaces the handler for the commands after it; the right of
// && and || and a branch replace nothing for what follows, since they may
// not run, unless the status of the left is known to run them. exit and
// exec of a command end their path. A call of a function of the script
// does what its body does, unless the script is opaque. Nothing in a
// subshell, a pipeline or a background command replaces a trap or ends the
// script. A return in a branch goes on, as the caller does.
func (f *trapFlow) afterTrap(stmt *syntax.Stmt, signals uint8) trapEffect {
	if stmt.Background {
		return trapEffect{left: signals}
	}
	switch x := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if effect, ok := f.callEffect(stmt, x, signals); ok {
			return effect
		}
	case *syntax.WhileClause, *syntax.ForClause:
		return trapEffect{found: true}
	case *syntax.Block:
		return f.listAfterTrap(x.Stmts, signals)
	case *syntax.IfClause:
		return f.ifAfterTrap(x, signals)
	case *syntax.CaseClause:
		return f.caseAfterTrap(x, signals)
	case *syntax.BinaryCmd:
		if x.Op == syntax.AndStmt || x.Op == syntax.OrStmt {
			return f.binaryAfterTrap(x, signals)
		}
	}
	return otherAfterTrap(stmt, signals)
}

// otherAfterTrap is the effect of a command the walk does not look into:
// a loop in it runs with the handler on, other work counts.
func otherAfterTrap(stmt *syntax.Stmt, signals uint8) trapEffect {
	effect := trapEffect{found: runsLoop(stmt)}
	if !effect.found {
		effect.work, effect.left = doesWork(stmt), signals
	}
	return effect
}

// callEffect: a trap replaces the handler for its signals, exit and exec
// of a command end the path, and a call of a function of the script is
// followed.
func (f *trapFlow) callEffect(stmt *syntax.Stmt, call *syntax.CallExpr, signals uint8) (trapEffect, bool) {
	if later, ok := signalTrapCall(call); ok {
		return trapEffect{left: signals &^ later.signals}, true
	}
	if exitsShell(call) {
		return trapEffect{exits: true}, true
	}
	return f.callAfterTrap(stmt, call, signals)
}

// sees holds where a call at a place sees a definition, and narrows span
// to the definitions run that give the same answer.
func (f *trapFlow) sees(fn scriptFunc, call uint) bool {
	seen := f.funcs.seen(fn, max(f.time, call), call)
	if fn.top && fn.decl.Pos().Offset() >= call {
		if seen {
			f.span.from = max(f.span.from, fn.index+1)
		} else {
			f.span.to = min(f.span.to, fn.index+1)
		}
	}
	return seen
}

// seq follows a path that did e and then next. The work of a path is
// dropped once every signal is replaced on it, since the handler no longer
// runs there, and counts once the path exits.
func (e trapEffect) seq(next trapEffect) trapEffect {
	if next.found || e.work && next.exits {
		return trapEffect{found: true}
	}
	exits := e.exits || next.exits
	if next.left == 0 {
		return trapEffect{exits: exits}
	}
	return trapEffect{work: e.work || next.work, exits: exits, left: next.left}
}

// orPath joins the effects of two paths of which either may run.
func (e trapEffect) orPath(o trapEffect) trapEffect {
	return trapEffect{
		found: e.found || o.found,
		work:  e.work || o.work,
		exits: e.exits || o.exits,
		left:  e.left | o.left,
	}
}

// callAfterTrap follows a call of a function of the script through its
// body, so a trap it replaces and an exit it runs on every path hold for
// the commands after the call. A call through command or builtin skips
// the function; a call or a definition with a redirection that may not
// open may not run it; a function already being followed is not followed
// again; in an opaque script none is, as in main. Inside a
// function followed, the functions defined are those run before the call
// at the top level that runs it. The effect of a call holds for the span
// of definitions run in which its body sees the same functions, and is
// kept for that span.
func (f *trapFlow) callAfterTrap(stmt *syntax.Stmt, call *syntax.CallExpr, signals uint8) (trapEffect, bool) {
	if f.funcs.opaque || len(call.Args) == 0 || riskyRedirect(stmt.Redirs) {
		return trapEffect{}, false
	}
	name := wordLit(call.Args[0])
	at := call.Pos().Offset()
	fn, ok := f.funcs.decls[name]
	if !ok || f.blocked[name] || f.visiting[name] || !f.sees(fn, at) {
		return trapEffect{}, false
	}
	time := max(f.time, at)
	entry, ok := f.entry(name, signals, f.funcs.epoch(time))
	if !ok {
		outer, outerTime := f.span, f.time
		f.span, f.time = anyEpoch, time
		f.visiting[name] = true
		effect := f.afterTrap(fn.decl.Body, signals)
		delete(f.visiting, name)
		entry = trapEntry{signals: signals, span: f.span, effect: effect}
		f.memo[name] = append(f.memo[name], entry)
		f.span, f.time = outer, outerTime
	}
	f.span = f.span.meet(entry.span)
	return entry.effect, true
}

// entry is the effect kept for a call of name with signals while epoch
// definitions have run.
func (f *trapFlow) entry(name string, signals uint8, epoch int) (trapEntry, bool) {
	for _, entry := range f.memo[name] {
		if entry.signals == signals && entry.span.holds(epoch) {
			return entry, true
		}
	}
	return trapEntry{}, false
}

func (f *trapFlow) listAfterTrap(stmts []*syntax.Stmt, signals uint8) trapEffect {
	out := trapEffect{left: signals}
	for _, stmt := range stmts {
		out = out.seq(f.afterTrap(stmt, out.left))
		if out.left == 0 {
			break
		}
	}
	return out
}

// binaryAfterTrap: the right side runs on every path that goes on from
// the left where the status of the left always chooses it, as in
// true && trap - TERM, and on none where it never does; a left that may
// return or that the status walk cannot follow leaves both, and so does
// any left in an opaque script, as in main.
func (f *trapFlow) binaryAfterTrap(x *syntax.BinaryCmd, signals uint8) trapEffect {
	left := f.afterTrap(x.X, signals)
	if left.left == 0 {
		return left
	}
	right := left.seq(f.afterTrap(x.Y, left.left))
	status := f.status.stmt(x.X)
	runs, skips := status.ok, status.failed
	if x.Op == syntax.OrStmt {
		runs, skips = skips, runs
	}
	switch {
	case f.funcs.opaque, status.unknown || status.ret:
	case !skips:
		return right
	case !runs:
		return left
	}
	return left.orPath(right)
}

func (f *trapFlow) ifAfterTrap(x *syntax.IfClause, signals uint8) trapEffect {
	cond := f.listAfterTrap(x.Cond, signals)
	if cond.left == 0 {
		return cond
	}
	then := cond.seq(f.listAfterTrap(x.Then, cond.left))
	switch {
	case x.Else == nil:
		return then.orPath(cond)
	case len(x.Else.Cond) == 0:
		return then.orPath(cond.seq(f.listAfterTrap(x.Else.Then, cond.left)))
	}
	return then.orPath(cond.seq(f.ifAfterTrap(x.Else, cond.left)))
}

// caseAfterTrap: the word, with a command substitution in it, runs before
// any item; without a default item a word may match no item and keep every
// signal.
func (f *trapFlow) caseAfterTrap(x *syntax.CaseClause, signals uint8) trapEffect {
	if runsLoop(x.Word) {
		return trapEffect{found: true}
	}
	word := trapEffect{work: doesWork(x.Word), left: signals}
	out, hasDefault := trapEffect{}, false
	for _, item := range x.Items {
		out = out.orPath(word.seq(f.listAfterTrap(item.Stmts, signals)))
		for _, pattern := range item.Patterns {
			hasDefault = hasDefault || wordLit(pattern) == "*"
		}
	}
	if !hasDefault {
		out = out.orPath(word)
	}
	return out
}

func runsLoop(node syntax.Node) bool {
	return foregroundWalk(node, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.WhileClause, *syntax.ForClause:
			return true
		}
		return false
	})
}

// doesWork finds a command other than a builtin that only waits, reports
// or tests, including one in a command substitution.
func doesWork(node syntax.Node) bool {
	return foregroundWalk(node, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return false
		}
		switch wordLit(call.Args[0]) {
		case "wait", "trap", "exit", "return", "exec", "echo", "printf", ":", "true", "false", "[", "test":
			return false
		}
		return true
	})
}
