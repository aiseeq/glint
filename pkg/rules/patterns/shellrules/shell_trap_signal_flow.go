package shellrules

import "mvdan.cc/sh/v3/syntax"

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
// which statements can run after it.
type trapFlow struct {
	order []*syntax.Stmt
	where map[*syntax.Stmt]stmtPlace
	calls map[string][]*syntax.Stmt
}

func newTrapFlow(file *syntax.File) *trapFlow {
	f := &trapFlow{where: make(map[*syntax.Stmt]stmtPlace), calls: make(map[string][]*syntax.Stmt)}
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
	return f
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
	name := wordLit(call.Args[0])
	f.calls[name] = append(f.calls[name], stmt)
}

// followedByWork reports whether some sequence of statements that runs
// after the trap does work while the handler is still set.
func (f *trapFlow) followedByWork(stmt *syntax.Stmt, signals uint8) bool {
	for _, tail := range f.continuations(stmt, make(map[string]bool)) {
		if trapFollowedByWork(tail, signals) {
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
func trapFollowedByWork(stmts []*syntax.Stmt, signals uint8) bool {
	if waitThenCleanup(stmts) {
		return false
	}
	out := trapEffect{left: signals}
	for _, stmt := range stmts {
		if stmt.Background {
			continue
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && callName(call) == "return" {
			return out.work
		}
		out = out.seq(afterTrap(stmt, out.left))
		if out.left == 0 {
			return out.found
		}
	}
	return out.work
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
// not run. exit and exec of a command end their path. A subshell, a
// pipeline and a background command neither replace nor end anything in
// the script. A return in a branch is taken to go on, as the caller does.
func afterTrap(stmt *syntax.Stmt, signals uint8) trapEffect {
	if stmt.Background {
		return trapEffect{left: signals}
	}
	switch x := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if later, ok := signalTrapCall(x); ok {
			return trapEffect{left: signals &^ later.signals}
		}
		if exitsShell(x) {
			return trapEffect{exits: true}
		}
	case *syntax.WhileClause, *syntax.ForClause:
		return trapEffect{found: true}
	case *syntax.Block:
		return listAfterTrap(x.Stmts, signals)
	case *syntax.IfClause:
		return ifAfterTrap(x, signals)
	case *syntax.CaseClause:
		return caseAfterTrap(x, signals)
	case *syntax.BinaryCmd:
		if x.Op == syntax.AndStmt || x.Op == syntax.OrStmt {
			return binaryAfterTrap(x, signals)
		}
	}
	if runsLoop(stmt) {
		return trapEffect{found: true}
	}
	return trapEffect{work: doesWork(stmt), left: signals}
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

func listAfterTrap(stmts []*syntax.Stmt, signals uint8) trapEffect {
	out := trapEffect{left: signals}
	for _, stmt := range stmts {
		out = out.seq(afterTrap(stmt, out.left))
		if out.left == 0 {
			break
		}
	}
	return out
}

func binaryAfterTrap(x *syntax.BinaryCmd, signals uint8) trapEffect {
	left := afterTrap(x.X, signals)
	if left.left == 0 {
		return left
	}
	return left.orPath(left.seq(afterTrap(x.Y, left.left)))
}

func ifAfterTrap(x *syntax.IfClause, signals uint8) trapEffect {
	cond := listAfterTrap(x.Cond, signals)
	if cond.left == 0 {
		return cond
	}
	then := cond.seq(listAfterTrap(x.Then, cond.left))
	switch {
	case x.Else == nil:
		return then.orPath(cond)
	case len(x.Else.Cond) == 0:
		return then.orPath(cond.seq(listAfterTrap(x.Else.Then, cond.left)))
	}
	return then.orPath(cond.seq(ifAfterTrap(x.Else, cond.left)))
}

// caseAfterTrap: the word, with a command substitution in it, runs before
// any item; without a default item a word may match no item and keep every
// signal.
func caseAfterTrap(x *syntax.CaseClause, signals uint8) trapEffect {
	if runsLoop(x.Word) {
		return trapEffect{found: true}
	}
	word := trapEffect{work: doesWork(x.Word), left: signals}
	out, hasDefault := trapEffect{}, false
	for _, item := range x.Items {
		out = out.orPath(word.seq(listAfterTrap(item.Stmts, signals)))
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
