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
// replaces the handler for its signals where it is set on every path. A
// loop before the replacement is long-lived; other work counts if the
// handler remains active afterwards. exit, return and exec of a command
// end the sequence.
func trapFollowedByWork(stmts []*syntax.Stmt, signals uint8) bool {
	if waitThenCleanup(stmts) {
		return false
	}
	work := false
	for _, stmt := range stmts {
		if stmt.Background {
			continue
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && endsShell(call) {
			return work
		}
		switch stmt.Cmd.(type) {
		case *syntax.WhileClause, *syntax.ForClause:
			return true
		}
		if runsLoop(stmt) {
			return true
		}
		work = work || doesWork(stmt)
		signals &^= replacedSignals(stmt)
		if signals == 0 {
			return false
		}
	}
	return work
}

// endsShell holds for exit, return and exec of a command, which replaces
// the shell; exec with redirections only goes on.
func endsShell(call *syntax.CallExpr) bool {
	args := call.Args
	for len(args) > 0 && (wordLit(args[0]) == "builtin" || wordLit(args[0]) == "command") {
		args = args[1:]
	}
	if len(args) == 0 {
		return false
	}
	switch wordLit(args[0]) {
	case "exit", "return":
		return true
	case "exec":
		return len(args) > 1
	}
	return false
}

// foregroundWalk visits what runs in the foreground of stmt, leaving out
// background commands and function definitions.
func foregroundWalk(stmt *syntax.Stmt, visit func(syntax.Node) bool) bool {
	found := false
	syntax.Walk(stmt, func(n syntax.Node) bool {
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

// replacedSignals are the signals stmt sets a new trap for on every path
// through it: in a brace group, in the condition of an if, on the left of
// && and ||, in every branch of an if with else or of a case with a default
// item. A subshell, a background command and a function definition replace
// nothing in the script.
func replacedSignals(stmt *syntax.Stmt) uint8 {
	if stmt.Background {
		return 0
	}
	switch x := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if later, ok := signalTrapCall(x); ok {
			return later.signals
		}
	case *syntax.Block:
		return listReplaced(x.Stmts)
	case *syntax.IfClause:
		return listReplaced(x.Cond) | branchesReplaced(x)
	case *syntax.CaseClause:
		return caseReplaced(x)
	case *syntax.BinaryCmd:
		if x.Op == syntax.AndStmt || x.Op == syntax.OrStmt {
			return replacedSignals(x.X)
		}
	}
	return 0
}

func listReplaced(stmts []*syntax.Stmt) uint8 {
	var signals uint8
	for _, stmt := range stmts {
		signals |= replacedSignals(stmt)
	}
	return signals
}

func branchesReplaced(x *syntax.IfClause) uint8 {
	then := listReplaced(x.Then)
	switch {
	case x.Else == nil:
		return 0
	case len(x.Else.Cond) == 0:
		return then & listReplaced(x.Else.Then)
	}
	return then & (listReplaced(x.Else.Cond) | branchesReplaced(x.Else))
}

func caseReplaced(x *syntax.CaseClause) uint8 {
	signals, hasDefault := ^uint8(0), false
	for _, item := range x.Items {
		signals &= listReplaced(item.Stmts)
		for _, pattern := range item.Patterns {
			hasDefault = hasDefault || wordLit(pattern) == "*"
		}
	}
	if !hasDefault {
		return 0
	}
	return signals
}

func runsLoop(stmt *syntax.Stmt) bool {
	return foregroundWalk(stmt, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.WhileClause, *syntax.ForClause:
			return true
		}
		return false
	})
}

// doesWork finds a command other than a builtin that only waits, reports
// or tests, including one in a command substitution.
func doesWork(stmt *syntax.Stmt) bool {
	return foregroundWalk(stmt, func(n syntax.Node) bool {
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
