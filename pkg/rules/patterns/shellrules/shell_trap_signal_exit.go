package shellrules

import "mvdan.cc/sh/v3/syntax"

// handlerPaths says how the paths through a piece of a trap handler end:
// some exit the script, some go on to the next command with status zero
// (ok) or non-zero (failed), some return from the function, and unknown
// marks a structure whose paths are not followed. The status decides which
// side of && and || and which branch of if runs next.
type handlerPaths struct {
	exit, ok, failed, ret, unknown bool
}

var (
	pathsFall    = handlerPaths{ok: true, failed: true}
	pathsUnknown = handlerPaths{unknown: true}
)

func (p handlerPaths) fall() bool {
	return p.ok || p.failed
}

// join holds the paths of either of two pieces.
func (p handlerPaths) join(q handlerPaths) handlerPaths {
	return handlerPaths{
		exit:    p.exit || q.exit,
		ok:      p.ok || q.ok,
		failed:  p.failed || q.failed,
		ret:     p.ret || q.ret,
		unknown: p.unknown || q.unknown,
	}
}

// alwaysExits holds for a handler that exits on every path; sure is false
// where the rule cannot tell, and then the trap is left alone.
func (p handlerPaths) alwaysExits() (exits, sure bool) {
	if p.unknown {
		return false, false
	}
	return p.exit && !p.fall(), true
}

// returned maps a return to the caller going on, as at the end of a
// function or a trap action. One that returns on one path and exits on
// another, such as a guard against running cleanup twice, is not followed.
func (p handlerPaths) returned() handlerPaths {
	if p.ret && p.exit {
		return pathsUnknown
	}
	return handlerPaths{exit: p.exit, ok: p.ok || p.ret, failed: p.failed || p.ret, unknown: p.unknown}
}

// handler follows the paths of a trap action.
func (s *exitScan) handler(action *syntax.File) handlerPaths {
	return s.list(action.Stmts).returned()
}

// exitScan follows the paths of a trap handler through the functions
// defined in the script.
type exitScan struct {
	funcs    map[string]*syntax.Stmt
	memo     map[string]handlerPaths
	visiting map[string]bool
}

func newExitScan(funcs map[string]*syntax.Stmt) *exitScan {
	return &exitScan{funcs: funcs, memo: make(map[string]handlerPaths), visiting: make(map[string]bool)}
}

func (s *exitScan) list(stmts []*syntax.Stmt) handlerPaths {
	out := pathsFall
	for _, stmt := range stmts {
		if !out.fall() {
			break
		}
		next := s.stmt(stmt)
		out = handlerPaths{
			exit:    out.exit || next.exit,
			ret:     out.ret || next.ret,
			unknown: out.unknown || next.unknown,
			ok:      next.ok,
			failed:  next.failed,
		}
	}
	return out
}

// stmt treats a subshell, a pipeline, a command substitution and a
// background command as not exiting: exit there ends only a child shell.
// ! swaps the status the command goes on with.
func (s *exitScan) stmt(stmt *syntax.Stmt) handlerPaths {
	paths := s.command(stmt)
	if stmt.Negated {
		paths.ok, paths.failed = paths.failed, paths.ok
	}
	return paths
}

func (s *exitScan) command(stmt *syntax.Stmt) handlerPaths {
	if stmt.Background || stmt.Coprocess || stmt.Disown {
		return pathsFall
	}
	switch x := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		return s.call(x)
	case *syntax.Block:
		return s.list(x.Stmts)
	case *syntax.IfClause:
		return s.ifClause(x)
	case *syntax.BinaryCmd:
		return s.binary(x)
	case *syntax.CaseClause:
		return s.caseClause(x)
	case *syntax.WhileClause:
		return loopPaths(s.list(append(append([]*syntax.Stmt(nil), x.Cond...), x.Do...)))
	case *syntax.ForClause:
		return loopPaths(s.list(x.Do))
	case *syntax.TimeClause:
		if x.Stmt != nil {
			return s.stmt(x.Stmt)
		}
	}
	return pathsFall
}

func (s *exitScan) call(call *syntax.CallExpr) handlerPaths {
	args := call.Args
	for len(args) > 0 && (wordLit(args[0]) == "builtin" || wordLit(args[0]) == "command") {
		args = args[1:]
	}
	if len(args) == 0 {
		return pathsFall
	}
	name := wordLit(args[0])
	switch name {
	case "exit":
		return handlerPaths{exit: true}
	case "return":
		return handlerPaths{ret: true}
	case "true", ":":
		return handlerPaths{ok: true}
	case "eval", ".", "source":
		return pathsUnknown
	}
	if body, ok := s.funcs[name]; ok {
		return s.function(name, body)
	}
	return pathsFall
}

func (s *exitScan) function(name string, body *syntax.Stmt) handlerPaths {
	if paths, ok := s.memo[name]; ok {
		return paths
	}
	if s.visiting[name] {
		return pathsFall
	}
	s.visiting[name] = true
	paths := s.stmt(body).returned()
	delete(s.visiting, name)
	s.memo[name] = paths
	return paths
}

func (s *exitScan) ifClause(x *syntax.IfClause) handlerPaths {
	cond := s.list(x.Cond)
	if cond.unknown {
		return cond
	}
	out := handlerPaths{exit: cond.exit, ret: cond.ret}
	if cond.ok {
		out = out.join(s.list(x.Then))
	}
	if cond.failed {
		switch {
		case x.Else == nil:
			// if without a branch taken has status zero.
			out.ok = true
		case len(x.Else.Cond) == 0:
			out = out.join(s.list(x.Else.Then))
		default:
			out = out.join(s.ifClause(x.Else))
		}
	}
	return out
}

// binary: the right side of && runs where the left goes on with status
// zero, that of || where it goes on with a non-zero one, so
// "cmd && exit 0 || exit 1" exits on every path; a pipeline runs its
// commands in child shells.
func (s *exitScan) binary(x *syntax.BinaryCmd) handlerPaths {
	if x.Op != syntax.AndStmt && x.Op != syntax.OrStmt {
		return pathsFall
	}
	left := s.stmt(x.X)
	if left.unknown {
		return left
	}
	out := handlerPaths{exit: left.exit, ret: left.ret}
	runs := left.ok
	if x.Op == syntax.AndStmt {
		out.failed = left.failed
	} else {
		out.ok = left.ok
		runs = left.failed
	}
	if runs {
		out = out.join(s.stmt(x.Y))
	}
	return out
}

// caseClause follows a case only where every item exits, with a default
// item, or where no item exits; a case that exits for some words, as a
// handler that takes the signal name, is not followed.
func (s *exitScan) caseClause(x *syntax.CaseClause) handlerPaths {
	out := handlerPaths{}
	allExit, anyExit, hasDefault := true, false, false
	for _, item := range x.Items {
		paths := s.list(item.Stmts)
		if paths.unknown {
			return pathsUnknown
		}
		exits := paths.exit && !paths.fall() && !paths.ret
		allExit = allExit && exits
		anyExit = anyExit || paths.exit
		out.ret = out.ret || paths.ret
		for _, pattern := range item.Patterns {
			hasDefault = hasDefault || wordLit(pattern) == "*"
		}
	}
	switch {
	case !anyExit:
		out.ok, out.failed = true, true
		return out
	case allExit && hasDefault:
		return handlerPaths{exit: true}
	}
	return pathsUnknown
}

// loopPaths does not follow an exit inside a loop: whether the loop runs
// it depends on the data. A loop that can only return or go on does both.
func loopPaths(body handlerPaths) handlerPaths {
	if body.exit || body.unknown {
		return pathsUnknown
	}
	return handlerPaths{ok: true, failed: true, ret: body.ret}
}
