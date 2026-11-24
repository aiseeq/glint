package shellrules

import "mvdan.cc/sh/v3/syntax"

// handlerPaths says how the paths through a piece of a trap handler end:
// some exit the script, some go on to the next command, some return from
// the function, and unknown marks a structure whose paths are not followed.
type handlerPaths struct {
	exit, fall, ret, unknown bool
}

var (
	pathsFall    = handlerPaths{fall: true}
	pathsUnknown = handlerPaths{unknown: true}
)

// alwaysExits holds for a handler that exits on every path; sure is false
// where the rule cannot tell, and then the trap is left alone.
func (p handlerPaths) alwaysExits() (exits, sure bool) {
	if p.unknown {
		return false, false
	}
	return p.exit && !p.fall, true
}

// returned maps a return to the caller going on, as at the end of a
// function or a trap action. One that returns on one path and exits on
// another, such as a guard against running cleanup twice, is not followed.
func (p handlerPaths) returned() handlerPaths {
	if p.ret && p.exit {
		return pathsUnknown
	}
	return handlerPaths{exit: p.exit, fall: p.fall || p.ret, unknown: p.unknown}
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
		if !out.fall {
			break
		}
		next := s.stmt(stmt)
		out = handlerPaths{
			exit:    out.exit || next.exit,
			ret:     out.ret || next.ret,
			unknown: out.unknown || next.unknown,
			fall:    next.fall,
		}
	}
	return out
}

// stmt treats a subshell, a pipeline, a command substitution and a
// background command as not exiting: exit there ends only a child shell.
func (s *exitScan) stmt(stmt *syntax.Stmt) handlerPaths {
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
	if !cond.fall || cond.unknown {
		return cond
	}
	then := s.list(x.Then)
	other := pathsFall
	switch {
	case x.Else == nil:
	case len(x.Else.Cond) == 0:
		other = s.list(x.Else.Then)
	default:
		other = s.ifClause(x.Else)
	}
	return handlerPaths{
		exit:    cond.exit || then.exit || other.exit,
		ret:     cond.ret || then.ret || other.ret,
		fall:    then.fall || other.fall,
		unknown: then.unknown || other.unknown,
	}
}

// binary: an exit on the right of && or || runs only on one outcome of the
// left side; a pipeline runs its commands in child shells.
func (s *exitScan) binary(x *syntax.BinaryCmd) handlerPaths {
	if x.Op != syntax.AndStmt && x.Op != syntax.OrStmt {
		return pathsFall
	}
	left := s.stmt(x.X)
	if !left.fall || left.unknown {
		return left
	}
	right := s.stmt(x.Y)
	return handlerPaths{exit: left.exit || right.exit, ret: left.ret || right.ret, unknown: right.unknown, fall: true}
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
		exits := paths.exit && !paths.fall && !paths.ret
		allExit = allExit && exits
		anyExit = anyExit || paths.exit
		out.ret = out.ret || paths.ret
		for _, pattern := range item.Patterns {
			hasDefault = hasDefault || wordLit(pattern) == "*"
		}
	}
	switch {
	case !anyExit:
		out.fall = true
		return out
	case allExit && hasDefault:
		return handlerPaths{exit: true}
	}
	return pathsUnknown
}

// loopPaths does not follow an exit or return inside a loop: whether the
// loop runs it depends on the data.
func loopPaths(body handlerPaths) handlerPaths {
	if body.exit || body.ret || body.unknown {
		return pathsUnknown
	}
	return pathsFall
}
