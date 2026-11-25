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

// exitScan follows the paths of a trap handler, or of a command of the
// script, through the functions defined in the script: body gives the
// body a call at a place runs, memo the paths of each function followed
// and stmts those of each command. redirects marks the scan of a status
// that chooses a path, where a redirection that may not open fails the
// command; a handler that exits through such a command is taken to exit.
type exitScan struct {
	body      func(name string, at syntax.Pos) *syntax.Stmt
	redirects bool
	memo      map[string]handlerPaths
	visiting  map[string]bool
	stmts     map[*syntax.Stmt]handlerPaths
}

// handlerExits follows a handler, which runs once the script has defined
// its functions, into the last definition of each.
func (s *scriptFuncs) handlerExits() *exitScan {
	return &exitScan{
		body:     func(name string, _ syntax.Pos) *syntax.Stmt { return s.last[name] },
		memo:     make(map[string]handlerPaths),
		visiting: make(map[string]bool),
		stmts:    make(map[*syntax.Stmt]handlerPaths),
	}
}

// statusScan follows a command of the script into the functions a call
// surely runs where it is written.
func (s *scriptFuncs) statusScan() *exitScan {
	return &exitScan{
		body:      s.at,
		redirects: true,
		memo:      make(map[string]handlerPaths),
		visiting:  make(map[string]bool),
		stmts:     make(map[*syntax.Stmt]handlerPaths),
	}
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
// In a status scan a redirection that may not open keeps the command from
// running with status 1. ! swaps the status the command goes on with.
func (s *exitScan) stmt(stmt *syntax.Stmt) handlerPaths {
	if paths, ok := s.stmts[stmt]; ok {
		return paths
	}
	paths := s.command(stmt)
	if s.redirects && riskyRedirect(stmt.Redirs) {
		paths = paths.join(handlerPaths{failed: true})
	}
	if stmt.Negated {
		paths.ok, paths.failed = paths.failed, paths.ok
	}
	s.stmts[stmt] = paths
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

// builtinPaths are the paths of the builtins the scan reads; a script
// that defines a function of such a name is not walked for its status.
var builtinPaths = map[string]handlerPaths{
	"exit":   {exit: true},
	"return": {ret: true},
	"true":   {ok: true},
	":":      {ok: true},
	"false":  {failed: true},
	"eval":   pathsUnknown,
	".":      pathsUnknown,
	"source": pathsUnknown,
}

// call: command and builtin before the name skip functions.
func (s *exitScan) call(call *syntax.CallExpr) handlerPaths {
	args, prefixed := unprefixed(call.Args)
	if len(args) == 0 {
		return pathsFall
	}
	name := wordLit(args[0])
	if paths, ok := builtinPaths[name]; ok {
		return paths
	}
	if body := s.body(name, call.Pos()); body != nil && !prefixed {
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

// unprefixed drops command and builtin before the name of a command, and
// tells whether any stood there.
func unprefixed(args []*syntax.Word) ([]*syntax.Word, bool) {
	n := 0
	for n < len(args) && (wordLit(args[n]) == "builtin" || wordLit(args[n]) == "command") {
		n++
	}
	return args[n:], n > 0
}
