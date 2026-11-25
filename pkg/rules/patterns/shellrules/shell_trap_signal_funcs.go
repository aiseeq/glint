package shellrules

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// scriptFuncs knows the functions of a script: last holds the last body
// defined under each name anywhere, which a trap handler runs once the
// script has defined it; decls the definition of a function defined once,
// never unset and not hidden by an alias, either at the top level of the
// script or as a command of the body of a function, which a call surely
// runs where the definition is seen; tops the places of the definitions
// at the top level, in order. sourced marks a script that reads another
// file with . or source. opaque marks one the walk cannot see through, as
// main took every script: it may define or run a function out of sight,
// through eval, a sourced file or a command named by a variable or a
// substitution, or it defines a function named as a builtin the rule
// reads.
type scriptFuncs struct {
	last    map[string]*syntax.Stmt
	decls   map[string]scriptFunc
	tops    []uint
	sourced bool
	opaque  bool
}

// scriptFunc is a definition at the top level of the script, with its
// index among the definitions there, or a command of a function body that
// ends at scope.
type scriptFunc struct {
	decl  *syntax.FuncDecl
	top   bool
	index int
	scope uint
}

// readBuiltins are the builtins whose meaning the rule reads: a function
// of such a name would change what a trap, an exit or a status means.
var readBuiltins = map[string]bool{
	"trap": true, "exit": true, "return": true, "exec": true, "true": true, "false": true, ":": true,
	"command": true, "builtin": true, "unset": true, "alias": true, "source": true, ".": true, "eval": true,
	"wait": true, "echo": true, "printf": true, "test": true, "[": true,
}

func newScriptFuncs(file *syntax.File) *scriptFuncs {
	s := &scriptFuncs{last: make(map[string]*syntax.Stmt), decls: make(map[string]scriptFunc)}
	count := make(map[string]int)
	hidden := make(map[string]bool)
	places := make(map[*syntax.FuncDecl]scriptFunc)
	for _, stmt := range file.Stmts {
		if decl, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
			places[decl] = scriptFunc{decl: decl, top: true, index: len(s.tops)}
			s.tops = append(s.tops, decl.Pos().Offset())
		}
	}
	syntax.Walk(file, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.FuncDecl:
			s.last[x.Name.Value] = x.Body
			count[x.Name.Value]++
			s.opaque = s.opaque || readBuiltins[x.Name.Value]
			if block, ok := x.Body.Cmd.(*syntax.Block); ok {
				for _, stmt := range block.Stmts {
					if decl, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
						places[decl] = scriptFunc{decl: decl, scope: x.Body.End().Offset()}
					}
				}
			}
		case *syntax.CallExpr:
			s.hideNames(x, hidden)
			s.noteRunner(x)
		}
		return true
	})
	for decl, fn := range places {
		if name := decl.Name.Value; count[name] == 1 && !hidden[name] {
			s.decls[name] = fn
		}
	}
	return s
}

// noteRunner marks a command that reads a file other than /dev/null,
// evaluates a string or is named by a variable or a substitution.
func (s *scriptFuncs) noteRunner(call *syntax.CallExpr) {
	args, _ := unprefixed(call.Args)
	if len(args) == 0 {
		return
	}
	name, known := wordValue(args[0])
	switch {
	case !known, name == "eval":
		s.opaque = true
	case name == "." || name == "source":
		if len(args) < 2 || wordLit(args[1]) != "/dev/null" {
			s.sourced, s.opaque = true, true
		}
	}
}

// seen holds where a call at the given place sees a definition while the
// command of the top level of the script that runs it is at time: one at
// the top level above that command, or one in a function body above the
// call, inside that body.
func (s *scriptFuncs) seen(fn scriptFunc, time, call uint) bool {
	if fn.top {
		return fn.decl.Pos().Offset() < time
	}
	return call >= fn.decl.End().Offset() && call < fn.scope
}

// at is the body a call surely runs, taken where the call is written.
func (s *scriptFuncs) at(name string, call syntax.Pos) *syntax.Stmt {
	fn, ok := s.decls[name]
	if !ok || !s.seen(fn, call.Offset(), call.Offset()) {
		return nil
	}
	return fn.decl.Body
}

// epoch counts the definitions at the top level of the script that have
// run at the given time.
func (s *scriptFuncs) epoch(time uint) int {
	n, _ := slices.BinarySearch(s.tops, time)
	return n
}

// hideNames records the names unset, functions too unless -v is given,
// and the names given to an alias, read without their quotes and escapes;
// an alias named as a builtin the rule reads makes the script opaque, as a
// function of that name does, and so does one named at run time.
func (s *scriptFuncs) hideNames(call *syntax.CallExpr, hidden map[string]bool) {
	if len(call.Args) == 0 {
		return
	}
	switch wordLit(call.Args[0]) {
	case "unset":
		for _, arg := range call.Args[1:] {
			name := wordLit(arg)
			if strings.HasPrefix(name, "-") {
				if strings.Contains(name, "v") {
					return
				}
				continue
			}
			hidden[name] = true
		}
	case "alias":
		for _, arg := range call.Args[1:] {
			text, known := wordValue(arg)
			name, _, _ := strings.Cut(text, "=")
			hidden[name] = true
			s.opaque = s.opaque || !known || readBuiltins[name]
		}
	}
}

// riskyRedirect finds a redirection that may fail to open, as one to a
// file or to a descriptor above 2, which may be closed: the command does
// not run then, and its status is 1. /dev/null, a standard stream, its
// device, a closed descriptor and a here-document always open.
func riskyRedirect(redirs []*syntax.Redirect) bool {
	for _, r := range redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			continue
		case syntax.DplIn, syntax.DplOut:
			if target := wordLit(r.Word); target == "-" || stdStream(target) {
				continue
			}
		}
		if !alwaysOpens(wordLit(r.Word)) {
			return true
		}
	}
	return false
}

// alwaysOpens holds for /dev/null and the devices of the standard streams.
func alwaysOpens(path string) bool {
	switch path {
	case "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr":
		return true
	}
	fd, ok := strings.CutPrefix(path, "/dev/fd/")
	return ok && stdStream(fd)
}

// stdStream holds for the descriptors 0, 1 and 2, open in any script.
func stdStream(word string) bool {
	return word == "0" || word == "1" || word == "2"
}
