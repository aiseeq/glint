package shellrules

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// scriptFuncs knows the functions of a script: last holds the last body
// defined under each name anywhere, which a trap handler runs once the
// script has defined it; defs every definition of each name; decls the
// definition of a function defined once, never unset and not hidden by an
// alias, either at the top level of the script or as a command of the body
// of a function, which a call surely runs where the definition is seen;
// tops the places of the definitions at the top level, in order; topCalls
// the places of the calls outside any function body, which run in the
// order they are written. sourced marks a script that reads another file
// with . or source, opaque one that also may define or run a function
// through eval or through a command named by a variable or a substitution.
type scriptFuncs struct {
	last     map[string]*syntax.Stmt
	defs     map[string][]scriptFunc
	decls    map[string]scriptFunc
	tops     []uint
	topCalls map[uint]bool
	sourced  bool
	opaque   bool
}

// scriptFunc is a definition: at the top level of the script, with its
// index among the definitions there, or a command of a function body that
// ends at scope, or elsewhere, which may run at any time.
type scriptFunc struct {
	decl  *syntax.FuncDecl
	top   bool
	index int
	scope uint
}

func newScriptFuncs(file *syntax.File) *scriptFuncs {
	s := &scriptFuncs{
		last:     make(map[string]*syntax.Stmt),
		defs:     make(map[string][]scriptFunc),
		decls:    make(map[string]scriptFunc),
		topCalls: make(map[uint]bool),
	}
	hidden := make(map[string]bool)
	places := make(map[*syntax.FuncDecl]scriptFunc)
	for _, stmt := range file.Stmts {
		if decl, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
			places[decl] = scriptFunc{decl: decl, top: true, index: len(s.tops)}
			s.tops = append(s.tops, decl.Pos().Offset())
		}
	}
	var stack []syntax.Node
	depth := 0
	syntax.Walk(file, func(n syntax.Node) bool {
		if n == nil {
			if _, ok := stack[len(stack)-1].(*syntax.FuncDecl); ok {
				depth--
			}
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch x := n.(type) {
		case *syntax.FuncDecl:
			depth++
			fn, ok := places[x]
			if !ok {
				fn = scriptFunc{decl: x}
			}
			s.defs[x.Name.Value] = append(s.defs[x.Name.Value], fn)
			s.last[x.Name.Value] = x.Body
			if block, ok := x.Body.Cmd.(*syntax.Block); ok {
				for _, stmt := range block.Stmts {
					if decl, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
						places[decl] = scriptFunc{decl: decl, scope: x.Body.End().Offset()}
					}
				}
			}
		case *syntax.CallExpr:
			hideNames(x, hidden)
			s.noteRunner(x)
			if depth == 0 {
				s.topCalls[x.Pos().Offset()] = true
			}
		}
		return true
	})
	for name, defs := range s.defs {
		if fn := defs[0]; len(defs) == 1 && !hidden[name] && (fn.top || fn.scope != 0) {
			s.decls[name] = fn
		}
	}
	return s
}

// noteRunner marks a command that reads a file other than /dev/null,
// evaluates a string or is named by a variable or a substitution.
func (s *scriptFuncs) noteRunner(call *syntax.CallExpr) {
	args := call.Args
	for len(args) > 0 && (wordLit(args[0]) == "builtin" || wordLit(args[0]) == "command") {
		args = args[1:]
	}
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
// the top level above that command, one in a function body above the call,
// inside that body, and one elsewhere at any time.
func (s *scriptFuncs) seen(fn scriptFunc, time, call uint) bool {
	switch {
	case fn.top:
		return fn.decl.Pos().Offset() < time
	case fn.scope != 0:
		return call >= fn.decl.End().Offset() && call < fn.scope
	}
	return true
}

// at is the body a call surely runs, taken where the call is written; none
// in a script that may run or define a function out of sight.
func (s *scriptFuncs) at(name string, call syntax.Pos) *syntax.Stmt {
	fn, ok := s.decls[name]
	if !ok || s.opaque || !s.seen(fn, call.Offset(), call.Offset()) {
		return nil
	}
	return fn.decl.Body
}

// hidesAt holds where a function may hide the builtin of its name at a
// call: a definition at the top level hides it for the calls outside any
// function body below it, and for every call in a function body, which
// may run at any later time; any other definition hides it everywhere.
func (s *scriptFuncs) hidesAt(name string, call syntax.Pos) bool {
	for _, fn := range s.defs[name] {
		if !hides(name, fn.decl.Body) {
			continue
		}
		if !fn.top || !s.topCalls[call.Offset()] || s.seen(fn, call.Offset(), call.Offset()) {
			return true
		}
	}
	return false
}

// epoch counts the definitions at the top level of the script that have
// run at the given time.
func (s *scriptFuncs) epoch(time uint) int {
	n, _ := slices.BinarySearch(s.tops, time)
	return n
}

// hides holds where a function body hides the builtin of its name: one
// that only passes its arguments on to that builtin is the builtin.
func hides(name string, body *syntax.Stmt) bool {
	return body != nil && !passesTo(name, body)
}

// passesTo holds for a body that is just builtin NAME "$@" or
// command NAME "$@", run in the foreground where it surely opens its
// redirections.
func passesTo(name string, body *syntax.Stmt) bool {
	block, ok := body.Cmd.(*syntax.Block)
	if !ok || len(block.Stmts) != 1 || riskyRedirect(body.Redirs) {
		return false
	}
	stmt := block.Stmts[0]
	if stmt.Background || stmt.Coprocess || stmt.Negated || riskyRedirect(stmt.Redirs) {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 3 {
		return false
	}
	prefix := wordLit(call.Args[0])
	return (prefix == "builtin" || prefix == "command") && wordLit(call.Args[1]) == name && allArgs(call.Args[2])
}

// allArgs holds for the word "$@".
func allArgs(word *syntax.Word) bool {
	if len(word.Parts) != 1 {
		return false
	}
	quoted, ok := word.Parts[0].(*syntax.DblQuoted)
	if !ok || len(quoted.Parts) != 1 {
		return false
	}
	param, ok := quoted.Parts[0].(*syntax.ParamExp)
	return ok && param.Param != nil && param.Param.Value == "@" && param.Exp == nil && param.Index == nil && param.Slice == nil && param.Repl == nil
}

// hideNames records the names unset, functions too unless -v is given,
// and the names given to an alias.
func hideNames(call *syntax.CallExpr, hidden map[string]bool) {
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
			if lit, ok := arg.Parts[0].(*syntax.Lit); ok {
				name, _, _ := strings.Cut(lit.Value, "=")
				hidden[name] = true
			}
		}
	}
}

// riskyRedirect finds a redirection that may fail to open, as one to a
// file: the command does not run then, and its status is 1. A device of
// the standard streams, a duplicated or closed descriptor and a
// here-document always open.
func riskyRedirect(redirs []*syntax.Redirect) bool {
	for _, r := range redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			continue
		case syntax.DplIn, syntax.DplOut:
			if target := wordLit(r.Word); target == "-" || isDescriptor(target) {
				continue
			}
		}
		if !alwaysOpens(wordLit(r.Word)) {
			return true
		}
	}
	return false
}

// alwaysOpens holds for /dev/null and the devices of the standard streams
// and of an open descriptor.
func alwaysOpens(path string) bool {
	switch path {
	case "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr":
		return true
	}
	fd, ok := strings.CutPrefix(path, "/dev/fd/")
	return ok && isDescriptor(fd)
}

func isDescriptor(word string) bool {
	if word == "" {
		return false
	}
	for _, c := range word {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
