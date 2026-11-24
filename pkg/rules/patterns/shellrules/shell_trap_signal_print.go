package shellrules

import "mvdan.cc/sh/v3/syntax"

// printOnlyStmts finds echo and printf commands whose output no command
// substitution, pipeline or redirection to a file captures, also through
// the functions they run in: a flag such a command prints is not read.
func printOnlyStmts(file *syntax.File, funcs map[string]*syntax.Stmt) map[*syntax.Stmt]bool {
	captured := make(map[*syntax.Stmt]bool)
	capturedFuncs := make(map[string]bool)
	var queue []string
	capture := func(node syntax.Node) {
		syntax.Walk(node, func(n syntax.Node) bool {
			switch x := n.(type) {
			case *syntax.Stmt:
				captured[x] = true
			case *syntax.CallExpr:
				name := callName(x)
				if _, ok := funcs[name]; ok && !capturedFuncs[name] {
					capturedFuncs[name] = true
					queue = append(queue, name)
				}
			}
			return true
		})
	}
	syntax.Walk(file, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			capture(x)
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				capture(x)
			}
		case *syntax.Stmt:
			if redirectsOutput(x.Redirs) {
				capture(x)
			}
		}
		return true
	})
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		capture(funcs[name])
	}
	prints := make(map[*syntax.Stmt]bool)
	syntax.Walk(file, func(n syntax.Node) bool {
		if stmt, ok := n.(*syntax.Stmt); ok && !captured[stmt] && printsOnly(stmt) {
			prints[stmt] = true
		}
		return true
	})
	return prints
}

// printsOnly holds for echo or printf without -v and without a command
// substitution in its words.
func printsOnly(stmt *syntax.Stmt) bool {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	switch callName(call) {
	case "echo":
	case "printf":
		for _, arg := range call.Args {
			if wordLit(arg) == "-v" {
				return false
			}
		}
	default:
		return false
	}
	substituted := false
	syntax.Walk(call, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			substituted = true
		}
		return !substituted
	})
	return !substituted
}

// redirectsOutput holds for a redirection of standard output anywhere other
// than standard error or /dev/null.
func redirectsOutput(redirs []*syntax.Redirect) bool {
	for _, r := range redirs {
		fd := "1"
		if r.N != nil {
			fd = r.N.Value
		}
		switch r.Op {
		case syntax.RdrAll, syntax.AppAll:
			if wordLit(r.Word) != "/dev/null" {
				return true
			}
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob:
			if fd == "1" && wordLit(r.Word) != "/dev/null" {
				return true
			}
		case syntax.DplOut:
			if fd == "1" && wordLit(r.Word) != "2" {
				return true
			}
		}
	}
	return false
}
