package shellrules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	rules.Register(newShellRule("shell-trap-signal-without-exit", "Detects an INT or TERM trap that does not exit while the script continues to work, swallowing the signal", core.SeverityMedium, checkTrapSignalWithoutExit))
}

type signalTrap struct {
	action  string
	signals uint8
	line    int
}

// signalTrapCall reads only statically known trap actions and signals.
func signalTrapCall(call *syntax.CallExpr) (signalTrap, bool) {
	args := call.Args
	for len(args) > 0 && (wordLit(args[0]) == "builtin" || wordLit(args[0]) == "command") {
		args = args[1:]
	}
	if len(args) < 3 || wordLit(args[0]) != "trap" {
		return signalTrap{}, false
	}
	args = args[1:]
	if opt := wordLit(args[0]); opt == "-p" || opt == "-P" || opt == "-l" {
		return signalTrap{}, false
	}
	if wordLit(args[0]) == "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		return signalTrap{}, false
	}
	action, known := wordValue(args[0])
	if !known {
		return signalTrap{}, false
	}
	var signals uint8
	for _, w := range args[1:] {
		switch strings.ToUpper(wordLit(w)) {
		case "INT", "SIGINT", "2":
			signals |= 1
		case "TERM", "SIGTERM", "15":
			signals |= 2
		}
	}
	return signalTrap{action: action, signals: signals, line: int(call.Pos().Line())}, signals != 0
}

func checkTrapSignalWithoutExit(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	if src.Make {
		return nil
	}
	text := strings.Join(src.Ctx.Lines, "\n")
	if !strings.Contains(text, "trap") {
		return nil
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(text), src.Ctx.Path)
	if err != nil {
		// Expected for a script outside the bash grammar (zsh, a template):
		// without its syntax tree no trap handler can be followed.
		return nil
	}
	flow := newScriptFuncs(file).flow(file)
	funcs := flow.funcs.last
	var prints map[*syntax.Stmt]bool
	var out []*core.Violation
	for _, stmt := range flow.order {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || stmt.Background {
			continue
		}
		trap, ok := signalTrapCall(call)
		if !ok || trap.action == "" || trap.action == "-" {
			continue
		}
		action, err := syntax.NewParser().Parse(strings.NewReader(trap.action), "")
		if err != nil {
			// Expected for an action that is not a whole command: what it
			// runs is not known, so the trap is left alone.
			continue
		}
		if exitsAlways, sure := flow.exits.handler(action).alwaysExits(); exitsAlways || !sure {
			continue
		}
		if flow.funcs.sourced && unknownTrapHandler(action.Stmts, funcs) {
			continue
		}
		handled, flags, handlerBodies := trapHandlerEffects(action, funcs)
		handlerBodies[stmt] = true
		if trap.signals&^handled == 0 {
			continue
		}
		if len(flags) > 0 {
			if prints == nil {
				prints = printOnlyStmts(file, funcs)
			}
			if readsTrapFlag(file, flags, handlerBodies, prints) {
				continue
			}
		}
		if !flow.followedByWork(stmt, trap.signals&^handled) {
			continue
		}
		signals := trapSignalNames(trap.signals &^ handled)
		out = appendReport(out, src.Report(r, trap.line, fmt.Sprintf("%s trap does not exit, so the script can continue after the signal", signals), trapSignalSuggestion))
	}
	return out
}

// trapHandlerEffects finds flags and reset-then-reraise actions, following
// locally defined functions with their statically known positional arguments.
func trapHandlerEffects(action syntax.Node, funcs map[string]*syntax.Stmt) (uint8, map[string]bool, map[*syntax.Stmt]bool) {
	scan := &handlerScan{
		funcs:    funcs,
		flags:    make(map[string]bool),
		bodies:   make(map[*syntax.Stmt]bool),
		visiting: make(map[string]bool),
	}
	scan.visit(action, nil, nil)
	return scan.raised, scan.flags, scan.bodies
}

// handlerScan holds what the walk of a trap handler has found so far.
type handlerScan struct {
	funcs         map[string]*syntax.Stmt
	flags         map[string]bool
	bodies        map[*syntax.Stmt]bool
	visiting      map[string]bool
	reset, raised uint8
}

func (s *handlerScan) visit(node syntax.Node, params []string, locals map[string]bool) {
	syntax.Walk(node, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Subshell, *syntax.FuncDecl:
			return false
		case *syntax.UnaryArithm:
			if x.Op == syntax.Inc || x.Op == syntax.Dec {
				addArithmFlag(x.X, s.flags, locals)
			}
		case *syntax.BinaryArithm:
			if x.Op >= syntax.Assgn && x.Op <= syntax.OrBoolAssgn {
				addArithmFlag(x.X, s.flags, locals)
			}
		case *syntax.DeclClause:
			for _, a := range x.Args {
				if a.Name != nil && a.Value != nil && !locals[a.Name.Value] && (x.Variant.Value != "local") {
					s.flags[a.Name.Value] = true
				}
			}
		case *syntax.CallExpr:
			s.call(x, params, locals)
		}
		return true
	})
}

// call records an assignment-only command as flags, a trap reset and a kill
// that re-raises a reset signal, and follows a call of a local function.
func (s *handlerScan) call(x *syntax.CallExpr, params []string, locals map[string]bool) {
	if len(x.Args) == 0 {
		for _, a := range x.Assigns {
			if a.Name != nil && !locals[a.Name.Value] {
				s.flags[a.Name.Value] = true
			}
		}
		return
	}
	args := x.Args
	for len(args) > 0 && (wordLit(args[0]) == "builtin" || wordLit(args[0]) == "command") {
		args = args[1:]
	}
	if len(args) == 0 {
		return
	}
	name := wordLit(args[0])
	if name == "trap" && len(args) >= 3 {
		operands := args[1:]
		if wordLit(operands[0]) == "--" {
			operands = operands[1:]
		}
		if len(operands) >= 2 && wordLit(operands[0]) == "-" {
			for _, signal := range operands[1:] {
				s.reset |= trapSignalMask(resolveHandlerWord(signal, params))
			}
		}
	}
	if name == "kill" {
		if signal, target := handlerKill(args[1:], params); target {
			s.raised |= s.reset & signal
		}
	}
	if body, ok := s.funcs[name]; ok && !s.visiting[name] {
		s.bodies[body] = true
		nested := make([]string, len(args)-1)
		for i, arg := range args[1:] {
			nested[i] = resolveHandlerWord(arg, params)
		}
		s.visiting[name] = true
		s.visit(body, nested, handlerLocals(body, locals))
		delete(s.visiting, name)
	}
}

// Bash function locals are dynamically scoped: a called helper can see and
// assign its caller's locals. Collect declarations before examining writes.
func handlerLocals(body *syntax.Stmt, inherited map[string]bool) map[string]bool {
	locals := make(map[string]bool, len(inherited))
	for name := range inherited {
		locals[name] = true
	}
	syntax.Walk(body, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.FuncDecl, *syntax.Subshell:
			return false
		case *syntax.DeclClause:
			if x.Variant.Value != "local" && x.Variant.Value != "declare" && x.Variant.Value != "typeset" {
				return true
			}
			for _, arg := range x.Args {
				if arg.Name == nil && arg.Value != nil {
					option := wordLit(arg.Value)
					if strings.HasPrefix(option, "-") && strings.Contains(option[1:], "g") {
						return true
					}
				}
			}
			for _, arg := range x.Args {
				if arg.Name != nil {
					locals[arg.Name.Value] = true
				}
			}
		}
		return true
	})
	return locals
}

func addArithmFlag(expr syntax.ArithmExpr, flags, locals map[string]bool) {
	if w, ok := expr.(*syntax.Word); ok {
		if name := wordLit(w); name != "" && !locals[name] {
			flags[name] = true
		}
	}
}

func resolveHandlerWord(word *syntax.Word, params []string) string {
	if value, ok := wordValue(word); ok {
		return value
	}
	parts := word.Parts
	if len(parts) == 1 {
		if q, ok := parts[0].(*syntax.DblQuoted); ok {
			parts = q.Parts
		}
	}
	if len(parts) == 1 {
		if p, ok := parts[0].(*syntax.ParamExp); ok && p.Param != nil {
			n, err := strconv.Atoi(p.Param.Value)
			if err == nil && n > 0 && n <= len(params) {
				return params[n-1]
			}
		}
	}
	return ""
}

func handlerKill(args []*syntax.Word, params []string) (uint8, bool) {
	signal := uint8(2) // kill without a signal sends TERM
	if len(args) == 0 {
		return 0, false
	}
	first := resolveHandlerWord(args[0], params)
	if first == "-s" && len(args) >= 2 {
		signal = trapSignalMask(resolveHandlerWord(args[1], params))
		args = args[2:]
	} else if strings.HasPrefix(first, "-") && first != "--" {
		signal = trapSignalMask(strings.TrimPrefix(first, "-"))
		args = args[1:]
	}
	if len(args) > 0 && wordLit(args[0]) == "--" {
		args = args[1:]
	}
	return signal, len(args) == 1 && isCurrentShellPID(args[0])
}

func trapSignalMask(signal string) uint8 {
	switch strings.ToUpper(signal) {
	case "INT", "SIGINT", "2":
		return 1
	case "TERM", "SIGTERM", "15":
		return 2
	}
	return 0
}

func isCurrentShellPID(word *syntax.Word) bool {
	if len(word.Parts) != 1 {
		return false
	}
	switch p := word.Parts[0].(type) {
	case *syntax.ParamExp:
		return p.Param != nil && p.Param.Value == "$"
	case *syntax.DblQuoted:
		if len(p.Parts) == 1 {
			if param, ok := p.Parts[0].(*syntax.ParamExp); ok {
				return param.Param != nil && param.Param.Value == "$"
			}
		}
	}
	return false
}

// readsTrapFlag looks for a read of a flag outside the handler and outside
// a command that only prints it.
func readsTrapFlag(node syntax.Node, flags map[string]bool, handlerBodies, prints map[*syntax.Stmt]bool) bool {
	found := false
	syntax.Walk(node, func(n syntax.Node) bool {
		if stmt, ok := n.(*syntax.Stmt); ok && (handlerBodies[stmt] || prints[stmt]) {
			return false
		}
		if p, ok := n.(*syntax.ParamExp); ok && p.Param != nil && flags[p.Param.Value] {
			found = true
		}
		switch x := n.(type) {
		case *syntax.ArithmCmd:
			found = found || readsArithmFlag(x.X, flags)
		case *syntax.ArithmExp:
			found = found || readsArithmFlag(x.X, flags)
		case *syntax.LetClause:
			for _, expr := range x.Exprs {
				found = found || readsArithmFlag(expr, flags)
			}
		}
		return !found
	})
	return found
}

func readsArithmFlag(node syntax.Node, flags map[string]bool) bool {
	found := false
	syntax.Walk(node, func(n syntax.Node) bool {
		if w, ok := n.(*syntax.Word); ok && flags[wordLit(w)] {
			found = true
		}
		return !found
	})
	return found
}

const trapSignalSuggestion = "Make the INT/TERM handler exit (exit 130 for INT, exit 143 for TERM), or put cleanup in an EXIT trap and exit on the signals. A flag read by the loop or resetting and re-sending the signal (trap - SIG; kill -SIG $$) can also stop the script."

func trapSignalNames(signals uint8) string {
	switch signals {
	case 1:
		return "INT"
	case 2:
		return "TERM"
	default:
		return "INT and TERM"
	}
}

// A sourced file may define the otherwise unknown handler; its behavior
// cannot be determined from this script alone.
func unknownTrapHandler(stmts []*syntax.Stmt, funcs map[string]*syntax.Stmt) bool {
	if len(stmts) != 1 {
		return false
	}
	call, ok := stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	name := wordLit(call.Args[0])
	if name == "" {
		return false
	}
	_, defined := funcs[name]
	return !defined && name != "exit" && name != "return" && name != "true" && name != "false" && name != ":"
}

// A wrapper that starts a child, waits and only cleans up afterwards has no
// further long-running work that can swallow the signal.
func waitThenCleanup(stmts []*syntax.Stmt) bool {
	waited := false
	for _, stmt := range stmts {
		if stmt.Background {
			continue
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok {
			return false
		}
		if len(call.Args) == 0 {
			continue
		}
		switch wordLit(call.Args[0]) {
		case "wait":
			waited = true
		case "trap":
		case "rm", "echo", "printf", "exit", "return", ":", "true":
			if !waited {
				return false
			}
		default:
			return false
		}
	}
	return waited
}
