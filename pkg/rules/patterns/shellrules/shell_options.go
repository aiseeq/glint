package shellrules

import (
	"errors"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"mvdan.cc/sh/v3/syntax"
)

// optionChange is one shell option that a set or shopt command, a shebang or
// the flags of a make shell turns on or off.
type optionChange struct {
	name string
	on   bool
}

// setLetterOptions names the one-letter flags of set the rules ask about.
var setLetterOptions = map[rune]string{'e': "errexit", 'B': "braceexpand"}

// setOptionChanges reads the arguments of set, of a shebang interpreter or of
// .SHELLFLAGS in order: a cluster of letters (-eu, +e), each o of which takes
// the next argument as an option name (-o pipefail, -euo pipefail). The
// options end at --, at a lone - and at the first word that is no option; a
// lone + and a long option (--noprofile) are skipped, as bash does.
func setOptionChanges(args []string) []optionChange {
	var out []optionChange
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "+" || strings.HasPrefix(arg, "--") && len(arg) > 2 {
			continue
		}
		if len(arg) < 2 || (arg[0] != '-' && arg[0] != '+') || arg == "--" {
			break
		}
		on := arg[0] == '-'
		for _, c := range arg[1:] {
			if c == 'o' {
				if i+1 < len(args) {
					i++
					out = append(out, optionChange{args[i], on})
				}
				continue
			}
			if name, ok := setLetterOptions[c]; ok {
				out = append(out, optionChange{name, on})
			}
		}
	}
	return out
}

// shoptOptionChanges reads the arguments of shopt: -s or -u with -o turns the
// named set options on or off; without -o they are shopt options, without -s
// or -u it only prints them.
func shoptOptionChanges(args []string) []optionChange {
	mode, setNames := byte(0), false
	i := 0
	for ; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			i++
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			break
		}
		for _, c := range arg[1:] {
			switch c {
			case 's', 'u':
				mode = byte(c)
			case 'o':
				setNames = true
			}
		}
	}
	if mode == 0 || !setNames {
		return nil
	}
	var out []optionChange
	for _, name := range args[i:] {
		out = append(out, optionChange{name, mode == 's'})
	}
	return out
}

// callOptionChanges returns the options a set or shopt command changes, also
// behind builtin or command and with its name quoted. A word expanded at run
// time ends the options: what it holds is not known.
func callOptionChanges(call *syntax.CallExpr) []optionChange {
	args, _ := unprefixed(call.Args)
	if len(args) == 0 {
		return nil
	}
	command := wordLit(args[0])
	if command != "set" && command != "shopt" {
		return nil
	}
	words := make([]string, 0, len(args)-1)
	for _, arg := range args[1:] {
		value, ok := wordValue(arg)
		if !ok {
			break
		}
		words = append(words, value)
	}
	if command == "set" {
		return setOptionChanges(words)
	}
	return shoptOptionChanges(words)
}

// textTurnsErrexitOn reports a command of a script held as text (the script
// of ssh, of sh -c) that is set turning errexit on.
func textTurnsErrexitOn(text string) bool {
	fields := strings.Fields(patternkit.WithoutComment(text))
	for len(fields) > 0 && (fields[0] == "builtin" || fields[0] == "command") {
		fields = fields[1:]
	}
	if len(fields) == 0 || strings.Trim(fields[0], `"'`) != "set" {
		return false
	}
	on, _ := optionChangesTurn(setOptionChanges(fields[1:]), "errexit")
	return on
}

// shebangOptionChanges returns the options of the interpreter named by the
// first line of a script: #!/bin/bash -e, #!/usr/bin/env -S bash -euo pipefail.
func shebangOptionChanges(first string) []optionChange {
	rest, ok := strings.CutPrefix(strings.TrimSpace(first), "#!")
	if !ok {
		return nil
	}
	fields := strings.Fields(rest)
	if len(fields) > 0 && (fields[0] == "env" || strings.HasSuffix(fields[0], "/env")) {
		fields = fields[1:]
		for len(fields) > 0 && strings.HasPrefix(fields[0], "-") {
			fields = fields[1:]
		}
	}
	if len(fields) < 2 {
		return nil
	}
	return setOptionChanges(fields[1:])
}

// makeOptionChanges returns the options of the shell a make file runs its
// recipes with: the flags after the program of SHELL, then .SHELLFLAGS. A
// make reference among them ($(FLAGS)) is left out: make expands it.
func makeOptionChanges(src *patternkit.ShellSource) []optionChange {
	var out []optionChange
	if fields := makeWords(src.MakeShell); len(fields) > 1 {
		out = setOptionChanges(fields[1:])
	}
	return append(out, setOptionChanges(makeWords(src.MakeFlags))...)
}

func makeWords(value string) []string {
	var out []string
	for field := range strings.FieldsSeq(value) {
		if !strings.HasPrefix(field, "$") {
			out = append(out, field)
		}
	}
	return out
}

// optionChangesTurn reports whether the changes leave the option on or off,
// and false for recognized when they do not touch it.
func optionChangesTurn(changes []optionChange, name string) (on, recognized bool) {
	for _, change := range changes {
		if change.name == name {
			on, recognized = change.on, true
		}
	}
	return on, recognized
}

// optionState is errexit and pipefail at one point of a run.
type optionState uint8

const (
	stateErrexit optionState = 1 << iota
	statePipefail
)

func (s optionState) apply(changes []optionChange) optionState {
	for _, change := range changes {
		bit := optionState(0)
		switch change.name {
		case "errexit":
			bit = stateErrexit
		case "pipefail":
			bit = statePipefail
		default:
			continue
		}
		if change.on {
			s |= bit
		} else {
			s &^= bit
		}
	}
	return s
}

// optionStates is the set of states a point is reached with: bit 1<<state.
type optionStates uint8

func (s optionStates) with(state optionState) optionStates { return s | 1<<state }

// may reports a state of the set with the option on (on) or off (!on): a
// rule that reports what the option allows asks whether some run has it.
func (s optionStates) may(option optionState, on bool) bool {
	for state := range optionState(4) {
		if s&(1<<state) != 0 && (state&option != 0) == on {
			return true
		}
	}
	return false
}

// initialOptions is the state a shell unit starts in: the flags of the make
// shell, or of the shebang of a script.
func initialOptions(src *patternkit.ShellSource) optionState {
	switch {
	case src.Make:
		return optionState(0).apply(makeOptionChanges(src))
	case src.Graft || len(src.Ctx.Lines) == 0:
		return 0
	}
	return optionState(0).apply(shebangOptionChanges(src.Ctx.Lines[0]))
}

// shellOptions answers which errexit and pipefail states a point of a parsed
// shell unit runs with. The unit is run in order once: set and shopt change
// the state for what runs after them in the same shell; a subshell, a pipeline
// element, a background job, a $(…) (which also drops -e, as bash does outside
// POSIX mode) and a <(…) start from the state of their parent and change
// nothing outside; a brace group, if, loop and case bodies are read in order
// as if they ran; a function runs with the state of each call and leaves its
// changes to the caller; a function nothing calls runs with the state where it
// is declared and changes nothing.
type shellOptions struct {
	initial optionState
	stmts   []optionStmt
}

type optionStmt struct {
	start, end   int
	parent       int
	entry, leave optionStates
}

// statesAt returns the states of the innermost statement around an offset of
// the unit; between statements the states a top-level statement before it
// leaves; the initial state before every statement.
func (o *shellOptions) statesAt(offset int) optionStates {
	last := sort.Search(len(o.stmts), func(i int) bool { return o.stmts[i].start > offset }) - 1
	i := last
	for i >= 0 && o.stmts[i].end <= offset {
		i = o.stmts[i].parent
	}
	if i >= 0 && o.stmts[i].entry != 0 {
		return o.stmts[i].entry
	}
	if last >= 0 {
		for o.stmts[last].parent >= 0 {
			last = o.stmts[last].parent
		}
		if o.stmts[last].leave != 0 && o.stmts[last].end <= offset {
			return o.stmts[last].leave
		}
	}
	return optionStates(0).with(o.initial)
}

// strictAt reports errexit together with pipefail at the offset in every run.
func (o *shellOptions) strictAt(offset int) bool {
	states := o.statesAt(offset)
	return !states.may(stateErrexit, false) && !states.may(statePipefail, false)
}

// pipefailAt reports pipefail on at the offset in every run.
func (o *shellOptions) pipefailAt(offset int) bool {
	return !o.statesAt(offset).may(statePipefail, false)
}

// newShellOptions runs the parsed unit from its initial state.
func newShellOptions(file *syntax.File, initial optionState) *shellOptions {
	o := &shellOptions{initial: initial}
	if file == nil {
		return o
	}
	run := &optionRun{
		index:   make(map[*syntax.Stmt]int),
		defined: make(map[string]*syntax.FuncDecl),
		called:  make(map[*syntax.FuncDecl]bool),
		memo:    make(map[optionCall]optionState),
		active:  make(map[optionCall]bool),
		options: o,
	}
	run.indexStmts(file)
	run.stmts(file.Stmts, initial)
	for _, decl := range run.decls {
		if run.called[decl] {
			continue
		}
		states := o.stmts[run.index[run.declStmt[decl]]].entry
		if states == 0 {
			states = optionStates(0).with(initial)
		}
		for state := range optionState(4) {
			if states&(1<<state) != 0 {
				run.call(decl, state)
			}
		}
	}
	return o
}

type optionCall struct {
	decl  *syntax.FuncDecl
	state optionState
}

type optionRun struct {
	options  *shellOptions
	index    map[*syntax.Stmt]int
	decls    []*syntax.FuncDecl
	declStmt map[*syntax.FuncDecl]*syntax.Stmt
	defined  map[string]*syntax.FuncDecl
	called   map[*syntax.FuncDecl]bool
	memo     map[optionCall]optionState
	active   map[optionCall]bool
}

// indexStmts lists every statement of the unit by its start, with the
// statement it is nested in, and the function declarations in text order.
func (r *optionRun) indexStmts(file *syntax.File) {
	type entry struct {
		stmt, parent *syntax.Stmt
	}
	var entries []entry
	var stack []*syntax.Stmt
	var marks []bool
	r.declStmt = make(map[*syntax.FuncDecl]*syntax.Stmt)
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			if marks[len(marks)-1] {
				stack = stack[:len(stack)-1]
			}
			marks = marks[:len(marks)-1]
			return true
		}
		stmt, isStmt := node.(*syntax.Stmt)
		if isStmt {
			var parent *syntax.Stmt
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			entries = append(entries, entry{stmt, parent})
			if decl, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
				r.decls = append(r.decls, decl)
				r.declStmt[decl] = stmt
			}
			stack = append(stack, stmt)
		}
		marks = append(marks, isStmt)
		return true
	})
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].stmt.Pos().Offset() < entries[j].stmt.Pos().Offset() })
	r.options.stmts = make([]optionStmt, len(entries))
	for i, e := range entries {
		r.index[e.stmt] = i
	}
	for i, e := range entries {
		parent := -1
		if e.parent != nil {
			parent = r.index[e.parent]
		}
		r.options.stmts[i] = optionStmt{start: int(e.stmt.Pos().Offset()), end: int(e.stmt.End().Offset()), parent: parent}
	}
}

func (r *optionRun) stmts(list []*syntax.Stmt, state optionState) optionState {
	for _, s := range list {
		state = r.stmt(s, state)
	}
	return state
}

func (r *optionRun) stmt(s *syntax.Stmt, state optionState) optionState {
	i, ok := r.index[s]
	if ok {
		r.options.stmts[i].entry = r.options.stmts[i].entry.with(state)
	}
	for _, redirect := range s.Redirs {
		r.expansions(redirect.Word, state)
		if redirect.Hdoc != nil {
			r.expansions(redirect.Hdoc, state)
		}
	}
	leave := state
	if s.Cmd != nil {
		leave = r.command(s.Cmd, state)
	}
	if s.Background || s.Coprocess {
		leave = state
	}
	if ok {
		r.options.stmts[i].leave = r.options.stmts[i].leave.with(leave)
	}
	return leave
}

func (r *optionRun) command(cmd syntax.Command, state optionState) optionState {
	switch x := cmd.(type) {
	case *syntax.CallExpr:
		r.expansions(x, state)
		if changes := callOptionChanges(x); changes != nil {
			return state.apply(changes)
		}
		if len(x.Args) > 0 {
			if decl := r.defined[wordLit(x.Args[0])]; decl != nil {
				return r.call(decl, state)
			}
		}
	case *syntax.Block:
		return r.stmts(x.Stmts, state)
	case *syntax.Subshell:
		r.stmts(x.Stmts, state)
	case *syntax.IfClause:
		for c := x; c != nil; c = c.Else {
			state = r.stmts(c.Cond, state)
			state = r.stmts(c.Then, state)
		}
		return state
	case *syntax.WhileClause:
		state = r.stmts(x.Cond, state)
		return r.stmts(x.Do, state)
	case *syntax.ForClause:
		r.expansions(x.Loop, state)
		return r.stmts(x.Do, state)
	case *syntax.CaseClause:
		r.expansions(x.Word, state)
		for _, item := range x.Items {
			for _, pattern := range item.Patterns {
				r.expansions(pattern, state)
			}
			state = r.stmts(item.Stmts, state)
		}
		return state
	case *syntax.BinaryCmd:
		if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
			r.stmt(x.X, state)
			r.stmt(x.Y, state)
			return state
		}
		state = r.stmt(x.X, state)
		return r.stmt(x.Y, state)
	case *syntax.FuncDecl:
		if x.Name != nil {
			r.defined[x.Name.Value] = x
		}
	case *syntax.TimeClause:
		if x.Stmt != nil {
			return r.stmt(x.Stmt, state)
		}
	case *syntax.CoprocClause:
		r.stmt(x.Stmt, state)
	default: // [[ ]], (( )), let, declare and local: only their expansions run
		r.expansions(x, state)
	}
	return state
}

// call runs a function body with the state of a call and returns the state
// the caller goes on with: a function declared with ( … ) keeps its changes.
func (r *optionRun) call(decl *syntax.FuncDecl, state optionState) optionState {
	key := optionCall{decl, state}
	if leave, ok := r.memo[key]; ok {
		return leave
	}
	if r.active[key] || decl.Body == nil {
		return state
	}
	r.called[decl] = true
	r.active[key] = true
	leave := r.stmt(decl.Body, state)
	delete(r.active, key)
	r.memo[key] = leave
	return leave
}

// expansions runs the substitutions of a node that holds no statements of
// its own besides theirs: a $(…) or `…` without -e, a <(…) as it is.
func (r *optionRun) expansions(node syntax.Node, state optionState) {
	if node == nil {
		return
	}
	syntax.Walk(node, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.CmdSubst:
			r.stmts(x.Stmts, state&^stateErrexit)
			return false
		case *syntax.ProcSubst:
			r.stmts(x.Stmts, state)
			return false
		}
		return true
	})
}

// scriptOptions is a script read as one shell unit, parsed once for every
// rule that asks.
type scriptOptions struct {
	unit patternkit.ShellLine
	// tree is the syntax tree of the whole unit, nil when it does not parse.
	tree    *syntax.File
	options *shellOptions
	// base is the offset in the unit where each logical line of the source
	// starts.
	base []int
}

type scriptOptionsKey struct{}

// scriptOptionsOf returns the parsed unit of a script and its options; nil for
// a make file or a graft step, which run each unit in a shell of its own.
func scriptOptionsOf(src *patternkit.ShellSource) *scriptOptions {
	if src.Make || src.Graft {
		return nil
	}
	return core.FileShared(src.Ctx, scriptOptionsKey{}, func() *scriptOptions { return readScriptOptions(src) })
}

// unitShellOptions returns the options of one unit of a source: the shared
// run of a script, a run of its own for a make line or a graft step.
func unitShellOptions(src *patternkit.ShellSource, unit patternkit.ShellLine) *shellOptions {
	if script := scriptOptionsOf(src); script != nil {
		return script.options
	}
	_, options := parseShellOptions(unit.Text, initialOptions(src))
	return options
}

// unitOptionsOf is scriptOptionsOf for a script and for one graft step read
// on its own, which is run as one shell.
func unitOptionsOf(src *patternkit.ShellSource) *scriptOptions {
	if src.Graft {
		return readScriptOptions(src)
	}
	return scriptOptionsOf(src)
}

func readScriptOptions(src *patternkit.ShellSource) *scriptOptions {
	s := &scriptOptions{base: make([]int, len(src.Lines))}
	offset := 0
	for k, l := range src.Lines {
		s.base[k] = offset
		offset += len(l.Text) + 1
	}
	units := src.Units()
	if len(units) == 0 {
		s.options = &shellOptions{initial: initialOptions(src)}
		return s
	}
	s.unit = units[0]
	s.tree, s.options = parseShellOptions(s.unit.Text, initialOptions(src))
	return s
}

// parseShellOptions parses a unit and runs it. A unit that does not parse
// (an extra fi, a zsh construct) is run up to the line of the error, retried
// a few times, and the text after it gets the state the prefix leaves.
func parseShellOptions(text string, initial optionState) (*syntax.File, *shellOptions) {
	file, err := syntax.NewParser().Parse(strings.NewReader(text), "")
	if err == nil {
		return file, newShellOptions(file, initial)
	}
	prefix := text
	for range 3 {
		line := parseErrorLine(err)
		if line <= 1 {
			break
		}
		cut := lineStart(prefix, line)
		if cut >= len(prefix) {
			break
		}
		prefix = prefix[:cut]
		var partial *syntax.File
		if partial, err = syntax.NewParser().Parse(strings.NewReader(prefix), ""); err == nil {
			return nil, newShellOptions(partial, initial)
		}
	}
	return nil, &shellOptions{initial: initial}
}

// parseErrorLine returns the line a parse error points at, 0 for none.
func parseErrorLine(err error) int {
	var parseErr syntax.ParseError
	if errors.As(err, &parseErr) {
		return int(parseErr.Pos.Line())
	}
	var langErr syntax.LangError
	if errors.As(err, &langErr) {
		return int(langErr.Pos.Line())
	}
	return 0
}

// lineStart returns the offset where the 1-based line starts in text.
func lineStart(text string, line int) int {
	offset := 0
	for n := 1; n < line; n++ {
		i := strings.IndexByte(text[offset:], '\n')
		if i < 0 {
			return len(text)
		}
		offset += i + 1
	}
	return offset
}

// at returns the states a run reaches an offset of a logical line of the
// script with.
func (s *scriptOptions) at(source, offset int) optionStates {
	if source >= 0 && source < len(s.base) {
		offset += s.base[source]
	}
	return s.options.statesAt(offset)
}

// step returns the states a run reaches the start of a step with.
func (s *scriptOptions) step(step patternkit.ShellStep) optionStates {
	return s.at(step.Source, step.Offset)
}

// linePipefail reports pipefail on in some run at an offset of a logical line
// of a script; a make file reads none.
func linePipefail(src *patternkit.ShellSource, source, offset int) bool {
	options := scriptOptionsOf(src)
	return options != nil && options.at(source, offset).may(statePipefail, true)
}

// line returns the states a run reaches the first command of a logical line
// with.
func (s *scriptOptions) line(src *patternkit.ShellSource, source int) optionStates {
	text := src.Lines[source].Text
	return s.at(source, len(text)-len(strings.TrimLeft(text, " \t")))
}
