package shellrules

import (
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"mvdan.cc/sh/v3/syntax"
)

type emptyCaptureUse struct {
	offset int
}
type emptyCaptureKey struct {
	line int
	name string
}
type emptyTestWord struct {
	word *syntax.Word
	pos  int
	neg  bool
}
type emptyCaptureReport struct {
	r     *shellRule
	src   *patternkit.ShellSource
	unit  patternkit.ShellLine
	facts *shellFacts
	out   []*core.Violation
	seen  map[int]bool
}

func emptyCapturePipeFindings(r *shellRule, src *patternkit.ShellSource, unit patternkit.ShellLine, facts *shellFacts) []*core.Violation {
	report := emptyCaptureReport{r: r, src: src, unit: unit, facts: facts, seen: make(map[int]bool)}
	tests, loops, rejected := collectEmptyCaptureConsumers(facts.tree)
	uses := reportEmptyTestConsumers(&report, facts, tests, rejected)
	reportEmptyAssignments(&report, facts, uses)
	for _, item := range loops {
		report.add(item.offset, item.producer, "a for-loop word list", nil)
	}
	sort.SliceStable(report.out, func(i, j int) bool {
		if report.out[i].Line == report.out[j].Line {
			return report.out[i].Column < report.out[j].Column
		}
		return report.out[i].Line < report.out[j].Line
	})
	return report.out
}

func (r *emptyCaptureReport) add(offset int, producer, form string, assignment *syntax.Assign) {
	if r.seen[offset] {
		return
	}
	r.seen[offset] = true
	message := "A failed " + producer + " pipeline can leave an empty substitution that passes an emptiness check as success in " + form
	if form == "a for-loop word list" {
		message = "A failed " + producer + " pipeline can leave an empty substitution that makes the for-loop word list empty, so the loop body is skipped"
	}
	hint := "Capture the producer alone and check its status, for example files=$("
	hint += producer + " ...) || exit 1; filter the captured value afterward"
	if assignment != nil && r.facts.hasSpan(r.facts.declarations, int(assignment.Pos().Offset())) {
		hint = "Separate declaration and assignment, for example local " + assignment.Name.Value + "; " + assignment.Name.Value + "=$("
		hint += producer + " ...) || exit 1; filter the captured value afterward"
	} else if form == "an assignment checked for emptiness" {
		hint += "; errexit together with pipefail before the assignment also checks the pipeline"
	}
	r.out = appendReport(r.out, r.src.Report(r.r, r.unit.LineAt(offset), message, hint))
}

type emptyLoopUse struct {
	offset   int
	producer string
}

func collectEmptyCaptureConsumers(tree *syntax.File) ([]emptyTestWord, []emptyLoopUse, []textSpan) {
	var tests []emptyTestWord
	var loops []emptyLoopUse
	var rejected []textSpan
	var ancestors []syntax.Node
	var negatedStack []bool
	negatedDepth := 0
	exitingHelpers := exitingFunctionNames(tree)
	syntax.Walk(tree, func(node syntax.Node) bool {
		if node == nil {
			if negatedStack[len(negatedStack)-1] {
				negatedDepth--
			}
			negatedStack = negatedStack[:len(negatedStack)-1]
			ancestors = ancestors[:len(ancestors)-1]
			return true
		}
		collectRejectedConsumer(node, exitingHelpers, &rejected)
		collectEmptyTestConsumer(node, negatedDepth > 0, &tests)
		collectForListConsumer(node, ancestors, &loops)
		isNegated := false
		if stmt, ok := node.(*syntax.Stmt); ok && stmt.Negated {
			isNegated = true
			negatedDepth++
		}
		negatedStack = append(negatedStack, isNegated)
		ancestors = append(ancestors, node)
		return true
	})
	return tests, loops, mergeSpans(rejected)
}

func collectRejectedConsumer(node syntax.Node, helpers map[string]bool, rejected *[]textSpan) {
	switch x := node.(type) {
	case *syntax.IfClause:
		if branchExitsNonzero(x.Then, helpers) {
			for _, cond := range x.Cond {
				*rejected = append(*rejected, textSpan{int(cond.Pos().Offset()), int(cond.End().Offset())})
			}
		}
	case *syntax.BinaryCmd:
		if x.Op == syntax.AndStmt && branchExitsNonzero([]*syntax.Stmt{x.Y}, helpers) {
			*rejected = append(*rejected, textSpan{int(x.X.Pos().Offset()), int(x.X.End().Offset())})
		}
	}
}

func collectEmptyTestConsumer(node syntax.Node, negated bool, tests *[]emptyTestWord) {
	switch node.(type) {
	case *syntax.CallExpr, *syntax.TestClause:
	default:
		return
	}
	pos := int(node.Pos().Offset())
	eachEmptyTestWord(node, func(word *syntax.Word) { *tests = append(*tests, emptyTestWord{word, pos, negated}) })
}

func collectForListConsumer(node syntax.Node, ancestors []syntax.Node, loops *[]emptyLoopUse) {
	subst, ok := node.(*syntax.CmdSubst)
	if !ok {
		return
	}
	var clauses []*syntax.ForClause
	for _, ancestor := range ancestors {
		if _, nested := ancestor.(*syntax.CmdSubst); nested {
			return
		}
		if clause, isFor := ancestor.(*syntax.ForClause); isFor {
			clauses = append(clauses, clause)
		}
	}
	if !inForWordList(clauses, subst) {
		return
	}
	if producer, ok := substFailedProducer(subst); ok {
		*loops = append(*loops, emptyLoopUse{int(subst.Pos().Offset()), producer})
	}
}

func reportEmptyTestConsumers(report *emptyCaptureReport, facts *shellFacts, tests []emptyTestWord, rejected []textSpan) map[emptyCaptureKey][]emptyCaptureUse {
	uses := make(map[emptyCaptureKey][]emptyCaptureUse)
	for _, test := range tests {
		if test.neg || facts.hasSpan(rejected, test.pos) {
			continue
		}
		if subst := findCmdSubst(test.word); subst != nil {
			if producer, ok := substFailedProducer(subst); ok {
				report.add(int(subst.Pos().Offset()), producer, "a -z emptiness test", nil)
			}
		}
		addVariableTestUses(uses, report.unit, test)
	}
	return uses
}

func addVariableTestUses(uses map[emptyCaptureKey][]emptyCaptureUse, unit patternkit.ShellLine, test emptyTestWord) {
	line := unit.LineAt(test.pos)
	for _, name := range wordVariableNames(test.word) {
		key := emptyCaptureKey{line: line, name: name}
		uses[key] = append(uses[key], emptyCaptureUse{offset: test.pos})
	}
}

func reportEmptyAssignments(report *emptyCaptureReport, facts *shellFacts, uses map[emptyCaptureKey][]emptyCaptureUse) {
	for _, a := range facts.captures {
		if a == nil || a.Name == nil || a.Value == nil {
			continue
		}
		subst := findCmdSubst(a.Value)
		if subst == nil {
			continue
		}
		producer, ok := substFailedProducer(subst)
		if !ok || assignmentStatusChecked(report.unit.Text, int(a.End().Offset()), a.Name.Value) || facts.inCondition(int(a.Pos().Offset())) {
			continue
		}
		if assignmentSafeFromErrexit(report, a) || !assignmentHasEmptyTest(uses, report.unit, a) {
			continue
		}
		report.add(int(a.Pos().Offset()), producer, "an assignment checked for emptiness", a)
	}
}

func assignmentSafeFromErrexit(report *emptyCaptureReport, assignment *syntax.Assign) bool {
	offset := int(assignment.Pos().Offset())
	return !report.facts.hasSpan(report.facts.declarations, offset) && report.facts.options.strictAt(offset)
}

func assignmentHasEmptyTest(uses map[emptyCaptureKey][]emptyCaptureUse, unit patternkit.ShellLine, assignment *syntax.Assign) bool {
	line := unit.LineAt(int(assignment.Pos().Offset()))
	for _, use := range uses[emptyCaptureKey{line: line, name: assignment.Name.Value}] {
		if use.offset > int(assignment.End().Offset()) {
			return true
		}
	}
	return false
}

func exitingFunctionNames(tree *syntax.File) map[string]bool {
	helpers := make(map[string]bool)
	syntax.Walk(tree, func(node syntax.Node) bool {
		decl, ok := node.(*syntax.FuncDecl)
		if ok && decl.Name != nil && stmtExitsNonzero(decl.Body, nil) {
			helpers[decl.Name.Value] = true
		}
		return true
	})
	return helpers
}

func branchExitsNonzero(stmts []*syntax.Stmt, helpers map[string]bool) bool {
	for _, stmt := range stmts {
		if stmtExitsNonzero(stmt, helpers) {
			return true
		}
	}
	return false
}

func stmtExitsNonzero(stmt *syntax.Stmt, helpers map[string]bool) bool {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return false
	}
	switch command := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if callExitsNonzero(command) {
			return true
		}
		return len(command.Args) > 0 && helpers[wordLit(command.Args[0])]
	case *syntax.Block:
		return branchExitsNonzero(command.Stmts, helpers)
	default:
		return false
	}
}

func callExitsNonzero(call *syntax.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	name := wordLit(call.Args[0])
	if name != "exit" && name != "return" {
		return false
	}
	if len(call.Args) < 2 {
		return false
	}
	code, err := strconv.Atoi(wordLit(call.Args[1]))
	return err == nil && code != 0
}

func inForWordList(ancestors []*syntax.ForClause, subst *syntax.CmdSubst) bool {
	start, end := int(subst.Pos().Offset()), int(subst.End().Offset())
	for _, parent := range ancestors {
		words, ok := parent.Loop.(*syntax.WordIter)
		if !ok {
			continue
		}
		if int(words.Pos().Offset()) <= start && int(words.End().Offset()) >= end {
			return true
		}
	}
	return false
}

func substFailedProducer(subst *syntax.CmdSubst) (string, bool) {
	var producer string
	found := false
	syntax.Walk(subst, func(n syntax.Node) bool {
		if found {
			return false
		}
		b, ok := n.(*syntax.BinaryCmd)
		if !ok || (b.Op != syntax.Pipe && b.Op != syntax.PipeAll) {
			return true
		}
		left := b.X
		firstPipe := b.Op
		for {
			next, ok := left.Cmd.(*syntax.BinaryCmd)
			if !ok || (next.Op != syntax.Pipe && next.Op != syntax.PipeAll) {
				break
			}
			firstPipe = next.Op
			left = next.X
		}
		found = true
		if firstPipe == syntax.PipeAll {
			return false
		}
		call, _ := left.Cmd.(*syntax.CallExpr)
		if call == nil || len(call.Args) == 0 {
			return false
		}
		if commandLookup(call.Args) {
			return false
		}
		name := wrappedCommand(call.Args)
		if newPipeProducers[name] && !producerErrorsDiscarded(left) {
			producer = name
		}
		return false
	})
	return producer, producer != ""
}

func commandLookup(args []*syntax.Word) bool {
	if len(args) < 2 || wordLit(args[0]) != "command" {
		return false
	}
	return wordLit(args[1]) == "-v" || wordLit(args[1]) == "-V"
}

func wrappedCommand(args []*syntax.Word) string {
	words := make([]string, len(args))
	for i, arg := range args {
		words[i] = wordLit(arg)
	}
	i := 0
	for i < len(words) {
		next, wrapped := skipCommandWrapper(words, i)
		if !wrapped {
			if strings.HasPrefix(words[i], "-") {
				return words[i]
			}
			return commandWord(words[i])
		}
		i = next
	}
	return ""
}

func skipCommandWrapper(words []string, i int) (int, bool) {
	switch words[i] {
	case "command":
		return skipSimpleWrapper(words, i), true
	case "sudo":
		return skipSudoWrapper(words, i), true
	case "env":
		return skipEnvWrapper(words, i), true
	default:
		return i, false
	}
}

func skipSimpleWrapper(words []string, i int) int {
	i++
	for i < len(words) && strings.HasPrefix(words[i], "-") && words[i] != "--" {
		i++
	}
	if i < len(words) && words[i] == "--" {
		i++
	}
	return i
}

func skipSudoWrapper(words []string, i int) int {
	i++
	for i < len(words) && strings.HasPrefix(words[i], "-") && words[i] != "--" {
		option := words[i]
		i++
		if sudoOptionTakesValue(option) {
			i++
		}
	}
	if i < len(words) && words[i] == "--" {
		i++
	}
	return i
}

func sudoOptionTakesValue(option string) bool {
	switch option {
	case "-u", "-g", "-h", "-C", "-T", "-p", "-R", "-D", "-r", "-t", "-U":
		return true
	default:
		return false
	}
}

func skipEnvWrapper(words []string, i int) int {
	i++
	for i < len(words) {
		option := words[i]
		if option == "--" {
			return i + 1
		}
		if envOptionTakesValue(option) {
			i += 2
			continue
		}
		if strings.HasPrefix(option, "-") || wordIsAssignment(option) {
			i++
			continue
		}
		break
	}
	return i
}

func envOptionTakesValue(option string) bool {
	return option == "-u" || option == "--unset" || option == "-C" || option == "--chdir"
}

func wordIsAssignment(word string) bool {
	_, _, assignment := strings.Cut(word, "=")
	return assignment
}

func producerErrorsDiscarded(stmt *syntax.Stmt) bool {
	stderrToNull := false
	stderrMerged := false
	for _, redir := range stmt.Redirs {
		target := ""
		if redir.Word != nil {
			target = wordLit(redir.Word)
		}
		fd := ""
		if redir.N != nil {
			fd = redir.N.Value
		}
		if (fd == "2" && (redir.Op == syntax.RdrOut || redir.Op == syntax.AppOut || redir.Op == syntax.RdrClob)) ||
			(redir.Op == syntax.RdrAll || redir.Op == syntax.RdrAllClob) {
			stderrToNull = target == "/dev/null"
			stderrMerged = false
		}
		if fd == "2" && redir.Op == syntax.DplOut && target == "1" {
			stderrMerged = true // stderr becomes part of the captured stdout
			stderrToNull = false
		}
	}
	return stderrToNull || stderrMerged
}

func eachEmptyTestWord(node syntax.Node, visit func(*syntax.Word)) {
	if call, ok := node.(*syntax.CallExpr); ok {
		if len(call.Args) < 2 {
			return
		}
		command := wordLit(call.Args[0])
		if command != "test" && command != "[" {
			return
		}
		for i := 1; i+1 < len(call.Args); i++ {
			if wordLit(call.Args[i]) == "-z" && wordLit(call.Args[i-1]) != "!" {
				visit(call.Args[i+1])
			}
		}
		return
	}
	if test, ok := node.(*syntax.TestClause); ok {
		walkEmptyTestWords(test.X, false, visit)
	}
}

func walkEmptyTestWords(expr syntax.TestExpr, negated bool, visit func(*syntax.Word)) {
	switch x := expr.(type) {
	case *syntax.UnaryTest:
		if x.Op == syntax.TsNot {
			walkEmptyTestWords(x.X, !negated, visit)
			return
		}
		if x.Op != syntax.TsEmpStr || negated {
			return
		}
		if word, ok := x.X.(*syntax.Word); ok {
			visit(word)
		}
	case *syntax.BinaryTest:
		walkEmptyTestWords(x.X, negated, visit)
		walkEmptyTestWords(x.Y, negated, visit)
	case *syntax.ParenTest:
		walkEmptyTestWords(x.X, negated, visit)
	}
}

func wordVariableNames(word *syntax.Word) []string {
	var names []string
	syntax.Walk(word, func(n syntax.Node) bool {
		if param, ok := n.(*syntax.ParamExp); ok && param.Param != nil && param.Exp == nil {
			names = append(names, param.Param.Value)
		}
		return true
	})
	return names
}
