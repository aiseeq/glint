package duplication

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"sort"
)

// A run of statements of one function written again in another function of
// the package under other names, as a prologue that prepares the input:
//
//	func refused(dir string, m meta, built []byte) (bool, error) {
//		path, found, err := find(m.out)
//		if err != nil {
//			return false, err
//		}
//		if found.header { built = strip(built, path) }
//		l, err := readLayout(dir, found)
//		... five more steps ...
//
//	func hint(dir string, m meta, built []byte) (string, string, error) {
//		at, mf, err := find(m.out)
//		if err != nil {
//			return "", "", err
//		}
//		if mf.header { built = strip(built, at) }
//		lay, err := readLayout(dir, mf)
//		... the same five steps ...
//
// No single statement of it is large enough for renamed-duplicate-block, and
// the lines differ in names and in what the guards return, so the textual
// rules see nothing either. The run is compared through windows of
// renamedSequenceWindow consecutive statements of the function body, normalized
// like a statement (its own variables numbered, values from outside one
// placeholder) with the zero values returned beside the last result left out.
// Equal windows of two functions that follow each other at one shift merge
// into one run.

// renamedSequenceWindow, minRenamedSequenceLines and minRenamedSequenceSteps
// are the size a run must reach: statements of the body, lines they take, and
// statements that are not a bare error guard. Below them lie the chains every
// function writes its own way: two or three calls, each with its guard, take
// four to six statements and six to nine lines.
const (
	renamedSequenceWindow   = 6
	minRenamedSequenceLines = 15
	minRenamedSequenceSteps = 4
)

// sequenceFunc is a function whose body is compared.
type sequenceFunc struct {
	file  string
	fd    *ast.FuncDecl
	nodes int
	order int
}

// sequenceWindow is the window of the body of fn starting at statement start.
type sequenceWindow struct {
	fn    *sequenceFunc
	start int
}

// sequenceMatch is a window of a equal to a window of b.
type sequenceMatch struct {
	a, b int
}

// renamedSequences collects the windows of the functions of one package.
type renamedSequences struct {
	info  *types.Info
	fset  *token.FileSet
	funcs []*sequenceFunc
	byKey map[string][]sequenceWindow
}

func newRenamedSequences(info *types.Info, fset *token.FileSet) *renamedSequences {
	return &renamedSequences{info: info, fset: fset, byKey: make(map[string][]sequenceWindow)}
}

// add hashes every window of the body of fd.
func (s *renamedSequences) add(path string, fd *ast.FuncDecl) {
	list := fd.Body.List
	fn := &sequenceFunc{file: path, fd: fd, nodes: countNodes(fd.Body), order: len(s.funcs)}
	s.funcs = append(s.funcs, fn)
	for start := 0; start+renamedSequenceWindow <= len(list); start++ {
		window := list[start : start+renamedSequenceWindow]
		norm := &blockNormalizer{
			info: s.info, lo: window[0].Pos(), hi: window[len(window)-1].End(),
			locals: make(map[types.Object]int), zeroReturns: true,
			redeclared: s.redeclared(window), packageNames: true, fieldNames: true,
		}
		for _, stmt := range window {
			norm.walk(stmt)
		}
		key := norm.b.String()
		s.byKey[key] = append(s.byKey[key], sequenceWindow{fn: fn, start: start})
	}
}

// redeclared finds the variables declared before the window that a := in it
// declares again: the name of such a variable has no definition there, only
// a use of the earlier one.
func (s *renamedSequences) redeclared(window []ast.Stmt) map[types.Object]bool {
	again := make(map[types.Object]bool)
	for _, stmt := range window {
		ast.Inspect(stmt, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok || assign.Tok != token.DEFINE {
				return true
			}
			for _, lhs := range assign.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					if obj := s.info.Uses[id]; obj != nil {
						again[obj] = true
					}
				}
			}
			return true
		})
	}
	return again
}

// reports pairs the equal windows of two functions, merges them into runs and
// reports each run large enough against the occurrence to call.
func (s *renamedSequences) reports() []renamedReport {
	matches := make(map[[2]*sequenceFunc][]sequenceMatch)
	for _, key := range slices.Sorted(maps.Keys(s.byKey)) {
		group := s.byKey[key]
		for i, x := range group {
			for _, y := range group[i+1:] {
				if x.fn == y.fn {
					continue
				}
				pair := [2]*sequenceFunc{x.fn, y.fn}
				matches[pair] = append(matches[pair], sequenceMatch{a: x.start, b: y.start})
			}
		}
	}
	pairs := slices.Collect(maps.Keys(matches))
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0].order != pairs[j][0].order {
			return pairs[i][0].order < pairs[j][0].order
		}
		return pairs[i][1].order < pairs[j][1].order
	})
	var reports []renamedReport
	for _, pair := range pairs {
		var large []sequenceRun
		for _, run := range mergeSequenceMatches(matches[pair]) {
			if s.large(pair[0], pair[1], run) {
				large = append(large, run)
			}
		}
		for _, region := range joinSequenceRuns(large) {
			reports = append(reports, s.report(pair[0], pair[1], region))
		}
	}
	return joinCopies(reports)
}

// sequenceRun is statements a..a+size-1 of one body equal to b..b+size-1 of another.
type sequenceRun struct {
	a, b, size int
}

// sequenceRegion is statements aLo..aHi of one body and bLo..bHi of another
// that runs at several shifts cover.
type sequenceRegion struct {
	aLo, aHi, bLo, bHi int
}

// joinSequenceRuns joins runs that overlap in both bodies into one region: a
// chain of equal statements matches at every shift, and each shift is the
// same copy again. Runs apart in one body are two copies.
func joinSequenceRuns(runs []sequenceRun) []sequenceRegion {
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].a != runs[j].a {
			return runs[i].a < runs[j].a
		}
		return runs[i].b < runs[j].b
	})
	var regions []sequenceRegion
	for _, run := range runs {
		aHi, bHi := run.a+run.size-1, run.b+run.size-1
		if n := len(regions); n > 0 {
			last := &regions[n-1]
			if run.a <= last.aHi && run.b <= last.bHi && bHi >= last.bLo {
				last.aHi = max(last.aHi, aHi)
				last.bLo, last.bHi = min(last.bLo, run.b), max(last.bHi, bHi)
				continue
			}
		}
		regions = append(regions, sequenceRegion{aLo: run.a, aHi: aHi, bLo: run.b, bHi: bHi})
	}
	return regions
}

// joinCopies joins the reports whose copies overlap in one function, against
// several originals, into the first of them: one copied run is one finding.
func joinCopies(reports []renamedReport) []renamedReport {
	sort.SliceStable(reports, func(i, j int) bool {
		a, b := reports[i].copy, reports[j].copy
		if a.file != b.file {
			return a.file < b.file
		}
		return a.pos < b.pos
	})
	var joined []renamedReport
	for _, rep := range reports {
		if n := len(joined); n > 0 {
			last := joined[n-1].copy
			// Positions of one file set never overlap across functions or files.
			if rep.copy.pos < last.end {
				last.end = max(last.end, rep.copy.end)
				continue
			}
		}
		joined = append(joined, rep)
	}
	return joined
}

// mergeSequenceMatches joins windows that follow each other at one shift.
func mergeSequenceMatches(matches []sequenceMatch) []sequenceRun {
	sort.Slice(matches, func(i, j int) bool {
		if di, dj := matches[i].b-matches[i].a, matches[j].b-matches[j].a; di != dj {
			return di < dj
		}
		return matches[i].a < matches[j].a
	})
	var runs []sequenceRun
	for _, m := range matches {
		if n := len(runs); n > 0 {
			last := &runs[n-1]
			if m.b-m.a == last.b-last.a && m.a <= last.a+last.size {
				last.size = m.a - last.a + renamedSequenceWindow
				continue
			}
		}
		runs = append(runs, sequenceRun{a: m.a, b: m.b, size: renamedSequenceWindow})
	}
	return runs
}

// large reports a run large enough to be a copy.
func (s *renamedSequences) large(fa, fb *sequenceFunc, run sequenceRun) bool {
	left := fa.fd.Body.List[run.a : run.a+run.size]
	right := fb.fd.Body.List[run.b : run.b+run.size]
	return min(s.statementLines(left), s.statementLines(right)) >= minRenamedSequenceLines && sequenceSteps(left) >= minRenamedSequenceSteps
}

// report turns a region into the copy and its original.
func (s *renamedSequences) report(fa, fb *sequenceFunc, region sequenceRegion) renamedReport {
	a := s.block(fa, fa.fd.Body.List[region.aLo:region.aHi+1])
	b := s.block(fb, fb.fd.Body.List[region.bLo:region.bHi+1])
	if originalBefore(s.fset, b, a) {
		a, b = b, a
	}
	return renamedReport{copy: b, original: a}
}

func (s *renamedSequences) block(fn *sequenceFunc, stmts []ast.Stmt) *renamedBlock {
	nodes := 0
	for _, stmt := range stmts {
		nodes += countNodes(stmt)
	}
	return &renamedBlock{
		file: fn.file, pos: stmts[0].Pos(), end: stmts[len(stmts)-1].End(), fn: fn.fd,
		share: float64(nodes) / float64(fn.nodes),
	}
}

// statementLines is the lines the statements take, blank lines and comments
// between them not counted.
func (s *renamedSequences) statementLines(stmts []ast.Stmt) int {
	lines := 0
	for _, stmt := range stmts {
		lines += s.fset.Position(stmt.End()).Line - s.fset.Position(stmt.Pos()).Line + 1
	}
	return lines
}

// sequenceSteps counts the statements that are not a bare error guard.
func sequenceSteps(stmts []ast.Stmt) int {
	steps := 0
	for _, stmt := range stmts {
		if !errorGuard(stmt) {
			steps++
		}
	}
	return steps
}

// errorGuard reports if x != nil { return ... } with nothing else in it.
func errorGuard(stmt ast.Stmt) bool {
	ifStmt, ok := stmt.(*ast.IfStmt)
	if !ok || ifStmt.Init != nil || ifStmt.Else != nil || len(ifStmt.Body.List) != 1 {
		return false
	}
	body := ifStmt.Body.List
	if _, ok := body[len(body)-1].(*ast.ReturnStmt); !ok {
		return false
	}
	cond, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ {
		return false
	}
	id, ok := cond.Y.(*ast.Ident)
	return ok && id.Name == "nil"
}

// zeroValues reports whether every expression is the zero value of its type:
// nil, false, "", a zero number, or an empty composite literal.
func (n *blockNormalizer) zeroValues(exprs []ast.Expr) bool {
	for _, expr := range exprs {
		if !n.zeroValue(expr) {
			return false
		}
	}
	return true
}

func (n *blockNormalizer) zeroValue(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if lit, ok := expr.(*ast.CompositeLit); ok {
		return len(lit.Elts) == 0
	}
	tv, ok := n.info.Types[expr]
	if !ok {
		return false
	}
	if tv.IsNil() {
		return true
	}
	if tv.Value == nil {
		return false
	}
	switch tv.Value.Kind() {
	case constant.Bool:
		return !constant.BoolVal(tv.Value)
	case constant.String:
		return constant.StringVal(tv.Value) == ""
	}
	// A number; Sign of an unknown value is 1.
	return constant.Sign(tv.Value) == 0
}
