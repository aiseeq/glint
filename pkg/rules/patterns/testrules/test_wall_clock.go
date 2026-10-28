package testrules

import (
	"go/ast"
	"path/filepath"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewTestDependsOnWallClockRule())
}

// TestDependsOnWallClockRule detects a Go test that calls code deciding by
// the calendar of the current moment:
//
//	func (s *Service) replyText() string {
//		now := time.Now().In(loc)
//		if now.Hour() >= s.cfg.Start && now.Weekday() != time.Sunday { ... }
//	}
//
//	func TestReplyBusinessHours(t *testing.T) {
//		if svc.replyText() != "day" { t.Error(...) }   // red at night and on weekends
//	}
//
// The code reads time.Now() itself, so the test cannot move the clock: it
// passes on a weekday at noon and fails at night, on a weekend, in another
// zone. The code decides when an hour, minute, weekday, day or month of
// time.Now() is compared or switched on; a test reaches it by calling it or a
// wrapper of it — a function of the package whose body is one statement
// calling it. A call into a function that reaches the decision on one of its
// paths is left alone: whether the test takes that path is not known. A test faking time (testing/synctest)
// or computing its expectation from time.Now() itself is left alone. Pass the
// moment or a clock into the code instead.
type TestDependsOnWallClockRule struct {
	*rules.BaseRule
	// dirs maps a directory to its wall-clock functions.
	dirs map[string]*wallClockPackage
}

// wallClockPackage is what the rule knows of the non-test code of a directory.
type wallClockPackage struct {
	name string
	// clock maps a function or method name to the clock-deciding function it
	// leads to, for the names whose every declaration leads to one.
	clock map[string]string
}

// NewTestDependsOnWallClockRule creates the rule
func NewTestDependsOnWallClockRule() *TestDependsOnWallClockRule {
	return &TestDependsOnWallClockRule{BaseRule: rules.NewBaseRule(
		"test-depends-on-wall-clock",
		"patterns",
		"Detects a Go test calling code that decides by the hour, weekday or date of time.Now() — with no clock to substitute, the test passes or fails by when it runs",
		core.SeverityMedium,
	)}
}

// wallClockDecl is a function declaration with what the rule needs of it:
// whether it decides by the wall clock itself, and for a one-statement body
// the names it calls.
type wallClockDecl struct {
	direct  bool
	callees map[string]bool
}

// UseProjectFiles finds, per directory, the functions that decide by the
// calendar of time.Now() directly or wrap one that does.
func (r *TestDependsOnWallClockRule) UseProjectFiles(files []*core.FileContext) {
	r.dirs = make(map[string]*wallClockPackage)
	decls := make(map[string]map[string][]wallClockDecl)
	for _, ctx := range files {
		if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
			continue
		}
		dir := filepath.Dir(ctx.Path)
		if r.dirs[dir] == nil {
			r.dirs[dir] = &wallClockPackage{name: ctx.GoAST.Name.Name, clock: make(map[string]string)}
			decls[dir] = make(map[string][]wallClockDecl)
		}
		for _, decl := range ctx.GoAST.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				d := wallClockDecl{direct: decidesByWallClock(fn.Body)}
				if len(fn.Body.List) == 1 {
					d.callees = calledNames(fn.Body)
				}
				decls[dir][fn.Name.Name] = append(decls[dir][fn.Name.Name], d)
			}
		}
	}
	for dir, byName := range decls {
		resolveWallClock(r.dirs[dir].clock, byName)
	}
}

// resolveWallClock fills clock with the names whose every declaration decides
// by the wall clock or wraps such a name, each with the deciding function.
func resolveWallClock(clock map[string]string, byName map[string][]wallClockDecl) {
	for name, list := range byName {
		if allDecls(list, func(d wallClockDecl) bool { return d.direct }) {
			clock[name] = name
		}
	}
	for changed := true; changed; {
		changed = false
		for name, list := range byName {
			if _, done := clock[name]; done {
				continue
			}
			leaf := ""
			if allDecls(list, func(d wallClockDecl) bool {
				for callee := range d.callees {
					if l, ok := clock[callee]; ok {
						leaf = l
						return true
					}
				}
				return false
			}) {
				clock[name] = leaf
				changed = true
			}
		}
	}
}

func allDecls(list []wallClockDecl, pred func(wallClockDecl) bool) bool {
	for _, d := range list {
		if !pred(d) {
			return false
		}
	}
	return len(list) > 0
}

// calledNames returns the names of the functions and methods a body calls.
func calledNames(body *ast.BlockStmt) map[string]bool {
	names := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			switch fun := ast.Unparen(call.Fun).(type) {
			case *ast.Ident:
				names[fun.Name] = true
			case *ast.SelectorExpr:
				names[fun.Sel.Name] = true
			}
		}
		return true
	})
	return names
}

// wallClockUnits are the calendar parts of a time.Time a decision is taken on.
var wallClockUnits = map[string]bool{
	"Hour": true, "Minute": true, "Weekday": true, "Day": true, "Month": true, "YearDay": true,
}

// wallClockViews are the methods returning the same moment in another form.
var wallClockViews = map[string]bool{
	"In": true, "UTC": true, "Local": true, "Add": true, "Truncate": true, "Round": true,
}

// decidesByWallClock reports a body comparing or switching on a calendar part
// of time.Now(), directly or through a local variable.
func decidesByWallClock(body *ast.BlockStmt) bool {
	nowVars := make(map[string]bool)
	unitVars := make(map[string]bool)
	isNow := func(e ast.Expr) bool {
		for {
			e = ast.Unparen(e)
			if patternkit.IsTimeNowCall(e) {
				return true
			}
			if id, ok := e.(*ast.Ident); ok {
				return nowVars[id.Name]
			}
			call, ok := e.(*ast.CallExpr)
			if !ok {
				return false
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !wallClockViews[sel.Sel.Name] {
				return false
			}
			e = sel.X
		}
	}
	isUnit := func(e ast.Expr) bool {
		e = ast.Unparen(e)
		if id, ok := e.(*ast.Ident); ok {
			return unitVars[id.Name]
		}
		call, ok := e.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		return ok && wallClockUnits[sel.Sel.Name] && isNow(sel.X)
	}
	decides := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) != len(n.Rhs) {
				return true
			}
			for i, lhs := range n.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				nowVars[id.Name] = isNow(n.Rhs[i])
				unitVars[id.Name] = isUnit(n.Rhs[i])
			}
		case *ast.BinaryExpr:
			if patternkit.IsComparison(n.Op) && (isUnit(n.X) || isUnit(n.Y)) {
				decides = true
			}
		case *ast.SwitchStmt:
			if n.Tag != nil && isUnit(n.Tag) {
				decides = true
			}
		}
		return !decides
	})
	return decides
}

// ResetState drops the functions of the previous root.
func (r *TestDependsOnWallClockRule) ResetState() { r.dirs = nil }

// AnalyzeFile reports the calls of the file's tests into wall-clock code.
func (r *TestDependsOnWallClockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !goTestFile(ctx) {
		return nil
	}
	pkg := r.dirs[filepath.Dir(ctx.Path)]
	if pkg == nil || len(pkg.clock) == 0 {
		return nil
	}
	external := ctx.GoAST.Name.Name != pkg.name
	imported := make(map[string]bool)
	for _, imp := range patternkit.FileImports(ctx.GoAST) {
		imported[imp.Name] = true
	}
	bodies := testingBodies(ctx.GoAST)
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fakesOrReadsClock(fn.Body) {
			continue
		}
		for _, tb := range bodiesWithin(bodies, fn) {
			unused := valuesUnused(tb.body)
			ownNodes(tb.body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || unused[call] {
					return true
				}
				name, leaf := r.clockCallee(pkg, call, external, imported)
				if leaf == "" {
					return true
				}
				line := ctx.LineFor(call)
				if ctx.IsSuppressed(line, r.Name()) {
					return true
				}
				message := "Test calls " + name + ", which decides by the hour, weekday or date of time.Now() — the test passes or fails by when it runs"
				if leaf != name {
					message = "Test calls " + name + ", which through " + leaf + " decides by the hour, weekday or date of time.Now() — the test passes or fails by when it runs"
				}
				violations = append(violations, testReport(r.BaseRule, ctx, line, message,
					"Pass the moment or a clock into "+leaf+" and set it in the test"))
				return true
			})
		}
	}
	return violations
}

// clockCallee returns the called name and the wall-clock function it leads
// to, or an empty leaf. In the package's own tests a bare name or a method
// is the package's; in an external test package only pkg.Exported is.
func (r *TestDependsOnWallClockRule) clockCallee(pkg *wallClockPackage, call *ast.CallExpr, external bool, imported map[string]bool) (string, string) {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		if !external {
			return fun.Name, pkg.clock[fun.Name]
		}
	case *ast.SelectorExpr:
		x, isIdent := fun.X.(*ast.Ident)
		if isIdent && imported[x.Name] {
			if external && x.Name == pkg.name && ast.IsExported(fun.Sel.Name) {
				return fun.Sel.Name, pkg.clock[fun.Sel.Name]
			}
			return "", ""
		}
		return fun.Sel.Name, pkg.clock[fun.Sel.Name]
	}
	return "", ""
}

// valuesUnused returns the calls of a body whose values the test drops: a
// call standing as a statement, or assigned with only its last result (the
// error) kept. Such a test checks how the call fails, not what it decided.
func valuesUnused(body *ast.BlockStmt) map[*ast.CallExpr]bool {
	unused := make(map[*ast.CallExpr]bool)
	ownNodes(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ExprStmt:
			if call, ok := ast.Unparen(n.X).(*ast.CallExpr); ok {
				unused[call] = true
			}
		case *ast.AssignStmt:
			if len(n.Rhs) != 1 || len(n.Lhs) < 2 {
				return true
			}
			call, ok := ast.Unparen(n.Rhs[0]).(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, lhs := range n.Lhs[:len(n.Lhs)-1] {
				if !helpers.IsIdentNamed(lhs, "_") {
					return true
				}
			}
			unused[call] = true
		}
		return true
	})
	return unused
}

// bodiesWithin returns the testing bodies that lie in fn.
func bodiesWithin(bodies []testingBody, fn *ast.FuncDecl) []testingBody {
	var in []testingBody
	for _, tb := range bodies {
		if tb.body.Pos() >= fn.Body.Pos() && tb.body.End() <= fn.Body.End() {
			in = append(in, tb)
		}
	}
	return in
}

// fakesOrReadsClock reports a test function that runs in a synctest bubble,
// whose clock is fake, or reads time.Now() itself to compute what it expects.
func fakesOrReadsClock(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if sel, ok := n.(*ast.SelectorExpr); ok && helpers.IsIdentNamed(sel.X, "synctest") {
			found = true
		}
		if expr, ok := n.(ast.Expr); ok && patternkit.IsTimeNowCall(expr) {
			found = true
		}
		return true
	})
	return found
}
