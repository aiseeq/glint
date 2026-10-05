package patterns

import (
	"go/ast"
	"go/constant"
	"go/types"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewDateFromLocalClockRule())
}

// NewDateFromLocalClockRule creates date-from-local-clock: a calendar date
// cut from the process's clock lands on the neighbouring day around midnight
// depending on the zone of the host the binary runs on, and disagrees with
// the dates the rest of the system takes in UTC:
//
//	snap.Date = time.Now().Format("2006-01-02")        // "today" of the host
//
// A time normalized with UTC() or In(loc) before the cut is not reported. A
// date cut from a timestamp scanned from the database is the session zone's
// business: sql-session-timezone reports it.
func NewDateFromLocalClockRule() *DateFromLocalClockRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"date-from-local-clock",
			"patterns",
			"Detects a calendar date formatted from time.Now() with no UTC()/In(loc) — around midnight it is another day than in UTC, depending on the host's zone",
			core.SeverityMedium,
		),
		suggestion: "Normalize the time first: t.UTC().Format(...) (or In(loc) with the zone the date is defined in)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		defs := singleDefinitions(scope.info, fn.Body)
		parents := helpers.ParentMap(fn.Body)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Format" || !isTimeTimeType(scope.info.TypeOf(sel.X)) || !dateOnlyLayout(scope.info, call.Args[0]) {
				return true
			}
			if localClock(scope.info, defs, sel.X, 0) && !onlyText(scope.info, fn.Body, parents, call) {
				findings = append(findings, funcFinding{node: call, message: "A calendar date is formatted from time.Now() in the host's zone — around midnight it is another day than in UTC"})
			}
			return true
		})
		return findings
	}
	return &DateFromLocalClockRule{typedFuncRule: r}
}

// DateFromLocalClockRule is date-from-local-clock: the typed check of
// production code, and for tests, which are not type-checked, a syntactic
// one against the project's business-day helper.
type DateFromLocalClockRule struct {
	*typedFuncRule
}

// AnalyzeGoProject runs the typed check, then the check of the test files.
func (r *DateFromLocalClockRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	violations, err := r.typedFuncRule.AnalyzeGoProject(ctx)
	if err != nil {
		return nil, err
	}
	helpers := todayHelpers(ctx.Files)
	if len(helpers) == 0 {
		return violations, nil
	}
	for _, file := range ctx.Files {
		violations = append(violations, r.hostClockToday(file, helpers[0])...)
	}
	return violations, nil
}

// dateWords name a calendar day in a helper's name; the other words of the
// name are what the date is of (TodayRateDate: rates).
var dateWords = map[string]bool{"today": true, "date": true, "day": true, "get": true, "current": true}

// helperNouns returns the words of a helper's name that are not about the day.
func helperNouns(helper string) []string {
	_, name, _ := strings.Cut(helper, ".")
	var nouns []string
	for _, word := range helpers.IdentifierWords(name) {
		if !dateWords[strings.ToLower(word)] {
			nouns = append(nouns, strings.ToLower(word))
		}
	}
	return nouns
}

// mentionsNoun reports a name with a word starting with one of the nouns:
// upsertXERates for rate.
func mentionsNoun(name string, nouns []string) bool {
	for _, word := range helpers.IdentifierWords(name) {
		for _, noun := range nouns {
			if strings.HasPrefix(strings.ToLower(word), noun) {
				return true
			}
		}
	}
	return false
}

// todayHelpers returns the project's functions named for today that return
// a time.Time: domain.TodayRateDate.
func todayHelpers(files []*core.FileContext) []string {
	var found []string
	for _, file := range files {
		if !file.IsGoFile() || !file.HasGoAST() || file.IsTestFile() {
			continue
		}
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !hasWordFrom(fn.Name.Name, map[string]bool{"today": true}) {
				continue
			}
			named := hasWordFrom(fn.Name.Name, map[string]bool{"date": true, "day": true})
			if results := fn.Type.Results; named && results != nil && len(results.List) == 1 && isTimeTimeExpr(results.List[0].Type) {
				found = append(found, file.GoAST.Name.Name+"."+fn.Name.Name)
			}
		}
	}
	sort.Strings(found)
	return found
}

// hostClockToday reports, in a test file, today's date taken from the host
// clock: time.Now() kept in a variable named for the day, or handed to a
// write (Upsert, Insert, Save).
func (r *DateFromLocalClockRule) hostClockToday(ctx *core.FileContext, helper string) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || !ctx.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	report := func(node ast.Node) {
		line := ctx.LineFor(node)
		v := r.CreateViolation(ctx.RelPath, line,
			"The test takes today's date from the host clock while the project defines "+helper+"() — around midnight in the business zone the test writes another day than the code reads")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Take the date from " + helper + "(), the helper production uses")
		violations = append(violations, v)
	}
	// A write gets the host's today only where it writes what the helper
	// dates: upsertRates(...) for TodayRateDate, not a session's created_at.
	nouns := helperNouns(helper)
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				if len(node.Lhs) == 1 && len(node.Rhs) == 1 && isTimeNowCall(node.Rhs[0]) {
					if id, ok := node.Lhs[0].(*ast.Ident); ok && id.Name == "today" {
						report(node)
					}
				}
			case *ast.CallExpr:
				if !helpers.IsWriteName(callName(node)) || len(nouns) == 0 {
					return true
				}
				if !mentionsNoun(fn.Name.Name, nouns) && !mentionsNoun(types.ExprString(node.Fun), nouns) {
					return true
				}
				for _, arg := range node.Args {
					if isTimeNowCall(arg) {
						report(arg)
					}
				}
			}
			return true
		})
	}
	return violations
}

// isTimeNowCall reports time.Now().
func isTimeNowCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Now" && isIdentNamed(sel.X, "time")
}

// isTimeTimeExpr reports the type expression time.Time.
func isTimeTimeExpr(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Time" && isIdentNamed(sel.X, "time")
}

// dateOnlyLayout reports a constant layout with a year and no time of day:
// "2006-01-02", time.DateOnly, "02.01.2006".
func dateOnlyLayout(info *types.Info, expr ast.Expr) bool {
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	return isDateOnlyLayout(constant.StringVal(tv.Value))
}

// dateOnlyLayoutSyntax is dateOnlyLayout without types: a string literal or
// time.DateOnly.
func dateOnlyLayoutSyntax(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		layout, err := strconv.Unquote(e.Value)
		return err == nil && isDateOnlyLayout(layout)
	case *ast.SelectorExpr:
		return e.Sel.Name == "DateOnly" && isIdentNamed(e.X, "time")
	}
	return false
}

func isDateOnlyLayout(layout string) bool {
	return strings.Contains(layout, "2006") && !strings.Contains(layout, "15") && !strings.Contains(layout, "04")
}

// onlyText reports a formatted date used only as text: glued into a string
// ("REF-" + date), handed to fmt or a logger, or held in a variable used
// only so. A reference or a file name carries the host's day harmlessly.
func onlyText(info *types.Info, body *ast.BlockStmt, parents map[ast.Node]ast.Node, expr ast.Expr) bool {
	if textOperand(parents, expr) {
		return true
	}
	assign, ok := parents[expr].(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != len(assign.Rhs) {
		return false
	}
	for i, rhs := range assign.Rhs {
		if rhs != expr {
			continue
		}
		ident, ok := assign.Lhs[i].(*ast.Ident)
		return ok && usedOnlyAsText(info, body, parents, info.ObjectOf(ident))
	}
	return false
}

// usedOnlyAsText reports a variable every use of which is text.
func usedOnlyAsText(info *types.Info, body *ast.BlockStmt, parents map[ast.Node]ast.Node, obj types.Object) bool {
	uses := 0
	text := true
	ast.Inspect(body, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok || info.Uses[ident] != obj {
			return true
		}
		uses++
		text = text && onlyText(info, body, parents, ident)
		return true
	})
	return uses > 0 && text
}

// localClock reports time.Now() that no UTC() or In(loc) normalized: Add,
// AddDate, Truncate and Round keep the zone; a local variable is followed to
// its only definition.
func localClock(info *types.Info, defs map[types.Object]ast.Expr, expr ast.Expr, depth int) bool {
	if depth > 4 {
		return false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		sel, ok := ast.Unparen(e.Fun).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if fn, ok := info.Uses[sel.Sel].(*types.Func); ok && fn.Pkg() != nil && fn.Pkg().Path() == "time" && fn.Name() == "Now" {
			return true
		}
		switch sel.Sel.Name {
		case "Add", "AddDate", "Truncate", "Round":
			return localClock(info, defs, sel.X, depth+1)
		}
	case *ast.Ident:
		if def, ok := defs[info.ObjectOf(e)]; ok {
			return localClock(info, defs, def, depth+1)
		}
	}
	return false
}

// singleDefinitions maps the local variables of a body defined once (v :=
// expr, var v = expr) and never assigned again to that expression.
func singleDefinitions(info *types.Info, body *ast.BlockStmt) map[types.Object]ast.Expr {
	defs := make(map[types.Object]ast.Expr)
	assigned := make(map[types.Object]int)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				obj := info.ObjectOf(ident)
				assigned[obj]++
				if len(node.Lhs) == len(node.Rhs) {
					defs[obj] = node.Rhs[i]
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				obj := info.ObjectOf(name)
				assigned[obj]++
				if len(node.Names) == len(node.Values) {
					defs[obj] = node.Values[i]
				}
			}
		}
		return true
	})
	for obj, count := range assigned {
		if count != 1 {
			delete(defs, obj)
		}
	}
	return defs
}
