package patterns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/types/typeutil"
)

func init() {
	rules.Register(NewCLINumberFlagUncheckedRule())
	rules.Register(NewCLIFlagMapLookupWithoutOKRule())
}

// flagOrigin is the command-line flag a value comes from.
type flagOrigin struct {
	name    string
	numeric bool
}

// flagFeeds follows the values of a package's command-line flags: the
// variables and fields a flag is bound to, and those its value is copied
// into - a local, a field set by assignment, a field of a struct literal.
type flagFeeds struct {
	info   *types.Info
	origin map[types.Object]flagOrigin
	// checked holds the flags compared with a constant somewhere in the
	// package: the program looks at the value it was given.
	checked map[string]bool
	// lookedUp holds the maps a flag indexes in a checked form somewhere in
	// the package - comma-ok, or a result tested right away - keyed by map
	// and flag: the flag's value is validated against that map.
	lookedUp map[flagLookup]bool
}

type flagLookup struct {
	m    types.Object
	flag string
}

var numericFlagFuncs = map[string]bool{
	"Int": true, "Int64": true, "Uint": true, "Uint64": true, "Float64": true, "Duration": true,
	"IntVar": true, "Int64Var": true, "UintVar": true, "Uint64Var": true, "Float64Var": true, "DurationVar": true,
}

var textFlagFuncs = map[string]bool{"String": true, "StringVar": true}

// packageFlagFeeds collects the flag values of one package's files.
func packageFlagFeeds(files []*core.FileContext, info *types.Info) *flagFeeds {
	feeds := &flagFeeds{info: info, origin: map[types.Object]flagOrigin{}, checked: map[string]bool{}, lookedUp: map[flagLookup]bool{}}
	for _, file := range files {
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			feeds.bind(n)
			return true
		})
	}
	if len(feeds.origin) == 0 {
		return feeds
	}
	for changed := true; changed; {
		changed = false
		for _, file := range files {
			ast.Inspect(file.GoAST, func(n ast.Node) bool {
				changed = feeds.copyInto(n) || changed
				return true
			})
		}
	}
	for _, file := range files {
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			feeds.markChecked(n)
			feeds.markLookedUp(n)
			return true
		})
	}
	return feeds
}

// markLookedUp records a checked lookup of a map by a flag: v, ok := m[flag],
// or if v := m[flag]; v == nil.
func (f *flagFeeds) markLookedUp(n ast.Node) {
	var index *ast.IndexExpr
	switch node := n.(type) {
	case *ast.AssignStmt:
		if len(node.Lhs) == 2 && len(node.Rhs) == 1 {
			index, _ = ast.Unparen(node.Rhs[0]).(*ast.IndexExpr)
		}
	case *ast.ValueSpec:
		if len(node.Names) == 2 && len(node.Values) == 1 {
			index, _ = ast.Unparen(node.Values[0]).(*ast.IndexExpr)
		}
	case *ast.IfStmt:
		index = f.testedLookup(node)
	}
	if index == nil {
		return
	}
	if origin, ok := f.reads(index.Index); ok {
		if m := f.objectOf(index.X); m != nil {
			f.lookedUp[flagLookup{m, origin.name}] = true
		}
	}
}

// testedLookup returns m[k] of an if whose init stores it in a variable the
// condition reads: if v := m[k]; v == nil.
func (f *flagFeeds) testedLookup(ifStmt *ast.IfStmt) *ast.IndexExpr {
	init, ok := ifStmt.Init.(*ast.AssignStmt)
	if !ok || len(init.Lhs) != 1 || len(init.Rhs) != 1 {
		return nil
	}
	index, ok := ast.Unparen(init.Rhs[0]).(*ast.IndexExpr)
	if !ok {
		return nil
	}
	target := f.objectOf(init.Lhs[0])
	read := false
	ast.Inspect(ifStmt.Cond, func(n ast.Node) bool {
		if expr, ok := n.(ast.Expr); ok && target != nil && f.objectOf(expr) == target {
			read = true
		}
		return !read
	})
	if !read {
		return nil
	}
	return index
}

// bind records a flag definition: x := flag.Int("name", ...) binds x,
// flag.IntVar(&cfg.n, "name", ...) binds the field n.
func (f *flagFeeds) bind(n ast.Node) {
	switch node := n.(type) {
	case *ast.AssignStmt:
		if len(node.Lhs) != 1 || len(node.Rhs) != 1 {
			return
		}
		if origin, ok := f.definition(node.Rhs[0], false); ok {
			f.set(node.Lhs[0], origin)
		}
	case *ast.ValueSpec:
		if len(node.Names) != 1 || len(node.Values) != 1 {
			return
		}
		if origin, ok := f.definition(node.Values[0], false); ok {
			f.set(node.Names[0], origin)
		}
	case *ast.CallExpr:
		if origin, ok := f.definition(node, true); ok && len(node.Args) > 0 {
			if addr, ok := ast.Unparen(node.Args[0]).(*ast.UnaryExpr); ok && addr.Op == token.AND {
				f.set(addr.X, origin)
			}
		}
	}
}

// definition reads a flag definition call: the Var form binds its first
// argument, the other form returns a pointer.
func (f *flagFeeds) definition(expr ast.Expr, varForm bool) (flagOrigin, bool) {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return flagOrigin{}, false
	}
	fn, ok := typeutil.Callee(f.info, call).(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "flag" {
		return flagOrigin{}, false
	}
	if strings.HasSuffix(fn.Name(), "Var") != varForm {
		return flagOrigin{}, false
	}
	numeric := numericFlagFuncs[fn.Name()]
	if !numeric && !textFlagFuncs[fn.Name()] {
		return flagOrigin{}, false
	}
	nameArg := 0
	if varForm {
		nameArg = 1
	}
	if len(call.Args) <= nameArg {
		return flagOrigin{}, false
	}
	tv, ok := f.info.Types[call.Args[nameArg]]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return flagOrigin{}, false
	}
	return flagOrigin{name: constant.StringVal(tv.Value), numeric: numeric}, true
}

// set binds the variable or field the expression names.
func (f *flagFeeds) set(expr ast.Expr, origin flagOrigin) bool {
	obj := f.objectOf(expr)
	if obj == nil {
		return false
	}
	if _, ok := f.origin[obj]; ok {
		return false
	}
	f.origin[obj] = origin
	return true
}

func (f *flagFeeds) objectOf(expr ast.Expr) types.Object {
	switch node := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return f.info.ObjectOf(node)
	case *ast.SelectorExpr:
		return f.info.Uses[node.Sel]
	}
	return nil
}

// copyInto follows a flag value into the variable or field it is copied to.
func (f *flagFeeds) copyInto(n ast.Node) bool {
	changed := false
	switch node := n.(type) {
	case *ast.AssignStmt:
		if len(node.Lhs) != len(node.Rhs) {
			return false
		}
		for i, rhs := range node.Rhs {
			if origin, ok := f.reads(rhs); ok {
				changed = f.set(node.Lhs[i], origin) || changed
			}
		}
	case *ast.KeyValueExpr:
		key, ok := node.Key.(*ast.Ident)
		if !ok {
			return false
		}
		if field, ok := f.info.Uses[key].(*types.Var); ok && field.IsField() {
			if origin, ok := f.reads(node.Value); ok {
				if _, seen := f.origin[field]; !seen {
					f.origin[field] = origin
					changed = true
				}
			}
		}
	}
	return changed
}

// reads returns the flag whose value the expression reads, if any.
func (f *flagFeeds) reads(expr ast.Expr) (flagOrigin, bool) {
	var found flagOrigin
	ok := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ok {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			// a value a function computes from the flag is not the flag
			if _, builtin := typeutil.Callee(f.info, node).(*types.Builtin); !builtin {
				if tv, conv := f.info.Types[node.Fun]; !conv || !tv.IsType() {
					return false
				}
			}
		case *ast.SelectorExpr:
			if origin, seen := f.origin[f.info.Uses[node.Sel]]; seen {
				found, ok = origin, true
				return false
			}
		case *ast.Ident:
			if origin, seen := f.origin[f.info.ObjectOf(node)]; seen {
				found, ok = origin, true
			}
		}
		return true
	})
	return found, ok
}

// markChecked records a flag compared with a constant.
func (f *flagFeeds) markChecked(n ast.Node) {
	binary, ok := n.(*ast.BinaryExpr)
	if !ok || !isComparison(binary.Op) {
		return
	}
	for _, pair := range [][2]ast.Expr{{binary.X, binary.Y}, {binary.Y, binary.X}} {
		origin, reads := f.reads(pair[0])
		if !reads {
			continue
		}
		if tv, ok := f.info.Types[pair[1]]; ok && tv.Value != nil {
			f.checked[origin.name] = true
		}
	}
}

// flagRule runs a check over the flag values of every package.
type flagRule struct {
	*rules.BaseRule
	suggestion string
	check      func(feeds *flagFeeds, file *core.FileContext) []flagFinding
}

type flagFinding struct {
	node    ast.Node
	flag    string
	message string
}

// AnalyzeFile is a no-op: the rule follows values across the package.
func (r *flagRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough.
func (r *flagRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks the production files of every package that defines
// command-line flags, reporting each flag once at its first use.
func (r *flagRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		var files []*core.FileContext
		for _, file := range pkg.Files {
			if file.GoAST != nil && !file.IsTestFile() {
				files = append(files, file)
			}
		}
		feeds := packageFlagFeeds(files, pkg.Package.TypesInfo)
		if len(feeds.origin) == 0 {
			continue
		}
		type located struct {
			file    *core.FileContext
			finding flagFinding
		}
		var found []located
		for _, file := range files {
			for _, finding := range r.check(feeds, file) {
				found = append(found, located{file, finding})
			}
		}
		sort.SliceStable(found, func(i, j int) bool {
			if found[i].file.RelPath != found[j].file.RelPath {
				return found[i].file.RelPath < found[j].file.RelPath
			}
			return found[i].finding.node.Pos() < found[j].finding.node.Pos()
		})
		reported := map[string]bool{}
		for _, item := range found {
			if reported[item.finding.flag] {
				continue
			}
			line := item.file.LineFor(item.finding.node)
			if item.file.IsSuppressed(line, r.Name()) {
				continue
			}
			reported[item.finding.flag] = true
			v := r.CreateViolation(item.file.RelPath, line, item.finding.message)
			v.WithCode(strings.TrimSpace(item.file.GetLine(line)))
			v.WithSuggestion(r.suggestion)
			violations = append(violations, v)
		}
	}
	return violations, nil
}

// NewCLINumberFlagUncheckedRule reports a numeric command-line flag that
// reaches a size, a bound or an interval with no check that it is positive:
//
//	flag.IntVar(&cfg.parallel, "parallel", 1, "workers")
//	for i := 0; i < cfg.parallel; i++ { go worker() }   // -parallel 0: no worker
//	time.NewTicker(*progress)                           // -progress 0: panic
//
// Zero or a negative number typed on the command line then panics far from
// the flag, or worse, makes the program do nothing and exit with success.
func NewCLINumberFlagUncheckedRule() *flagRule {
	return &flagRule{
		BaseRule: rules.NewBaseRule("cli-number-flag-unchecked", "patterns",
			"Detects a numeric command-line flag reaching a worker count, a buffer size, a ticker interval or a slice bound with no check that it is positive — 0 from the command line panics or quietly does nothing",
			core.SeverityMedium),
		suggestion: "Check the flag right after flag.Parse and fail with a usage error when it is not positive",
		check:      numberFlagSinks,
	}
}

func numberFlagSinks(feeds *flagFeeds, file *core.FileContext) []flagFinding {
	var found []flagFinding
	add := func(node ast.Node, expr ast.Expr, what string) {
		origin, ok := feeds.reads(expr)
		if !ok || !origin.numeric || feeds.checked[origin.name] {
			return
		}
		found = append(found, flagFinding{node, origin.name, fmt.Sprintf(
			"Flag -%s reaches %s with no check that it is positive — a zero or negative value from the command line makes the program fail or quietly do nothing", origin.name, what)})
	}
	ast.Inspect(file.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			numberFlagCallSink(feeds.info, node, add)
		case *ast.SliceExpr:
			for _, bound := range []ast.Expr{node.Low, node.High, node.Max} {
				if bound != nil {
					add(node, bound, "a slice bound")
				}
			}
		case *ast.ForStmt:
			if bound, ok := node.Cond.(*ast.BinaryExpr); ok && (bound.Op == token.LSS || bound.Op == token.LEQ) && startsGoroutine(node.Body) {
				add(node, bound.Y, "a worker loop bound")
			}
		}
		return true
	})
	return found
}

func numberFlagCallSink(info *types.Info, call *ast.CallExpr, add func(ast.Node, ast.Expr, string)) {
	if builtin, ok := typeutil.Callee(info, call).(*types.Builtin); ok && builtin.Name() == "make" && len(call.Args) > 1 {
		what := "a make size"
		if _, isChan := typeOrNil(info, call.Args[0]).Underlying().(*types.Chan); isChan {
			what = "a channel buffer size"
		}
		for _, size := range call.Args[1:] {
			add(call, size, what)
		}
		return
	}
	if len(call.Args) == 1 && calleeIn(call, info, "time", "NewTicker", "Tick", "Reset") {
		fn, _ := typeutil.Callee(info, call).(*types.Func)
		name := "time." + fn.Name()
		if fn.Name() == "Reset" {
			name = "Ticker.Reset"
		}
		add(call, call.Args[0], name)
	}
}

func startsGoroutine(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.GoStmt); ok {
			found = true
		}
		return !found
	})
	return found
}

// NewCLIFlagMapLookupWithoutOKRule reports a map indexed by a command-line
// flag without the comma-ok form:
//
//	match.CPU(..., Difficulties[*diff], ...)
//
// A value typed wrong on the command line gives the zero value, and the
// program runs with it instead of failing on the unknown name.
func NewCLIFlagMapLookupWithoutOKRule() *flagRule {
	return &flagRule{
		BaseRule: rules.NewBaseRule("cli-flag-map-lookup-without-ok", "patterns",
			"Detects a map indexed by a command-line flag without the comma-ok form — a mistyped value runs with the zero value instead of failing",
			core.SeverityMedium),
		suggestion: "Look the value up with v, ok := m[*flag] and fail with the list of known values when it is missing",
		check:      flagMapLookups,
	}
}

func flagMapLookups(feeds *flagFeeds, file *core.FileContext) []flagFinding {
	checked := map[*ast.IndexExpr]bool{}
	ast.Inspect(file.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if index, ok := ast.Unparen(lhs).(*ast.IndexExpr); ok {
					checked[index] = true
				}
			}
			if len(node.Lhs) == 2 && len(node.Rhs) == 1 {
				if index, ok := ast.Unparen(node.Rhs[0]).(*ast.IndexExpr); ok {
					checked[index] = true
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) == 2 && len(node.Values) == 1 {
				if index, ok := ast.Unparen(node.Values[0]).(*ast.IndexExpr); ok {
					checked[index] = true
				}
			}
		}
		return true
	})
	var found []flagFinding
	ast.Inspect(file.GoAST, func(n ast.Node) bool {
		index, ok := n.(*ast.IndexExpr)
		if !ok || checked[index] {
			return true
		}
		mapType, ok := typeOrNil(feeds.info, index.X).Underlying().(*types.Map)
		if !ok || isBooleanType(mapType.Elem()) {
			return true
		}
		origin, ok := feeds.reads(index.Index)
		if !ok || feeds.lookedUp[flagLookup{feeds.objectOf(index.X), origin.name}] {
			return true
		}
		found = append(found, flagFinding{index, origin.name, fmt.Sprintf(
			"Map %s is indexed by flag -%s without the comma-ok form — a value typed wrong on the command line runs with the zero value instead of failing",
			types.ExprString(index.X), origin.name)})
		return true
	})
	return found
}
