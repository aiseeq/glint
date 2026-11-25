package frontendrules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewTSConstantCopiesGoConstantRule())
}

// TSConstantCopiesGoConstantRule detects top-level frontend numeric constants
// that duplicate numeric production Go constants with related names.
type TSConstantCopiesGoConstantRule struct {
	*rules.BaseRule
	goConstants []goNumericConstant
}

type goNumericConstant struct {
	name  string
	value float64
}

var tsNumericConstant = regexp.MustCompile(`\b(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*(-?(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?)`)

// NewTSConstantCopiesGoConstantRule creates the rule.
func NewTSConstantCopiesGoConstantRule() *TSConstantCopiesGoConstantRule {
	return &TSConstantCopiesGoConstantRule{BaseRule: rules.NewBaseRule(
		"ts-constant-copies-go-constant",
		"duplication",
		"Detects frontend numeric constants that copy matching backend Go constants",
		core.SeverityMedium,
	)}
}

// ResetState clears the constants collected from the current project.
func (r *TSConstantCopiesGoConstantRule) ResetState() { r.goConstants = nil }

// UseProjectFiles collects numeric constants from production Go files. An
// unexported constant its package uses only inside loops that read in pages
// of it is left out: it is not a contract of the API.
func (r *TSConstantCopiesGoConstantRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	packages := make(map[string][]*ast.File)
	private := make(map[string]map[*ast.Ident]float64)
	for _, ctx := range files {
		if !patternkit.ProductionGoFile(ctx) || ctx.IsGenerated() || strings.Contains(ctx.RelPath, "generated") {
			continue
		}
		pkg := filepath.Dir(ctx.RelPath)
		packages[pkg] = append(packages[pkg], ctx.GoAST)
		for _, c := range goNumericConstants(ctx.GoAST) {
			if c.ident.IsExported() {
				r.goConstants = append(r.goConstants, goNumericConstant{name: c.ident.Name, value: c.value})
				continue
			}
			if private[pkg] == nil {
				private[pkg] = make(map[*ast.Ident]float64)
			}
			private[pkg][c.ident] = c.value
		}
	}
	for pkg, decls := range private {
		steps := pagedReadsOnly(packages[pkg], decls)
		for decl, value := range decls {
			if !steps[decl.Name] {
				r.goConstants = append(r.goConstants, goNumericConstant{name: decl.Name, value: value})
			}
		}
	}
}

type declaredConstant struct {
	ident *ast.Ident
	value float64
}

// goNumericConstants lists the top-level constants of file with a numeric
// value other than a small business one.
func goNumericConstants(file *ast.File) []declaredConstant {
	var out []declaredConstant
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok || len(valueSpec.Values) != len(valueSpec.Names) {
				continue
			}
			for i, name := range valueSpec.Names {
				if value, ok := goNumericValue(valueSpec.Values[i]); ok && !smallBusinessConstant(value) {
					out = append(out, declaredConstant{ident: name, value: value})
				}
			}
		}
	}
	return out
}

// pagedReadsOnly names the constants declared at decls whose every use in the
// package is a form of a loop reading in pages of it, inside a for loop of the
// same function (a function literal ends the loop): the step of a cursor, an
// argument of a page read, a stop on a short page, a slice bound. Any other
// use — a return, a literal, another sum, the condition of the for, an
// argument of a call that is not a read, a shadowing declaration — keeps the
// constant a contract.
func pagedReadsOnly(files []*ast.File, decls map[*ast.Ident]float64) map[string]bool {
	names := make(map[string]bool, len(decls))
	for decl := range decls {
		names[decl.Name] = true
	}
	paged, other := make(map[string]bool), make(map[string]bool)
	loops := make(map[pageLoopKey]*pageLoop)
	for _, file := range files {
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			if ident, ok := n.(*ast.Ident); ok && names[ident.Name] {
				if _, declared := decls[ident]; !declared {
					if pagedUse(stack, ident.Name, loops) {
						paged[ident.Name] = true
					} else {
						other[ident.Name] = true
					}
				}
			}
			stack = append(stack, n)
			return true
		})
	}
	only := make(map[string]bool, len(paged))
	for name := range paged {
		only[name] = !other[name]
	}
	return only
}

type pageLoopKey struct {
	loop *ast.ForStmt
	name string
}

// pageLoop is what a for loop, outside its function literals, does with a
// page constant.
type pageLoop struct {
	cursors map[string]bool // x of x += c, x = x + c, x = c + x
	reads   map[string]bool // v of v, … := call(…, c, …)
	stops   map[string]bool // v of len(v) < c, c > len(v); pagedUse checks the if around it
}

// pagedUse reports whether the use of the constant name at the top of stack
// is one of the forms of a paged read in a for loop around it.
func pagedUse(stack []ast.Node, name string, loops map[pageLoopKey]*pageLoop) bool {
	around := enclosingPageLoops(stack, name, loops)
	if len(around) == 0 {
		return false
	}
	parent, grand := stack[len(stack)-1], stack[len(stack)-2]
	switch p := parent.(type) {
	case *ast.AssignStmt:
		return cursorStep(p, name) != ""
	case *ast.CallExpr:
		assign, ok := grand.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return false
		}
		return slices.ContainsFunc(around, func(l *pageLoop) bool { return len(l.cursors) > 0 || anyName(assign.Lhs, l.stops) })
	case *ast.BinaryExpr:
		if v := shortPage(p, name); v != "" {
			stop, ok := grand.(*ast.IfStmt)
			return ok && endsLoop(stop) && slices.ContainsFunc(around, func(l *pageLoop) bool { return l.reads[v] })
		}
		if p.Op != token.ADD {
			return false
		}
		if assign, ok := grand.(*ast.AssignStmt); ok {
			return cursorStep(assign, name) != ""
		}
		cursor, ok := p.X.(*ast.Ident)
		return ok && sliceBound(stack) && slices.ContainsFunc(around, func(l *pageLoop) bool { return l.cursors[cursor.Name] })
	}
	return false
}

// enclosingPageLoops lists the for loops around the top of stack up to the
// function that holds it.
func enclosingPageLoops(stack []ast.Node, name string, loops map[pageLoopKey]*pageLoop) []*pageLoop {
	var out []*pageLoop
	for i := len(stack) - 1; i >= 0; i-- {
		switch n := stack[i].(type) {
		case *ast.FuncLit:
			return out
		case *ast.ForStmt:
			key := pageLoopKey{loop: n, name: name}
			if loops[key] == nil {
				loops[key] = newPageLoop(n, name)
			}
			out = append(out, loops[key])
		}
	}
	return out
}

func newPageLoop(loop *ast.ForStmt, name string) *pageLoop {
	l := &pageLoop{cursors: make(map[string]bool), reads: make(map[string]bool), stops: make(map[string]bool)}
	ast.Inspect(loop, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			if cursor := cursorStep(n, name); cursor != "" {
				l.cursors[cursor] = true
			}
			if call, ok := n.Rhs[0].(*ast.CallExpr); ok && passes(call, name) {
				for _, lhs := range n.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						l.reads[ident.Name] = true
					}
				}
			}
		case *ast.BinaryExpr:
			if v := shortPage(n, name); v != "" {
				l.stops[v] = true
			}
		}
		return true
	})
	return l
}

// cursorStep names x of a statement x += name, x = x + name or x = name + x.
// The operator of the sum is left to pagedUse: name under any other operator
// is another use, which keeps the constant a contract anyway.
func cursorStep(assign *ast.AssignStmt, name string) string {
	if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return ""
	}
	cursor, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return ""
	}
	if assign.Tok == token.ADD_ASSIGN && isName(assign.Rhs[0], name) {
		return cursor.Name
	}
	sum, ok := assign.Rhs[0].(*ast.BinaryExpr)
	if assign.Tok != token.ASSIGN || !ok {
		return ""
	}
	if isName(sum.X, cursor.Name) && isName(sum.Y, name) || isName(sum.X, name) && isName(sum.Y, cursor.Name) {
		return cursor.Name
	}
	return ""
}

// shortPage names v of len(v) < name or name > len(v).
func shortPage(cmp *ast.BinaryExpr, name string) string {
	switch {
	case cmp.Op == token.LSS && isName(cmp.Y, name):
		return lenOf(cmp.X)
	case cmp.Op == token.GTR && isName(cmp.X, name):
		return lenOf(cmp.Y)
	}
	return ""
}

// endsLoop reports an if without else whose body only breaks or returns.
func endsLoop(stop *ast.IfStmt) bool {
	if stop.Else != nil || len(stop.Body.List) != 1 {
		return false
	}
	switch s := stop.Body.List[0].(type) {
	case *ast.BranchStmt:
		return s.Tok == token.BREAK
	case *ast.ReturnStmt:
		return true
	}
	return false
}

// sliceBound reports whether the sum at the top of stack bounds a slice:
// s[i:i+c], s[i:min(i+c, len(s))] or end := min(i+c, len(s)).
func sliceBound(stack []ast.Node) bool {
	parent := stack[len(stack)-2]
	if _, ok := parent.(*ast.SliceExpr); ok {
		return true
	}
	// With len(s) second, the sum can only be the first argument.
	call, ok := parent.(*ast.CallExpr)
	if !ok || !isName(call.Fun, "min") || len(call.Args) != 2 || lenOf(call.Args[1]) == "" {
		return false
	}
	switch stack[len(stack)-3].(type) {
	case *ast.SliceExpr:
		return true
	case *ast.AssignStmt:
		return true
	}
	return false
}

func passes(call *ast.CallExpr, name string) bool {
	for _, arg := range call.Args {
		if isName(arg, name) {
			return true
		}
	}
	return false
}

func anyName(exprs []ast.Expr, set map[string]bool) bool {
	for _, expr := range exprs {
		if ident, ok := expr.(*ast.Ident); ok && set[ident.Name] {
			return true
		}
	}
	return false
}

func isName(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

// lenOf names v of len(v).
func lenOf(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok || !isName(call.Fun, "len") || len(call.Args) != 1 {
		return ""
	}
	if v, ok := call.Args[0].(*ast.Ident); ok {
		return v.Name
	}
	return ""
}

func goNumericValue(expr ast.Expr) (float64, bool) {
	var value constant.Value
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			text := constant.MakeFromLiteral(e.Value, e.Kind, 0)
			if text.Kind() != constant.String {
				return 0, false
			}
			parsed, err := strconv.ParseFloat(strings.ReplaceAll(constant.StringVal(text), "_", ""), 64)
			return parsed, err == nil
		}
		if e.Kind != token.INT && e.Kind != token.FLOAT {
			return 0, false
		}
		value = constant.MakeFromLiteral(e.Value, e.Kind, 0)
	case *ast.UnaryExpr:
		if e.Op != token.ADD && e.Op != token.SUB {
			return 0, false
		}
		lit, ok := e.X.(*ast.BasicLit)
		if !ok || lit.Kind != token.INT && lit.Kind != token.FLOAT {
			return 0, false
		}
		value = constant.MakeFromLiteral(lit.Value, lit.Kind, 0)
		if e.Op == token.SUB {
			value = constant.UnaryOp(token.SUB, value, 0)
		}
	default:
		return 0, false
	}
	if value == nil || value.Kind() != constant.Int && value.Kind() != constant.Float {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(constant.ToFloat(value).String(), 64)
	return parsed, err == nil
}

func smallBusinessConstant(value float64) bool {
	return value == 0 || value == 1 || value == 2 || value == -1
}

// AnalyzeFile reports frontend constants whose value and name copy a Go constant.
func (r *TSConstantCopiesGoConstantRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || patternkit.SkipFrontendPath(ctx) || ctx.IsGenerated() || strings.Contains(ctx.RelPath, "generated") {
		return nil
	}
	flat := patternkit.NewJSFlat(ctx)
	type finding struct {
		line, start  int
		name, goName string
		value        float64
	}
	var findings []finding
	for _, match := range tsNumericConstant.FindAllStringSubmatchIndex(flat.Code, -1) {
		if flat.EnclosingBrace(match[0]) != -1 {
			continue
		}
		value, err := strconv.ParseFloat(strings.ReplaceAll(flat.Code[match[4]:match[5]], "_", ""), 64)
		if err != nil || smallBusinessConstant(value) {
			continue
		}
		name := flat.Code[match[2]:match[3]]
		var candidates []string
		for _, backend := range r.goConstants {
			if backend.value == value && namesRelated(name, backend.name) {
				candidates = append(candidates, backend.name)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		sort.Strings(candidates)
		findings = append(findings, finding{line: flat.Line(match[0]), start: match[0], name: name, goName: candidates[0], value: value})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].start < findings[j].start })
	out := make([]*core.Violation, 0, len(findings))
	for _, f := range findings {
		v := r.CreateViolation(ctx.RelPath, f.line, f.name+" copies the backend constant "+f.goName+" ("+strconv.FormatFloat(f.value, 'f', -1, 64)+") — take the value from the API or a generated config")
		v.WithCode(strings.TrimSpace(ctx.Lines[f.line-1]))
		out = append(out, v)
	}
	return out
}

func namesRelated(frontend, backend string) bool {
	frontWords, backendWords := constantNameWords(frontend), constantNameWords(backend)
	if len(frontWords) == 0 || len(backendWords) == 0 {
		return false
	}
	available := make(map[string]bool, len(backendWords))
	for _, word := range backendWords {
		available[word] = true
	}
	common := make(map[string]bool)
	for _, word := range frontWords {
		if !available[word] {
			return false
		}
		common[word] = true
	}
	return len(common) >= 2
}

func constantNameWords(name string) []string {
	words := patternkit.IdentifierWords(name)
	for i, word := range words {
		switch word {
		case "maximum", "limit":
			words[i] = "max"
		case "minimum":
			words[i] = "min"
		}
	}
	return words
}

func frontendProjectReportsOn(ctx *core.FileContext) bool {
	return ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile()
}

// ReportsOn reports whether this rule can report on this file.
func (r *TSConstantCopiesGoConstantRule) ReportsOn(ctx *core.FileContext) bool {
	return frontendProjectReportsOn(ctx)
}
