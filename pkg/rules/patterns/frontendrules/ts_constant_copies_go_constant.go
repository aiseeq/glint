package frontendrules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"path/filepath"
	"regexp"
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
		steps := readLoopsOnly(packages[pkg], decls)
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

// readLoopsOnly names the constants declared at decls that the package uses
// only inside loops that read in pages of them. A read loop of a constant
// moves a cursor by it (offset += page, offset = offset + page), stops on a
// page shorter than it (len(rows) < page) or passes it to a call together
// with a cursor the loop assigns (cursor = next). Inside such a loop the
// constant may only step the cursor, bound a slice (i+page), end the reads on
// a short page or go to a call. Any use outside a read loop of the same
// function — a handler, a helper, a constructor, a response — and any other
// use, a shadowing declaration too, keeps it a contract.
func readLoopsOnly(files []*ast.File, decls map[*ast.Ident]float64) map[string]bool {
	names := make(map[string]bool, len(decls))
	for decl := range decls {
		names[decl.Name] = true
	}
	inLoop, other := make(map[string]bool), make(map[string]bool)
	loops := make(map[readLoopKey]bool)
	for _, file := range files {
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			if ident, ok := n.(*ast.Ident); ok && names[ident.Name] {
				if _, declared := decls[ident]; !declared {
					if readLoopUse(stack[len(stack)-1]) && insideReadLoop(stack, ident.Name, loops) {
						inLoop[ident.Name] = true
					} else {
						other[ident.Name] = true
					}
				}
			}
			stack = append(stack, n)
			return true
		})
	}
	only := make(map[string]bool, len(inLoop))
	for name := range inLoop {
		only[name] = !other[name]
	}
	return only
}

// readLoopUse reports whether the parent of a use of a constant lets it step
// a cursor (+=, +), go to a call or end the reads on a short page. A
// constant can only be the value added or an argument: a variable of its name
// is caught as another use where it is declared.
func readLoopUse(parent ast.Node) bool {
	switch p := parent.(type) {
	case *ast.AssignStmt:
		return p.Tok == token.ADD_ASSIGN
	case *ast.CallExpr:
		return true
	case *ast.BinaryExpr:
		return p.Op == token.ADD || shortPage(p, "")
	}
	return false
}

type readLoopKey struct {
	loop *ast.ForStmt
	name string
}

// insideReadLoop reports whether a for loop of the function holding the top
// of stack reads in pages of the constant name.
func insideReadLoop(stack []ast.Node, name string, loops map[readLoopKey]bool) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		switch n := stack[i].(type) {
		case *ast.FuncLit:
			return false
		case *ast.ForStmt:
			key := readLoopKey{loop: n, name: name}
			read, seen := loops[key]
			if !seen {
				read = readsInPages(n, name)
				loops[key] = read
			}
			if read {
				return true
			}
		}
	}
	return false
}

// readsInPages reports whether loop, outside its function literals, moves a
// cursor by name, stops on a page shorter than name, or passes name to a call
// together with a variable the loop assigns.
func readsInPages(loop *ast.ForStmt, name string) bool {
	assigned := make(map[string]bool)
	var calls []*ast.CallExpr
	found := false
	ast.Inspect(loop, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			found = found || cursorStep(n, name)
			if n.Tok == token.ASSIGN {
				for _, lhs := range n.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						assigned[ident.Name] = true
					}
				}
			}
		case *ast.BinaryExpr:
			found = found || shortPage(n, name)
		case *ast.CallExpr:
			calls = append(calls, n)
		}
		return true
	})
	if found {
		return true
	}
	for _, call := range calls {
		if passesWithCursor(call, name, assigned) {
			return true
		}
	}
	return false
}

// cursorStep reports offset += name, offset = offset + name or offset = name + offset.
// The operator of the sum is left to readLoopUse: name under any other
// operator is another use, which keeps the constant a contract anyway.
func cursorStep(assign *ast.AssignStmt, name string) bool {
	if assign.Tok == token.ADD_ASSIGN {
		return isName(assign.Rhs[0], name)
	}
	cursor, ok := assign.Lhs[0].(*ast.Ident)
	sum, isSum := assign.Rhs[0].(*ast.BinaryExpr)
	if !ok || !isSum {
		return false
	}
	return isName(sum.X, cursor.Name) && isName(sum.Y, name) || isName(sum.X, name) && isName(sum.Y, cursor.Name)
}

// shortPage reports len(rows) < name or name > len(rows); an empty name
// takes any operand in its place.
func shortPage(cmp *ast.BinaryExpr, name string) bool {
	return cmp.Op == token.LSS && lenCall(cmp.X) && (name == "" || isName(cmp.Y, name)) ||
		cmp.Op == token.GTR && lenCall(cmp.Y) && (name == "" || isName(cmp.X, name))
}

// passesWithCursor reports a call that takes name and a variable of assigned.
func passesWithCursor(call *ast.CallExpr, name string, assigned map[string]bool) bool {
	page, cursor := false, false
	for _, arg := range call.Args {
		ident, ok := arg.(*ast.Ident)
		if !ok {
			continue
		}
		page = page || ident.Name == name
		cursor = cursor || assigned[ident.Name]
	}
	return page && cursor
}

func isName(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

func lenCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	fun, ok := call.Fun.(*ast.Ident)
	return ok && fun.Name == "len"
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
