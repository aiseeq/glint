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
// unexported constant its package only steps its own reads with is left out:
// it is not a contract of the API.
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
		steps := readStepsOnly(packages[pkg], decls)
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

// readStepsOnly names the constants declared at decls that the package uses
// only as the step of its own reads: it moves a cursor by it (offset +=
// page), and every other use passes it to a call or ends the reads on a short
// page (len(rows) < page). Any other use of the name — a comparison with a
// request value, an assignment, a return, a declaration that shadows it —
// keeps it a contract.
func readStepsOnly(files []*ast.File, decls map[*ast.Ident]float64) map[string]bool {
	names := make(map[string]bool, len(decls))
	for decl := range decls {
		names[decl.Name] = true
	}
	step, other := make(map[string]bool), make(map[string]bool)
	for _, file := range files {
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			if ident, ok := n.(*ast.Ident); ok && names[ident.Name] {
				if _, declared := decls[ident]; !declared {
					switch readStepUse(stack[len(stack)-1]) {
					case stepUse:
						step[ident.Name] = true
					case otherUse:
						other[ident.Name] = true
					}
				}
			}
			stack = append(stack, n)
			return true
		})
	}
	only := make(map[string]bool, len(step))
	for name := range step {
		only[name] = !other[name]
	}
	return only
}

type constantUse int

const (
	otherUse constantUse = iota
	stepUse
	readUse
)

// readStepUse classifies a use of a constant by its parent. A
// constant can only be the value of +=, an argument of a call, or an operand:
// a variable of its name is caught as another use where it is declared.
func readStepUse(parent ast.Node) constantUse {
	switch p := parent.(type) {
	case *ast.AssignStmt:
		if p.Tok == token.ADD_ASSIGN {
			return stepUse
		}
	case *ast.CallExpr:
		return readUse
	case *ast.BinaryExpr:
		// A page shorter than the step ends the reads: len(rows) < page, page > len(rows).
		if p.Op == token.LSS && lenCall(p.X) || p.Op == token.GTR && lenCall(p.Y) {
			return readUse
		}
	}
	return otherUse
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
