package frontendrules

import (
	"go/ast"
	"go/constant"
	"go/token"
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

// UseProjectFiles collects numeric constants from production Go files.
func (r *TSConstantCopiesGoConstantRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	for _, ctx := range files {
		if !patternkit.ProductionGoFile(ctx) || ctx.IsGenerated() || strings.Contains(ctx.RelPath, "generated") {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if len(valueSpec.Values) != len(valueSpec.Names) {
					continue
				}
				for i, name := range valueSpec.Names {
					if value, ok := goNumericValue(valueSpec.Values[i]); ok && !smallBusinessConstant(value) {
						r.goConstants = append(r.goConstants, goNumericConstant{name: name.Name, value: value})
					}
				}
			}
		}
	}
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
