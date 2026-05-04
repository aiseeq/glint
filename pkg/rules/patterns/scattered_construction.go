package patterns

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewScatteredConstructionRule())
}

// ScatteredConstructionRule detects struct types that are constructed via struct literals
// in too many different functions. Each construction site is a potential point of failure
// when a new field is added — the field will be silently missing in all but the updated sites.
//
// Principle: "One conversion function per type pair, not scattered literals"
type ScatteredConstructionRule struct {
	*rules.BaseRule
	constructions map[string][]constructionSite
	maxSites      int
}

type constructionSite struct {
	file  string
	line  int
	funcN string
}

func NewScatteredConstructionRule() *ScatteredConstructionRule {
	return &ScatteredConstructionRule{
		BaseRule: rules.NewBaseRule(
			"scattered-construction",
			"patterns",
			"Detects struct types constructed in too many places — each site risks missing new fields",
			core.SeverityHigh,
		),
		constructions: make(map[string][]constructionSite),
		maxSites:      2,
	}
}

func (r *ScatteredConstructionRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.maxSites = r.GetIntSetting("max_sites", 2)
	return nil
}

func (r *ScatteredConstructionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}
	if ctx.IsTestFile() {
		return nil
	}

	r.collectConstructions(ctx)
	return r.reportViolations(ctx)
}

func (r *ScatteredConstructionRule) collectConstructions(ctx *core.FileContext) {
	currentFunc := ""

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			currentFunc = fn.Name.Name
		case *ast.FuncLit:
			currentFunc = "(anonymous)"
		}

		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}

		typeName := resolveConstructedTypeName(lit.Type)
		if typeName == "" || !strings.Contains(typeName, ".") {
			return true
		}

		// Only struct literals with named fields (key:value), 3+ fields
		if len(lit.Elts) < 3 {
			return true
		}
		if _, isKV := lit.Elts[0].(*ast.KeyValueExpr); !isKV {
			return true
		}

		pos := ctx.GoFileSet.Position(lit.Pos())
		r.constructions[typeName] = append(r.constructions[typeName], constructionSite{
			file:  ctx.Path,
			line:  pos.Line,
			funcN: currentFunc,
		})

		return true
	})
}

func (r *ScatteredConstructionRule) reportViolations(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for typeName, sites := range r.constructions {
		uniqueFuncs := make(map[string]bool)
		for _, s := range sites {
			uniqueFuncs[s.file+":"+s.funcN] = true
		}

		if len(uniqueFuncs) <= r.maxSites {
			continue
		}

		for _, site := range sites {
			if site.file != ctx.Path {
				continue
			}

			locations := formatOtherLocations(sites, site)

			violations = append(violations, r.CreateViolation(
				ctx.Path,
				site.line,
				fmt.Sprintf("%s constructed in %d places (%d functions) — adding a field risks silent omission",
					typeName, len(sites), len(uniqueFuncs)),
			).WithSuggestion(
				fmt.Sprintf("Extract a single conversion function and call it from all sites: %s", locations),
			))
		}
	}

	return violations
}

func resolveConstructedTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name + "." + t.Sel.Name
		}
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return resolveConstructedTypeName(t.X)
	}
	return ""
}

func formatOtherLocations(sites []constructionSite, exclude constructionSite) string {
	var others []string
	for _, s := range sites {
		if s.file == exclude.file && s.line == exclude.line {
			continue
		}
		parts := strings.Split(s.file, "/")
		short := parts[len(parts)-1]
		others = append(others, fmt.Sprintf("%s:%d", short, s.line))
	}
	if len(others) > 3 {
		return strings.Join(others[:3], ", ") + fmt.Sprintf(" +%d more", len(others)-3)
	}
	return strings.Join(others, ", ")
}
