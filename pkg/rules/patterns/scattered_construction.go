package patterns

import (
	"fmt"
	"go/ast"
	"maps"
	"slices"
	"sort"
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
//
// The sites are collected over the whole project first, so every site of a
// scattered type is reported, not only those in files seen after the count
// passed the threshold.
type ScatteredConstructionRule struct {
	*rules.BaseRule
	maxSites int
}

type constructionSite struct {
	fileCtx *core.FileContext
	line    int
	funcN   string
}

// NewScatteredConstructionRule creates the rule
func NewScatteredConstructionRule() *ScatteredConstructionRule {
	return &ScatteredConstructionRule{
		BaseRule: rules.NewBaseRule(
			"scattered-construction",
			"patterns",
			"Detects struct types constructed in too many places — each site risks missing new fields",
			core.SeverityHigh,
		),
		maxSites: 2,
	}
}

// Configure allows setting rule options
func (r *ScatteredConstructionRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.maxSites = r.GetIntSetting("max_sites", 2)
	return nil
}

// AnalyzeFile is a no-op: the sites of a type are spread over the project.
func (r *ScatteredConstructionRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that syntax is enough for this rule.
func (r *ScatteredConstructionRule) RequiresSSA() bool { return false }

// AnalyzeGoProject collects the construction sites of every Go file of the
// project, then reports every site of each type built in too many functions.
func (r *ScatteredConstructionRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}

	files := make([]*core.FileContext, 0, len(ctx.Files))
	for _, fileCtx := range ctx.Files {
		if fileCtx == nil || !fileCtx.IsGoFile() || fileCtx.GoAST == nil || fileCtx.IsTestFile() {
			continue
		}
		files = append(files, fileCtx)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].RelPath < files[j].RelPath })

	constructions := make(map[string][]constructionSite)
	for _, fileCtx := range files {
		collectConstructions(fileCtx, constructions)
	}
	return r.reportViolations(constructions), nil
}

func collectConstructions(ctx *core.FileContext, constructions map[string][]constructionSite) {
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

		constructions[typeName] = append(constructions[typeName], constructionSite{
			fileCtx: ctx,
			line:    ctx.LineFor(lit),
			funcN:   currentFunc,
		})

		return true
	})
}

func (r *ScatteredConstructionRule) reportViolations(constructions map[string][]constructionSite) []*core.Violation {
	var violations []*core.Violation

	for _, typeName := range slices.Sorted(maps.Keys(constructions)) {
		sites := constructions[typeName]
		uniqueFuncs := make(map[string]bool)
		for _, s := range sites {
			uniqueFuncs[s.fileCtx.RelPath+":"+s.funcN] = true
		}

		if len(uniqueFuncs) <= r.maxSites {
			continue
		}

		for _, site := range sites {
			locations := formatOtherLocations(sites, site)

			violations = append(violations, r.CreateViolation(
				site.fileCtx.RelPath,
				site.line,
				fmt.Sprintf("%s constructed in %d places (%d functions) — adding a field risks silent omission",
					typeName, len(sites), len(uniqueFuncs)),
			).WithSuggestion(
				fmt.Sprintf("Extract a single conversion function and call it from all sites: %s", locations),
			))
		}
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
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
		if s.fileCtx == exclude.fileCtx && s.line == exclude.line {
			continue
		}
		others = append(others, fmt.Sprintf("%s:%d", s.fileCtx.RelPath, s.line))
	}
	if len(others) > 3 {
		return strings.Join(others[:3], ", ") + fmt.Sprintf(" +%d more", len(others)-3)
	}
	return strings.Join(others, ", ")
}
