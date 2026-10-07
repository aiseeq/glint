package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"maps"
	"path/filepath"
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
//
// Not reported: a filter or options struct — named …Filter, …Options, …Opts,
// …Params or …Query, or with only optional (pointer, slice, map) fields — whose
// literals set different fields: each call states what it asks for and leaves
// the rest unset on purpose, so a new field is missing nowhere by accident.
type ScatteredConstructionRule struct {
	*rules.BaseRule
	maxSites int
}

type constructionSite struct {
	fileCtx *core.FileContext
	line    int
	funcN   string
	// fields are the keys the literal sets, sorted and joined.
	fields string
	// optional: the type checker sees a struct whose fields are all optional.
	optional bool
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
	helperDir := map[string]bool{} // fixtures of a test-helper package are test code
	for _, fileCtx := range ctx.Files {
		if fileCtx == nil || !fileCtx.IsGoFile() || fileCtx.GoAST == nil || fileCtx.IsTestFile() {
			continue
		}
		dir := filepath.Dir(fileCtx.Path)
		helper, seen := helperDir[dir]
		if !seen {
			var err error
			if helper, err = core.IsTestHelperDir(dir); err != nil {
				return nil, fmt.Errorf("%s: %w", r.Name(), err)
			}
			helperDir[dir] = helper
		}
		if !helper {
			files = append(files, fileCtx)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].RelPath < files[j].RelPath })

	infos := map[*core.FileContext]*types.Info{}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		for _, fileCtx := range pkg.Files {
			infos[fileCtx] = pkg.Package.TypesInfo
		}
	}
	constructions := make(map[string][]constructionSite)
	for _, fileCtx := range files {
		collectConstructions(fileCtx, infos[fileCtx], constructions)
	}
	return r.reportViolations(constructions), nil
}

func collectConstructions(ctx *core.FileContext, info *types.Info, constructions map[string][]constructionSite) {
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
			fileCtx:  ctx,
			line:     ctx.LineFor(lit),
			funcN:    currentFunc,
			fields:   literalKeys(lit),
			optional: info != nil && allFieldsOptional(info.TypeOf(lit)),
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

		if len(uniqueFuncs) <= r.maxSites || perCallFilter(typeName, sites) {
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

// filterTypeSuffixes end the names of types that describe a request: what to
// select or how to run, each field set only by the calls that need it.
var filterTypeSuffixes = []string{"Filter", "Options", "Opts", "Params", "Query"}

// perCallFilter reports a filter or options type whose literals set different
// fields from one site to another.
func perCallFilter(typeName string, sites []constructionSite) bool {
	filter := false
	for _, suffix := range filterTypeSuffixes {
		if strings.HasSuffix(typeName, suffix) {
			filter = true
		}
	}
	fieldSets := map[string]bool{}
	optional := true
	for _, site := range sites {
		fieldSets[site.fields] = true
		optional = optional && site.optional
	}
	return (filter || optional) && len(fieldSets) > 1
}

// literalKeys returns the keys a keyed literal sets, sorted and joined.
func literalKeys(lit *ast.CompositeLit) string {
	var keys []string
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if ident, ok := kv.Key.(*ast.Ident); ok {
				keys = append(keys, ident.Name)
			}
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// allFieldsOptional reports a struct (or a pointer to one) whose every field
// may be left unset: a pointer, slice or map.
func allFieldsOptional(t types.Type) bool {
	if t == nil {
		return false
	}
	if pointer, ok := t.Underlying().(*types.Pointer); ok {
		t = pointer.Elem()
	}
	structure, ok := t.Underlying().(*types.Struct)
	if !ok || structure.NumFields() == 0 {
		return false
	}
	for i := 0; i < structure.NumFields(); i++ {
		switch structure.Field(i).Type().Underlying().(type) {
		case *types.Pointer, *types.Slice, *types.Map:
		default:
			return false
		}
	}
	return true
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
