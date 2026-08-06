package patterns

import (
	"errors"
	"go/ast"
	"go/types"
	"path/filepath"
	"sort"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnboundedSyncMapRule())
}

// UnboundedSyncMapRule detects package-level sync.Map variables that production
// code grows (Store/LoadOrStore) but never shrinks (Delete/CompareAndDelete/
// Clear). In a long-running process such a map is a slow leak: every new key
// stays forever.
//
// Родилось из ревью projectD 2026-08 (№22): пакетные sync.Map доменных расписаний,
// Crawl-delay и состояний robots.txt копили по записи на каждый встреченный
// домен. Демон работает месяцами — набор доменов только растёт, вытеснения не
// было ни в одном файле пакета.
//
// Не считаются: локальные sync.Map (живут не дольше функции), карты без
// записей и карты, у которых есть хоть одно не-методное использование
// (передача указателя наружу — судьбу записей отсюда не видно). Delete только
// в _test.go не спасает: production-рост он не ограничивает.
type UnboundedSyncMapRule struct {
	*rules.BaseRule
}

// NewUnboundedSyncMapRule creates the rule.
func NewUnboundedSyncMapRule() *UnboundedSyncMapRule {
	return &UnboundedSyncMapRule{
		BaseRule: rules.NewBaseRule(
			"unbounded-sync-map",
			"patterns",
			"Detects package-level sync.Map that only grows — no code path ever deletes entries, a slow leak in long-running processes",
			core.SeverityMedium,
		),
	}
}

// RequiresSSA reports that typed packages are enough — no SSA program needed.
func (r *UnboundedSyncMapRule) RequiresSSA() bool { return false }

// AnalyzeFile does nothing: the rule needs the whole package to see eviction.
func (r *UnboundedSyncMapRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// syncMapUsage aggregates how one package-level sync.Map is used.
type syncMapUsage struct {
	variable *types.Var
	methods  map[string]bool
	escaped  bool
}

// AnalyzeGoProject inspects every package for grow-only package-level sync.Maps.
func (r *UnboundedSyncMapRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unbounded sync map: nil Go project context")
	}

	var violations []*core.Violation
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.Types == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		violations = append(violations, r.analyzePackage(ctx, pkgCtx)...)
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

// analyzePackage finds the package-level sync.Map vars and classifies their uses.
func (r *UnboundedSyncMapRule) analyzePackage(ctx *core.GoProjectContext, pkgCtx *core.GoPackageContext) []*core.Violation {
	pkg := pkgCtx.Package
	scope := pkg.Types.Scope()

	usages := map[*types.Var]*syncMapUsage{}
	var ordered []*syncMapUsage // порядок scope.Names() — детерминированный вывод
	for _, name := range scope.Names() {
		variable, ok := scope.Lookup(name).(*types.Var)
		if !ok || !isSyncMapType(variable.Type()) {
			continue
		}
		usage := &syncMapUsage{variable: variable, methods: map[string]bool{}}
		usages[variable] = usage
		ordered = append(ordered, usage)
	}
	if len(usages) == 0 {
		return nil
	}

	// Каждое использование переменной обязано быть вызовом её метода; всё
	// прочее (взятие адреса, передача наружу) делает судьбу записей невидимой
	consumed := map[*ast.Ident]bool{}
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			variable, ok := pkg.TypesInfo.Uses[ident].(*types.Var)
			if !ok {
				return true
			}
			if usage, tracked := usages[variable]; tracked {
				usage.methods[selector.Sel.Name] = true
				consumed[ident] = true
			}
			return true
		})
	}
	for ident, obj := range pkg.TypesInfo.Uses {
		variable, ok := obj.(*types.Var)
		if !ok {
			continue
		}
		if usage, tracked := usages[variable]; tracked && !consumed[ident] {
			usage.escaped = true
		}
	}

	var violations []*core.Violation
	for _, usage := range ordered {
		if usage.escaped {
			continue
		}
		grows := usage.methods["Store"] || usage.methods["LoadOrStore"] || usage.methods["Swap"]
		shrinks := usage.methods["Delete"] || usage.methods["CompareAndDelete"] || usage.methods["Clear"]
		if !grows || shrinks {
			continue
		}
		violations = append(violations, r.violationFor(ctx, usage))
	}
	return violations
}

// violationFor renders the finding at the variable declaration.
func (r *UnboundedSyncMapRule) violationFor(ctx *core.GoProjectContext, usage *syncMapUsage) *core.Violation {
	pos := ctx.FileSet.Position(usage.variable.Pos())
	rel := pos.Filename
	if ctx.ProjectRoot != "" {
		if relPath, err := filepath.Rel(ctx.ProjectRoot, pos.Filename); err == nil {
			rel = relPath
		}
	}
	v := r.CreateViolation(rel, pos.Line,
		"Package-level sync.Map '"+usage.variable.Name()+"' only grows: entries are stored but no production code ever deletes them — a slow leak in long-running processes")
	v.WithSuggestion("Add eviction (TTL sweep with Delete, or Clear on rollover), or document why the key set is bounded and suppress")
	v.WithContext("variable", usage.variable.Name())
	return v
}

// isSyncMapType reports whether a type is sync.Map.
func isSyncMapType(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "Map"
}
