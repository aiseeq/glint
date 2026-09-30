package patterns

import (
	"errors"
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnboundedSyncMapRule())
}

// UnboundedSyncMapRule detects package-level sync.Map variables that production
// code grows (Store/LoadOrStore/Swap) but never shrinks (Delete/LoadAndDelete/
// CompareAndDelete/Clear). In a long-running process such a map is a slow leak: every new key
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

// AnalyzeGoProject inspects every package for grow-only package-level
// sync.Maps and reports each at its declaration.
func (r *UnboundedSyncMapRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unbounded sync map: nil Go project context")
	}

	growOnly := map[*types.Info][]*syncMapUsage{}
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.Types == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		growOnly[pkgCtx.Package.TypesInfo] = growOnlySyncMaps(pkgCtx)
	}

	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, usage := range growOnly[info] {
			pos := usage.variable.Pos()
			if pos < fileCtx.GoAST.FileStart || pos >= fileCtx.GoAST.FileEnd {
				continue
			}
			violations = append(violations, r.violationFor(fileCtx, usage))
		}
		return violations
	})
}

// growOnlySyncMaps finds the package-level sync.Map vars that are grown and
// never shrunk.
func growOnlySyncMaps(pkgCtx *core.GoPackageContext) []*syncMapUsage {
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

	var growing []*syncMapUsage
	for _, usage := range ordered {
		if usage.escaped || !usage.grows() || usage.shrinks() {
			continue
		}
		growing = append(growing, usage)
	}
	return growing
}

// grows reports whether some call can add a key: Store, LoadOrStore and Swap
// all insert a missing one. CompareAndSwap only replaces an existing value.
func (u *syncMapUsage) grows() bool {
	return u.methods["Store"] || u.methods["LoadOrStore"] || u.methods["Swap"]
}

// shrinks reports whether some call removes keys.
func (u *syncMapUsage) shrinks() bool {
	return u.methods["Delete"] || u.methods["LoadAndDelete"] || u.methods["CompareAndDelete"] || u.methods["Clear"]
}

// violationFor renders the finding at the variable declaration.
func (r *UnboundedSyncMapRule) violationFor(ctx *core.FileContext, usage *syncMapUsage) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, ctx.LineForPos(usage.variable.Pos()),
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
