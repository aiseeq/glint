package deadcode

import (
	"errors"
	"go/ast"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnusedInternalExportRule())
}

// UnusedInternalExportRule detects exported package-level symbols in internal/
// packages that no production code references. internal/ packages cannot be
// imported from outside the module, so "no references in the module" means the
// symbol is dead — the export keyword only hides it from per-file dead-code
// checks.
//
// Родилось из ревью ipop 2026-08: в internal/config накопилась 51
// экспортированная константа и кластер экспортированных функций, на которые не
// ссылался никто, кроме их собственных тестов. Per-file правило unused-symbol
// их не видело — символы экспортированы, а границу модуля файл-за-файлом не
// проверить.
//
// Символ считается живым, если на него есть хотя бы одна ссылка в
// production-коде — в своём пакете или в любом другом. Ссылки только из
// _test.go файлов не спасают: код, нужный лишь тестам, — мёртвый груз
// production-сборки, и сообщение это называет отдельно.
//
// Методы не проверяются: они могут закрывать интерфейсы. Интерфейсные типы —
// зона orphaned-interface.
type UnusedInternalExportRule struct {
	*rules.BaseRule
}

// NewUnusedInternalExportRule creates the rule.
func NewUnusedInternalExportRule() *UnusedInternalExportRule {
	return &UnusedInternalExportRule{
		BaseRule: rules.NewBaseRule(
			"unused-internal-export",
			"deadcode",
			"Detects exported symbols in internal/ packages that nothing in the module uses — the module boundary makes them dead code",
			core.SeverityMedium,
		),
	}
}

// RequiresSSA reports that typed packages are enough — no SSA program needed.
func (r *UnusedInternalExportRule) RequiresSSA() bool { return false }

// AnalyzeFile does nothing: the rule needs every package to count references.
func (r *UnusedInternalExportRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// exportUsage tracks how a candidate symbol is referenced across the module.
type exportUsage struct {
	object         types.Object
	kind           string
	productionUses int
	testUses       int
}

// AnalyzeGoProject collects exported symbols of internal packages and counts
// their references across the whole module.
func (r *UnusedInternalExportRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unused internal export: nil Go project context")
	}
	return r.findDeadExports(ctx), nil
}

// findDeadExports does the actual work; a project without internal/ exports
// yields no violations.
func (r *UnusedInternalExportRule) findDeadExports(ctx *core.GoProjectContext) []*core.Violation {
	candidates := map[types.Object]*exportUsage{}
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.Types == nil {
			continue
		}
		if !isInternalPackage(pkgCtx.Package.PkgPath) {
			continue
		}
		scope := pkgCtx.Package.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if obj == nil || !obj.Exported() {
				continue
			}
			kind, ok := exportKind(obj)
			if !ok {
				continue
			}
			candidates[obj] = &exportUsage{object: obj, kind: kind}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		for _, obj := range pkgCtx.Package.TypesInfo.Uses {
			if usage, ok := candidates[obj]; ok {
				usage.productionUses++
			}
		}
	}

	// Тестовые файлы не входят в типизированную загрузку (Tests: false), поэтому
	// test-only использование считается по синтаксису: совпадение имени в
	// _test.go достаточно, чтобы отличить «мёртвый совсем» от «нужен только тестам»
	countTestIdentUses(ctx, candidates)

	var violations []*core.Violation
	for _, usage := range candidates {
		if usage.productionUses > 0 {
			continue
		}
		violations = append(violations, r.violationFor(ctx, usage))
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations
}

// violationFor renders the finding at the symbol declaration.
func (r *UnusedInternalExportRule) violationFor(ctx *core.GoProjectContext, usage *exportUsage) *core.Violation {
	pos := ctx.FileSet.Position(usage.object.Pos())
	rel := pos.Filename
	if ctx.ProjectRoot != "" {
		if relPath, err := filepath.Rel(ctx.ProjectRoot, pos.Filename); err == nil {
			rel = relPath
		}
	}

	name := usage.object.Name()
	message := "Exported " + usage.kind + " '" + name + "' in internal package is never used — the internal/ boundary makes it dead code"
	suggestion := "Remove the " + usage.kind + " — internal/ packages cannot be imported from outside the module"
	if usage.testUses > 0 {
		message = "Exported " + usage.kind + " '" + name + "' in internal package is used only by tests — production code never touches it"
		suggestion = "Remove the " + usage.kind + " together with its tests, or use it from production code"
	}

	v := r.CreateViolation(rel, pos.Line, message)
	v.WithSuggestion(suggestion)
	v.WithContext("symbol", name)
	v.WithContext("kind", usage.kind)
	v.WithContext("package", usage.object.Pkg().Path())
	return v
}

// countTestIdentUses counts, for every candidate, how often its name appears in
// the module's _test.go files. Имя без типов может совпасть с чужим — это лишь
// смягчит сообщение с «никогда» до «только тестами», сама находка не исчезнет.
func countTestIdentUses(ctx *core.GoProjectContext, candidates map[types.Object]*exportUsage) {
	byName := map[string][]*exportUsage{}
	for _, usage := range candidates {
		name := usage.object.Name()
		byName[name] = append(byName[name], usage)
	}

	for _, file := range ctx.Files {
		if file == nil || !file.IsTestFile() || file.GoAST == nil {
			continue
		}
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			for _, usage := range byName[ident.Name] {
				usage.testUses++
			}
			return true
		})
	}
}

// isInternalPackage reports whether a package path lies under an internal/
// directory — visible only within its module subtree.
func isInternalPackage(pkgPath string) bool {
	return strings.HasSuffix(pkgPath, "/internal") ||
		strings.Contains(pkgPath, "/internal/") ||
		pkgPath == "internal" ||
		strings.HasPrefix(pkgPath, "internal/")
}

// exportKind classifies package-level objects the rule checks. Methods are not
// package-scope objects, so they never reach here; interface types are skipped
// as the orphaned-interface rule's territory.
func exportKind(obj types.Object) (string, bool) {
	switch typed := obj.(type) {
	case *types.Const:
		return "constant", true
	case *types.Var:
		return "variable", true
	case *types.Func:
		return "function", true
	case *types.TypeName:
		if typed.IsAlias() {
			return "type", true
		}
		if _, ok := typed.Type().Underlying().(*types.Interface); ok {
			return "", false
		}
		return "type", true
	default:
		return "", false
	}
}
