package deadcode

import (
	"errors"
	"go/ast"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
// Родилось из ревью projectD 2026-08: в internal/config накопилась 51
// экспортированная константа и кластер экспортированных функций, на которые не
// ссылался никто, кроме их собственных тестов. Per-file правило unused-symbol
// их не видело — символы экспортированы, а границу модуля файл-за-файлом не
// проверить.
//
// Символ считается живым, если на него есть хотя бы одна ссылка в
// production-коде — в своём пакете или в любом другом. Ссылки только из
// _test.go файлов своего пакета не спасают: код, нужный лишь им, переезжает в
// _test.go, и сообщение это называет отдельно. Тесты других пакетов чужой
// _test.go импортировать не могут: экспорт, который они зовут, — единственное
// место для такого помощника, и он жив.
//
// Методы не проверяются: они могут закрывать интерфейсы. Интерфейсные типы —
// зона orphaned-interface. Пакет, чьи файлы импортируют testing, существует для
// тестов, и его экспорт, нужный только тестам, — его назначение.
//
// A main package cannot be imported either, and its exports are judged the
// same way.
//
// Outside internal/ an export may serve another module, so only an
// initializer (Init*, Setup*, Configure*, Register*) that tests call and
// production code does not is reported: production runs without it, and what
// it would have set up answers as if it had.
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
	object   types.Object
	kind     string
	testUses int
	// otherTestUses counts the references from the tests of other
	// directories, which reach the symbol through an import of its package.
	otherTestUses int
	// initializer marks a candidate outside internal/: reported only when
	// tests, and nothing else, call it.
	initializer bool
	// mainPackage marks a candidate of a main package.
	mainPackage bool
}

// AnalyzeGoProject collects the exported symbols the analyzed files of
// internal packages declare and counts their references across every loaded
// package. A package outside the analyzed files (a path argument, an exclude
// pattern) still counts as a user, but its own symbols are not judged: they
// have no file to report into.
func (r *UnusedInternalExportRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unused internal export: nil Go project context")
	}

	byFile := make(map[*core.FileContext][]*exportUsage)
	candidates := make(map[types.Object]*exportUsage)
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			return nil, errors.New("unused internal export: package has no typed syntax")
		}
		// A package whose own files import "testing" exists for tests:
		// production code cannot use it, so tests are its intended callers.
		if _, testSupport := pkgCtx.Package.Imports["testing"]; testSupport {
			continue
		}
		// Nothing imports a main package either: its exports serve the
		// package alone, like those of an internal one.
		mainPackage := pkgCtx.Package.Name == "main"
		internal := isInternalPackage(pkgCtx.Package.PkgPath) || mainPackage
		for _, fileCtx := range pkgCtx.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			for _, usage := range exportedDeclarations(fileCtx.GoAST, pkgCtx.Package.TypesInfo) {
				if !internal {
					if usage.kind != "function" || !isInitializerName(usage.object.Name()) ||
						isTestSupport(pkgCtx.Package.Name, usage.object.Name()) {
						continue
					}
					usage.initializer = true
				}
				usage.mainPackage = mainPackage
				candidates[usage.object] = usage
				byFile[fileCtx] = append(byFile[fileCtx], usage)
			}
		}
	}

	own := make(ownDeclarations)
	uses := make(map[types.Object]int, len(candidates))
	for obj := range candidates {
		uses[obj] = 0
	}
	for _, pkgCtx := range ctx.Packages {
		own.addPackage(pkgCtx.Package.Syntax, pkgCtx.Package.TypesInfo)
	}
	for _, pkgCtx := range ctx.Packages {
		countOutsideUses(pkgCtx.Package.TypesInfo, own, uses)
	}

	// Тестовые файлы не входят в типизированную загрузку (Tests: false), поэтому
	// test-only использование считается по синтаксису: совпадение имени в
	// _test.go достаточно, чтобы отличить «мёртвый совсем» от «нужен только тестам»
	countTestIdentUses(ctx, candidates)

	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, _ *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, usage := range byFile[fileCtx] {
			if uses[usage.object] > 0 || usage.otherTestUses > 0 || (usage.initializer && usage.testUses == 0) {
				continue
			}
			violations = append(violations, r.violationFor(ctx, usage))
		}
		return violations
	})
}

// exportedDeclarations returns the exported package-level objects a file
// declares, in source order, so findings on one line keep a stable order.
func exportedDeclarations(file *ast.File, info *types.Info) []*exportUsage {
	var declared []*exportUsage
	add := func(name *ast.Ident) {
		obj := info.Defs[name]
		if obj == nil || !obj.Exported() || obj.Parent() != obj.Pkg().Scope() {
			return
		}
		if kind, ok := exportKind(obj); ok {
			declared = append(declared, &exportUsage{object: obj, kind: kind})
		}
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				add(d.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					add(s.Name)
				case *ast.ValueSpec:
					for _, name := range s.Names {
						add(name)
					}
				}
			}
		}
	}
	return declared
}

// violationFor renders the finding at the symbol declaration.
func (r *UnusedInternalExportRule) violationFor(ctx *core.GoProjectContext, usage *exportUsage) *core.Violation {
	pos := ctx.FileSet.Position(usage.object.Pos())
	// cmd/glint maps the absolute path to the project-relative one.
	rel := pos.Filename

	name := usage.object.Name()
	message := "Exported " + usage.kind + " '" + name + "' in internal package is never used — the internal/ boundary makes it dead code"
	suggestion := "Remove the " + usage.kind + " — internal/ packages cannot be imported from outside the module"
	if usage.mainPackage {
		message = "Exported " + usage.kind + " '" + name + "' in a main package is never used — nothing can import a main package"
		suggestion = "Remove the " + usage.kind + ", or use it where it was meant to take effect"
	}
	if usage.testUses > 0 {
		where := "internal package"
		if usage.mainPackage {
			where = "main package"
		}
		message = "Exported " + usage.kind + " '" + name + "' in " + where + " is used only by tests — production code never touches it"
		suggestion = "Remove the " + usage.kind + " together with its tests, or use it from production code"
	}
	if usage.initializer {
		message = "Initializer '" + name + "' is called only by tests — production runs without what it sets up"
		suggestion = "Call it on the production start path, or remove it with the state it initializes"
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
		imported := importedPackages(file.GoAST)
		dir := filepath.Dir(file.Path)
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok {
					for _, usage := range byName[sel.Sel.Name] {
						if usage.importedAs(imported, pkg.Name) && declaredDir(ctx, usage) != dir {
							usage.otherTestUses++
						}
					}
				}
			}
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

// importedPackages maps the import paths of a file to the names it refers to
// them by: the explicit name, or "" for the package's own name.
func importedPackages(file *ast.File) map[string]string {
	out := make(map[string]string, len(file.Imports))
	for _, spec := range file.Imports {
		// The parser accepted the literal, and import paths hold no escapes.
		path := strings.Trim(spec.Path.Value, "`\"")
		name := ""
		if spec.Name != nil {
			name = spec.Name.Name
		}
		out[path] = name
	}
	return out
}

// importedAs reports a file that imports the symbol's package under a name.
func (u *exportUsage) importedAs(imported map[string]string, name string) bool {
	pkg := u.object.Pkg()
	local, ok := imported[pkg.Path()]
	if !ok {
		return false
	}
	if local == "" {
		local = pkg.Name()
	}
	return local == name
}

// declaredDir returns the directory of the file that declares a symbol.
func declaredDir(ctx *core.GoProjectContext, usage *exportUsage) string {
	return filepath.Dir(ctx.FileSet.Position(usage.object.Pos()).Filename)
}

// initializerVerbs lead the names of functions that set a package up.
var initializerVerbs = []string{"Init", "Initialize", "Setup", "Configure", "Register"}

// isInitializerName reports InitErrorConfig, SetupLogging, RegisterHandlers.
func isInitializerName(name string) bool {
	for _, verb := range initializerVerbs {
		if helpers.HasLeadingWord(name, verb) {
			return true
		}
	}
	return false
}

// isTestSupport reports a function tests are its only intended callers of:
// in a test-support package (testing, testutil, mocks, fixtures) or named for
// tests (SetupTestConfig, RegisterMocks).
func isTestSupport(pkgName, name string) bool {
	lowerPkg := strings.ToLower(pkgName)
	if helpers.IsTestSupportPackage(pkgName) || strings.HasSuffix(lowerPkg, "mocks") || strings.HasSuffix(lowerPkg, "fixtures") {
		return true
	}
	for _, word := range []string{"Test", "Mock", "Fake", "Fixture", "Stub"} {
		if strings.Contains(name, word) {
			return true
		}
	}
	return false
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
