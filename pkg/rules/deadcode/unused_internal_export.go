package deadcode

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
// Методы учитываются, если на них нет ссылок в модуле, и не нужны
// интерфейсам, соглашениям Go или вызовам из шаблонов. Пакет, чьи файлы импортируют testing, существует для
// тестов, и его экспорт, нужный только тестам, — его назначение.
//
// A main package cannot be imported either, and its exports are judged the
// same way.
//
// A module the project names in closed_modules is imported by no other
// module: every package of it is judged like an internal one.
//
// A name hand-written TypeScript imports from TypeScript generated from Go
// types (a file with the "Code generated ... DO NOT EDIT." marker) is in use:
// removing the Go type drops it from the next generation and breaks the
// frontend that imports it.
//
// Outside internal/ an export may serve another module, so only an
// initializer (Init*, Setup*, Configure*, Register*) that tests call and
// production code does not is reported: production runs without it, and what
// it would have set up answers as if it had.
type UnusedInternalExportRule struct {
	*rules.BaseRule
	closed map[string]bool
}

// NewUnusedInternalExportRule creates the rule.
func NewUnusedInternalExportRule() *UnusedInternalExportRule {
	return &UnusedInternalExportRule{
		BaseRule: rules.NewBaseRule(
			"unused-internal-export",
			"deadcode",
			"Detects exported symbols in internal/ packages, main packages and the packages of closed_modules that nothing in the module uses — the module boundary makes them dead code",
			core.SeverityMedium,
		),
	}
}

// Configure reads closed_modules, the module paths no other module imports.
func (r *UnusedInternalExportRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	closed, _, err := rules.NameSetSetting(settings, r.Name(), "closed_modules")
	if err != nil {
		return err
	}
	r.closed = closed
	return nil
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
	// closedModule marks a candidate of a package of a closed module.
	closedModule bool
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

	interfaces := moduleInterfaces(ctx)
	templateTypes := templateMethodTypes(ctx)
	templateNames, err := templateSelectorNames(ctx)
	if err != nil {
		return nil, err
	}
	byFile, candidates, err := r.collectGoCandidates(ctx, interfaces, promotedMethodOwners(ctx), templateTypes, templateNames)
	if err != nil {
		return nil, err
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
			if uses[usage.object] > 0 || usage.otherTestUses > 0 || (usage.kind == "method" && usage.testUses > 0) || (usage.initializer && usage.testUses == 0) || ctx.GeneratedTSImports[usage.object.Name()] {
				continue
			}
			violations = append(violations, r.violationFor(ctx, usage))
		}
		return violations
	})
}

func (r *UnusedInternalExportRule) collectGoCandidates(ctx *core.GoProjectContext, interfaces []interfaceType, owners map[*types.Func][]types.Type, templateTypes map[types.Object]bool, templateNames map[string]bool) (map[*core.FileContext][]*exportUsage, map[types.Object]*exportUsage, error) {
	byFile := make(map[*core.FileContext][]*exportUsage)
	candidates := make(map[types.Object]*exportUsage)
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			return nil, nil, errors.New("unused internal export: package has no typed syntax")
		}
		// A package whose own files import "testing" exists for tests:
		// production code cannot use it, so tests are its intended callers.
		if _, testSupport := pkgCtx.Package.Imports["testing"]; testSupport {
			continue
		}
		// Nothing imports a main package either: its exports serve the
		// package alone, like those of an internal one.
		mainPackage := pkgCtx.Package.Name == "main"
		closedModule := pkgCtx.Package.Module != nil && r.closed[pkgCtx.Package.Module.Path] && !isInternalPackage(pkgCtx.Package.PkgPath)
		internal := isInternalPackage(pkgCtx.Package.PkgPath) || mainPackage || closedModule
		for _, fileCtx := range pkgCtx.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			for _, usage := range exportedDeclarations(fileCtx.GoAST, pkgCtx.Package.TypesInfo) {
				include, err := r.includeGoCandidate(usage, pkgCtx, internal, closedModule, interfaces, owners, templateTypes, templateNames)
				if err != nil {
					return nil, nil, err
				}
				if !include {
					continue
				}
				if !internal {
					usage.initializer = true
				}
				usage.mainPackage = mainPackage
				usage.closedModule = closedModule && !mainPackage
				candidates[usage.object] = usage
				byFile[fileCtx] = append(byFile[fileCtx], usage)
			}
		}
	}
	return byFile, candidates, nil
}

func (r *UnusedInternalExportRule) includeGoCandidate(usage *exportUsage, pkgCtx *core.GoPackageContext, internal, closedModule bool, interfaces []interfaceType, owners map[*types.Func][]types.Type, templateTypes map[types.Object]bool, templateNames map[string]bool) (bool, error) {
	include, err := includeExportCandidate(usage, pkgCtx, internal, closedModule, interfaces)
	if err != nil || !include {
		return include, err
	}
	if usage.kind == "method" {
		method, ok := usage.object.(*types.Func)
		if !ok || templateTypes[receiverTypeObject(method)] || templateNames[method.Name()] {
			return false, nil
		}
		if promotedIntoInterface(method, owners[method.Origin()], interfaces) {
			return false, nil
		}
	}
	return true, nil
}

var templateFieldSelector = regexp.MustCompile(`\.([A-Za-z_][A-Za-z0-9_]*)`)

// templateSelectorNames collects field and method selectors used inside Go
// template actions in module template files and Go string literals.
func templateSelectorNames(ctx *core.GoProjectContext) (map[string]bool, error) {
	names := make(map[string]bool)
	addActions := func(source string) {
		for rest := source; ; {
			start := strings.Index(rest, "{{")
			if start < 0 {
				return
			}
			rest = rest[start+2:]
			end := strings.Index(rest, "}}")
			if end < 0 {
				return
			}
			for _, match := range templateFieldSelector.FindAllStringSubmatch(rest[:end], -1) {
				names[match[1]] = true
			}
			rest = rest[end+2:]
		}
	}
	for _, file := range ctx.Files {
		if file == nil || file.GoAST == nil {
			continue
		}
		ast.Inspect(file.GoAST, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err == nil && strings.Contains(value, "{{") {
				addActions(value)
			}
			return true
		})
	}
	if ctx.ProjectRoot == "" {
		return names, nil
	}
	err := filepath.WalkDir(ctx.ProjectRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != ctx.ProjectRoot {
				switch entry.Name() {
				case ".git", "node_modules", "vendor":
					return filepath.SkipDir
				}
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".html", ".tmpl", ".tpl", ".gohtml", ".gotmpl", ".txt":
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			addActions(string(content))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

func includeExportCandidate(usage *exportUsage, pkgCtx *core.GoPackageContext, internal, closedModule bool, interfaces []interfaceType) (bool, error) {
	if fn, ok := usage.object.(*types.Func); ok {
		if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
			if !isInternalPackage(pkgCtx.Package.PkgPath) && !closedModule || methodHasConventionalUse(fn) {
				return false, nil
			}
			required, err := methodRequiredByInterface(fn, interfaces)
			return !required, err
		}
	}
	if internal {
		return true, nil
	}
	return usage.kind == "function" && isInitializerName(usage.object.Name()) &&
		!isTestSupport(pkgCtx.Package.Name, usage.object.Name()), nil
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
			} else if obj := info.Defs[d.Name]; obj != nil && obj.Exported() {
				declared = append(declared, &exportUsage{object: obj, kind: "method"})
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

type interfaceType struct {
	named *types.Named
	iface *types.Interface
}

func collectInterfaces(pkg *types.Package, seen map[*types.Package]bool) []interfaceType {
	if pkg == nil || seen[pkg] {
		return nil
	}
	seen[pkg] = true
	var interfaces []interfaceType
	for _, name := range pkg.Scope().Names() {
		if typeName, ok := pkg.Scope().Lookup(name).(*types.TypeName); ok {
			if named, ok := typeName.Type().(*types.Named); ok {
				if iface, ok := named.Underlying().(*types.Interface); ok {
					interfaces = append(interfaces, interfaceType{named: named, iface: iface.Complete()})
				}
			}
		}
	}
	for _, imported := range pkg.Imports() {
		interfaces = append(interfaces, collectInterfaces(imported, seen)...)
	}
	return interfaces
}

func moduleInterfaces(ctx *core.GoProjectContext) []interfaceType {
	seen := make(map[*types.Package]bool)
	var interfaces []interfaceType
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx != nil && pkgCtx.Package != nil && pkgCtx.Package.Types != nil {
			interfaces = append(interfaces, collectInterfaces(pkgCtx.Package.Types, seen)...)
		}
	}
	return interfaces
}

func methodHasConventionalUse(method *types.Func) bool {
	switch method.Name() {
	case "String", "Error", "GoString", "Format", "MarshalJSON", "UnmarshalJSON",
		"MarshalText", "UnmarshalText", "MarshalYAML", "UnmarshalYAML", "Scan", "Value",
		"ServeHTTP", "Unwrap", "Is", "As", "Len", "Less", "Swap", "IsBoolFlag":
		return true
	default:
		return false
	}
}

func templateMethodTypes(ctx *core.GoProjectContext) map[types.Object]bool {
	typesInTemplates := make(map[types.Object]bool)
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		info := pkgCtx.Package.TypesInfo
		for _, file := range pkgCtx.Package.Syntax {
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (selector.Sel.Name != "Execute" && selector.Sel.Name != "ExecuteTemplate") {
					return true
				}
				var fn *types.Func
				if selection := info.Selections[selector]; selection != nil {
					fn, _ = selection.Obj().(*types.Func)
				}
				if fn == nil {
					fn, _ = info.Uses[selector.Sel].(*types.Func)
				}
				if fn == nil {
					return true
				}
				if fn.Pkg() == nil || (fn.Pkg().Path() != "html/template" && fn.Pkg().Path() != "text/template") {
					return true
				}
				dataIndex := 1
				if selector.Sel.Name == "ExecuteTemplate" {
					dataIndex = 2
				}
				if dataIndex >= len(call.Args) {
					return true
				}
				t := types.Unalias(info.TypeOf(call.Args[dataIndex]))
				if pointer, ok := t.(*types.Pointer); ok {
					t = types.Unalias(pointer.Elem())
				}
				if named, ok := t.(*types.Named); ok {
					typesInTemplates[named.Origin().Obj()] = true
				}
				return true
			})
		}
	}
	return typesInTemplates
}

func methodRequiredByInterface(method *types.Func, interfaces []interfaceType) (bool, error) {
	typeName, ok := receiverTypeObject(method).(*types.TypeName)
	if !ok {
		return false, nil
	}
	named, ok := typeName.Type().(*types.Named)
	if !ok {
		return false, nil
	}
	concrete := types.Type(named)
	if params := named.TypeParams(); params != nil && params.Len() > 0 {
		instantiated, err := instantiateTypeParams(named, params)
		if err != nil {
			return false, err
		}
		concrete = instantiated
	}
	for _, candidate := range interfaces {
		iface := candidate.iface
		if params := candidate.named.TypeParams(); params != nil && params.Len() > 0 {
			receiverParams := named.TypeParams()
			if receiverParams == nil || receiverParams.Len() != params.Len() {
				continue
			}
			instantiated, err := instantiateTypeParams(candidate.named, receiverParams)
			if err != nil {
				return false, err
			}
			iface, _ = instantiated.Underlying().(*types.Interface)
			if iface == nil {
				continue
			}
		}
		for ifaceMethod := range iface.Methods() {
			if ifaceMethod.Name() != method.Name() {
				continue
			}
			if types.Implements(concrete, iface) || types.Implements(types.NewPointer(concrete), iface) {
				return true, nil
			}
		}
	}
	return false, nil
}

// promotedMethodOwners maps a method to the module types that get it by
// embedding: such a type can satisfy an interface its embedded type alone
// does not, and the method is called through that interface.
func promotedMethodOwners(ctx *core.GoProjectContext) map[*types.Func][]types.Type {
	owners := make(map[*types.Func][]types.Type)
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.Types == nil {
			continue
		}
		scope := pkgCtx.Package.Types.Scope()
		for _, name := range scope.Names() {
			typeName, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || typeName.IsAlias() {
				continue
			}
			named, ok := typeName.Type().(*types.Named)
			if !ok || named.TypeParams().Len() > 0 || types.IsInterface(named) {
				continue
			}
			for _, owner := range []types.Type{named, types.NewPointer(named)} {
				for selection := range types.NewMethodSet(owner).Methods() {
					if fn, ok := selection.Obj().(*types.Func); ok && len(selection.Index()) > 1 {
						owners[fn.Origin()] = append(owners[fn.Origin()], owner)
					}
				}
			}
		}
	}
	return owners
}

// promotedIntoInterface reports a method promoted into a type that
// implements an interface naming it.
func promotedIntoInterface(method *types.Func, owners []types.Type, interfaces []interfaceType) bool {
	for _, candidate := range interfaces {
		if candidate.named.TypeParams().Len() > 0 || !helpers.InterfaceDeclaresMethod(candidate.iface, method.Name()) {
			continue
		}
		for _, owner := range owners {
			if types.Implements(owner, candidate.iface) {
				return true
			}
		}
	}
	return false
}

func instantiateTypeParams(named *types.Named, params *types.TypeParamList) (types.Type, error) {
	args := make([]types.Type, params.Len())
	for i := range args {
		args[i] = params.At(i)
	}
	return types.Instantiate(types.NewContext(), named, args, false)
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
	if usage.closedModule {
		message = "Exported " + usage.kind + " '" + name + "' of a closed module is never used — no other module imports it (closed_modules)"
		suggestion = "Remove the " + usage.kind + "; if another module does import this one, drop the module from closed_modules"
	}
	if usage.testUses > 0 {
		where := "internal package"
		switch {
		case usage.mainPackage:
			where = "main package"
		case usage.closedModule:
			where = "closed module"
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
				for _, usage := range byName[sel.Sel.Name] {
					if usage.kind == "method" {
						usage.testUses++
					}
				}
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
