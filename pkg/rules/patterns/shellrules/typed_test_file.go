package shellrules

import (
	"go/ast"
	"go/importer"
	"go/types"
	"maps"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"golang.org/x/tools/go/packages"
)

type projectSignalTypesKey struct{}

type signalSourcePackage struct {
	path    string
	name    string
	dir     string
	asts    []*ast.File
	root    []*core.FileContext
	checked *types.Package
}

// analyzeSignalProject runs a rule over the Go files of the run, each with
// the typed syntax of its package.
func analyzeSignalProject(project *core.GoProjectContext, goFile func(*core.FileContext, *signalPackage) []*core.Violation) ([]*core.Violation, error) {
	typed, err := core.Shared(project, projectSignalTypesKey{}, func() (map[*core.FileContext]*signalPackage, error) {
		return typeSignalFiles(project), nil
	})
	if err != nil {
		return nil, err
	}
	files := project.ReportFiles()
	if !project.HasReportScope() {
		files = project.Files
	}
	var findings []*core.Violation
	for _, file := range files {
		if file != nil && file.GoAST != nil {
			findings = append(findings, goFile(file, typed[file])...)
		}
	}
	return findings, nil
}

// typeSignalFiles gives each Go file of the project its package: the loaded
// one for a file of the build, for a test file its package typed with all its
// test files on the packages the core loaded.
func typeSignalFiles(project *core.GoProjectContext) map[*core.FileContext]*signalPackage {
	out := make(map[*core.FileContext]*signalPackage)
	run := &signalProject{}
	aliases := make(map[types.Object]*types.Func)
	for _, loaded := range project.Packages {
		if loaded == nil || loaded.Package == nil || loaded.Package.Types == nil {
			continue
		}
		pkg := run.add(newSignalPackage(loaded.Package.PkgPath, loaded.Package.TypesInfo, loaded.Package.Syntax...))
		pkg.packageAliases()
		maps.Copy(aliases, pkg.functions)
		for _, file := range loaded.Files {
			out[file] = pkg
		}
	}
	byDir, neededDirs := signalSourceGroups(project, aliases)
	imports := loadedSignalImports(project.Packages)
	groups := make([]*signalSourcePackage, 0, len(byDir))
	for _, group := range byDir {
		groups = append(groups, group)
	}
	// A package sorts before its external test package: "p" < "p_test".
	sort.Slice(groups, func(i, j int) bool {
		return signalSourceKey(groups[i].dir, groups[i].name) < signalSourceKey(groups[j].dir, groups[j].name)
	})
	for _, group := range groups {
		if len(group.root) == 0 {
			continue
		}
		under := byDir[signalSourceKey(group.dir, strings.TrimSuffix(group.name, "_test"))]
		path := group.path
		if path == "" && under != nil {
			path = under.path
		}
		pkg := run.add(newSignalPackage(path, nil, group.asts...))
		if neededDirs[group.dir] {
			pkg.info = typeSignalGroup(project, group, path, signalImporter{packages: imports, under: under})
		}
		for _, file := range group.root {
			out[file] = pkg
		}
	}
	return out
}

// signalSourceGroups groups the syntax of each directory by package name; a
// directory is needed when a test file names a signal function or one of the
// aliases of Kill and Tgkill the loaded packages declare.
func signalSourceGroups(project *core.GoProjectContext, aliases map[types.Object]*types.Func) (map[string]*signalSourcePackage, map[string]bool) {
	names := map[string]bool{"Kill": true, "Signal": true, "Tgkill": true, "CommandContext": true}
	for obj := range aliases {
		names[obj.Name()] = true
	}
	byDir := make(map[string]*signalSourcePackage)
	neededDirs := make(map[string]bool)
	for _, loaded := range project.Packages {
		if loaded == nil || loaded.Package == nil || loaded.Package.Types == nil {
			continue
		}
		pkg := loaded.Package
		for i, file := range pkg.Syntax {
			if i >= len(pkg.CompiledGoFiles) || file == nil {
				continue
			}
			dir := filepath.Clean(filepath.Dir(pkg.CompiledGoFiles[i]))
			key := signalSourceKey(dir, file.Name.Name)
			group := byDir[key]
			if group == nil {
				group = &signalSourcePackage{path: pkg.PkgPath, name: file.Name.Name, dir: dir}
				byDir[key] = group
			}
			group.asts = append(group.asts, file)
		}
	}
	for _, file := range project.Files {
		if file == nil || file.GoAST == nil || !file.IsTestFile() {
			continue
		}
		dir := filepath.Clean(filepath.Dir(file.Path))
		key := signalSourceKey(dir, file.GoAST.Name.Name)
		group := byDir[key]
		if group == nil {
			group = &signalSourcePackage{name: file.GoAST.Name.Name, dir: dir}
			byDir[key] = group
		}
		group.asts = append(group.asts, file.GoAST)
		group.root = append(group.root, file)
		if hasSignalRefs(file.GoAST, names) {
			neededDirs[dir] = true
		}
	}
	return byDir, neededDirs
}

func typeSignalGroup(project *core.GoProjectContext, group *signalSourcePackage, path string, importer signalImporter) *types.Info {
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	importer.std = cachedSignalImporter()
	// An error leaves partial types, which is what a test file gets; the
	// package is never nil.
	checked, _ := (&types.Config{Importer: importer, Error: func(error) {}}).Check(path, project.FileSet, group.asts, info) // ignored-error: safe — the first of the expected errors of imports outside the loaded graph; the partial types are what a test file gets
	group.checked = checked
	return info
}

func hasSignalRefs(file *ast.File, names map[string]bool) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && names[id.Name] {
			found = true
		}
		return !found
	})
	return found
}

// signalImporter imports a package the core loaded, else stdlib from export
// data, else an empty package. An external test package imports the package
// under test with its test files (under), so export_test.go is seen.
type signalImporter struct {
	packages map[string]*types.Package
	under    *signalSourcePackage
	std      types.Importer
}

func (i signalImporter) Import(path string) (*types.Package, error) {
	if i.under != nil && i.under.checked != nil && i.under.path == path {
		return i.under.checked, nil
	}
	// A dependency the load knows only by reference is incomplete, and
	// go/types drops an incomplete import with every name it declares.
	if pkg := i.packages[path]; pkg != nil && pkg.Complete() {
		return pkg, nil
	}
	signalStdPackages.Lock()
	pkg := signalStdPackages.values[path]
	if pkg == nil {
		var err error
		pkg, err = i.std.Import(path)
		if err == nil {
			signalStdPackages.values[path] = pkg
		}
	}
	signalStdPackages.Unlock()
	if pkg != nil {
		return pkg, nil
	}
	pkg = types.NewPackage(path, filepath.Base(path))
	pkg.MarkComplete()
	i.packages[path] = pkg
	return pkg, nil
}

func signalSourceKey(dir, name string) string { return dir + "\x00" + name }

func loadedSignalImports(loaded []*core.GoPackageContext) map[string]*types.Package {
	result := make(map[string]*types.Package)
	var add func(*packages.Package)
	add = func(pkg *packages.Package) {
		if pkg == nil || pkg.Types == nil || result[pkg.PkgPath] != nil {
			return
		}
		result[pkg.PkgPath] = pkg.Types
		for _, dependency := range pkg.Imports {
			add(dependency)
		}
	}
	for _, pkg := range loaded {
		if pkg != nil {
			add(pkg.Package)
		}
	}
	return result
}

var signalImporterOnce sync.Once
var signalImporterValue types.Importer
var signalStdPackages = struct {
	sync.Mutex
	values map[string]*types.Package
}{values: make(map[string]*types.Package)}

func cachedSignalImporter() types.Importer {
	signalImporterOnce.Do(func() { signalImporterValue = importer.Default() })
	return signalImporterValue
}
