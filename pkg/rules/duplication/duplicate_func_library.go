package duplication

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/toolcache"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/tools/go/packages"
)

func init() { rules.Register(NewDuplicateFuncOfLibraryRule()) }

// DuplicateFuncOfLibraryRule compares normalized function bodies with exported
// functions from directly required libraries of the same owner and with modules
// listed in library_modules. Function names do not affect a match.
type DuplicateFuncOfLibraryRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
	warningWriter   io.Writer
	loadCache       func(*toolcache.Cache, string) (libraryCacheEntry, bool, error)
	storeCache      func(*toolcache.Cache, string, libraryCacheEntry) error
	loadLibraryKeys func(string) (libraryCacheEntry, error)
}

// NewDuplicateFuncOfLibraryRule creates the library function duplication rule.
func NewDuplicateFuncOfLibraryRule() *DuplicateFuncOfLibraryRule {
	return &DuplicateFuncOfLibraryRule{
		loadCache: loadLibraryCache,
		storeCache: func(cache *toolcache.Cache, key string, entry libraryCacheEntry) error {
			return cache.Store(key, entry)
		},
		loadLibraryKeys: loadLibraryFunctionKeys,
		BaseRule: rules.NewBaseRule(
			"duplicate-func-of-library", "duplication",
			"Compares function bodies with exported functions from directly required libraries of the same owner and library_modules; function names do not matter",
			core.SeverityMedium,
		).DeclareSettings(rules.NewSettingSpec("library_modules", "string list", []string{}, "Module path prefixes treated as libraries.", []string{"example.com/shared"}))}
}

// AnalyzeFile is a no-op because this rule needs project module metadata.
func (r *DuplicateFuncOfLibraryRule) AnalyzeFile(*core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DuplicateFuncOfLibraryRule) RequiresSSA() bool { return false }

// Used by tests to assert disk-cache hits do not load library packages again.
var libraryPackageLoads atomic.Int64

type libraryFunction struct {
	Name       string `json:"name"`
	Package    string `json:"package"`
	ImportPath string `json:"import_path"`
}
type libraryCacheEntry struct {
	Keys map[string][]libraryFunction `json:"keys"`
}
type libraryMatch struct{ name, module, packageName, importPath string }
type goModule struct{ path, dir, goMod string }

func moduleIdentity(m goModule) string {
	if m.goMod != "" {
		return filepath.Clean(m.goMod)
	}
	return filepath.Join(m.dir, "go.mod")
}

// AnalyzeGoProject compares project functions with eligible library functions.
func (r *DuplicateFuncOfLibraryRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("duplicate func of library: nil Go project context")
	}
	allowed, _, err := r.GetStringListSetting("library_modules")
	if err != nil {
		return nil, err
	}
	modules, fileModules := projectModules(ctx)
	if len(modules) == 0 {
		return nil, nil
	}
	keysByModule := r.loadProjectLibraryKeys(modules, allowed)
	return rules.AnalyzeTypedRunFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		id := fileModules[filepath.Clean(file.Path)]
		return r.findLibraryDuplicates(ctx, file, info, keysByModule[id])
	})
}

func projectModules(ctx *core.GoProjectContext) (map[string]goModule, map[string]string) {
	modules := make(map[string]goModule)
	fileModules := make(map[string]string)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.Module == nil {
			continue
		}
		loaded := pkg.Package.Module
		m := goModule{path: loaded.Path, dir: loaded.Dir, goMod: loaded.GoMod}
		id := moduleIdentity(m)
		modules[id] = m
		for _, file := range pkg.Files {
			if file != nil {
				fileModules[filepath.Clean(file.Path)] = id
			}
		}
	}
	return modules, fileModules
}

func (r *DuplicateFuncOfLibraryRule) loadProjectLibraryKeys(modules map[string]goModule, allowed []string) map[string]map[string]libraryMatch {
	moduleIDs := slices.Sorted(maps.Keys(modules))
	keysByModule := make(map[string]map[string]libraryMatch, len(modules))
	cache := toolcache.New("duplicate-func-of-library")
	for _, id := range moduleIDs {
		keysByModule[id] = r.loadModuleLibraryKeys(modules[id], allowed, cache)
	}
	return keysByModule
}

func (r *DuplicateFuncOfLibraryRule) loadModuleLibraryKeys(m goModule, allowed []string, cache *toolcache.Cache) map[string]libraryMatch {
	keys := make(map[string]libraryMatch)
	deps, err := libraryDependencies(m.dir, m.path, allowed)
	if err != nil {
		r.warnLibraryInput(m.path, "read dependencies", err)
		return keys
	}
	for _, dep := range deps {
		r.mergeDependencyKeys(keys, m, dep, cache)
	}
	return keys
}

func (r *DuplicateFuncOfLibraryRule) mergeDependencyKeys(keys map[string]libraryMatch, project goModule, dep libraryDependency, cache *toolcache.Cache) {
	dir, digest, found, err := dependencySource(project.dir, dep)
	if err != nil {
		r.warnLibraryInput(dep.path, "locate source", err)
		return
	}
	if !found {
		return
	}
	availability, err := libraryDependencyAvailability(dir)
	if err != nil {
		r.warnLibraryInput(dep.path, "inspect library dependencies", err)
		return
	}
	digest = toolcache.Key([]byte(digest), []byte(availability))
	buildHash, err := duplicateLibraryBuildHash()
	cacheKey := ""
	if err != nil {
		r.warnLibraryInput(dep.path, "identify analyzer", err)
	} else {
		cacheKey = libraryCacheKey(dep, digest, buildHash)
	}
	var entry libraryCacheEntry
	var hit bool
	if cacheKey != "" {
		entry, hit, err = r.loadCache(cache, cacheKey)
		if err != nil {
			r.warnLibraryInput(dep.path, "read cache", err)
		}
	}
	if !hit {
		libraryPackageLoads.Add(1)
		entry, err = r.loadLibraryKeys(dir)
		if err != nil {
			r.warnLibraryInput(dep.path, "load source", err)
			return
		}
		if cacheKey != "" {
			if err := r.storeCache(cache, cacheKey, entry); err != nil {
				r.warnLibraryInput(dep.path, "write cache", err)
			}
		}
	}
	mergeImportableFunctions(keys, project, dep, entry)
}

func loadLibraryCache(cache *toolcache.Cache, key string) (libraryCacheEntry, bool, error) {
	var entry libraryCacheEntry
	hit, err := cache.Load(key, &entry)
	if err != nil {
		return libraryCacheEntry{}, false, fmt.Errorf("load library function cache: %w", err)
	}
	return entry, hit, nil
}

func mergeImportableFunctions(keys map[string]libraryMatch, project goModule, dep libraryDependency, entry libraryCacheEntry) {
	for body := range entry.Keys {
		for _, fn := range entry.Keys[body] {
			if !packageImportableFrom(project.path, fn.ImportPath) {
				continue
			}
			candidate := libraryMatch{name: fn.Name, module: dep.path, packageName: fn.Package, importPath: fn.ImportPath}
			if current, found := keys[body]; !found || libraryMatchLess(candidate, current) {
				keys[body] = candidate
			}
		}
	}
}

func (r *DuplicateFuncOfLibraryRule) findLibraryDuplicates(ctx *core.GoProjectContext, file *core.FileContext, info *types.Info, libraryKeys map[string]libraryMatch) []*core.Violation {
	if len(libraryKeys) == 0 {
		return nil
	}
	var out []*core.Violation
	for _, decl := range file.GoAST.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || !IsDuplicateFuncBodyCandidate(fd, info) {
			continue
		}
		n := newFunctionBlockNormalizer(info, fd)
		n.walk(fd.Body)
		if n.nodes < minimumDuplicateBodyNodes {
			continue
		}
		match, ok := libraryKeys[n.b.String()]
		if !ok {
			continue
		}
		line := ctx.FileSet.Position(fd.Pos()).Line
		if file.IsSuppressed(line, r.Name()) {
			continue
		}
		out = append(out, r.libraryViolation(file, fd, line, match))
	}
	return out
}

func (r *DuplicateFuncOfLibraryRule) libraryViolation(file *core.FileContext, fd *ast.FuncDecl, line int, match libraryMatch) *core.Violation {
	packageName := match.packageName
	for _, spec := range file.GoAST.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err == nil && importPath == match.importPath && spec.Name != nil {
			packageName = spec.Name.Name
			break
		}
	}
	v := r.CreateViolation(file.RelPath, line, fmt.Sprintf("Function %s duplicates function %s of library %s — call %s.%s instead", fd.Name.Name, match.name, match.module, packageName, match.name))
	v.WithCode(strings.TrimSpace(file.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Call %s.%s instead of keeping a copy", packageName, match.name))
	return v
}

func (r *DuplicateFuncOfLibraryRule) warnLibraryInput(path, action string, err error) {
	writer := r.warningWriter
	if writer == nil {
		writer = os.Stderr
	}
	_, _ = fmt.Fprintf(writer, "warning: duplicate-func-of-library could not %s %s: %v\n", action, path, err) // ignored-error: safe — a warning on stderr has nowhere left to be reported
}

func libraryMatchLess(a, b libraryMatch) bool {
	return a.importPath+"\x00"+a.name+"\x00"+a.module < b.importPath+"\x00"+b.name+"\x00"+b.module
}

type libraryDependency struct {
	path, version string
	dir           string
}

func libraryDependencies(moduleDir, projectModule string, extra []string) ([]libraryDependency, error) {
	goMod := filepath.Join(moduleDir, "go.mod")
	data, err := os.ReadFile(goMod)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", goMod, err)
	}
	mod, err := modfile.Parse(goMod, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", goMod, err)
	}
	var eligible []*modfile.Require
	for _, req := range mod.Require {
		if req.Indirect || sameModuleMajorBase(projectModule, req.Mod.Path) || (!sameOwner(projectModule, req.Mod.Path) && !hasModulePrefix(req.Mod.Path, extra)) {
			continue
		}
		eligible = append(eligible, req)
	}
	if len(eligible) == 0 {
		return nil, nil
	}
	replacements := make(map[string]string)
	for _, rep := range mod.Replace {
		if rep.New.Version == "" {
			replacements[rep.Old.Path] = resolveRelative(moduleDir, rep.New.Path)
		}
	}
	workspaceModules := make(map[string]string)
	if work, err := activeGoWork(moduleDir); err != nil {
		return nil, err
	} else if work != "" {
		workspace, err := workspaceModulePaths(work)
		if err != nil {
			return nil, err
		}
		maps.Copy(workspaceModules, workspace.modules)
		maps.Copy(replacements, workspace.replacements)
	}
	var out []libraryDependency
	for _, req := range eligible {
		dep := libraryDependency{path: req.Mod.Path, version: req.Mod.Version}
		if dir := replacements[req.Mod.Path]; dir != "" {
			dep.dir = dir
		} else if dir := workspaceModules[req.Mod.Path]; dir != "" {
			dep.dir = dir
		}
		out = append(out, dep)
	}
	return out, nil
}

func readProjectModule(root string) (string, error) {
	file := filepath.Join(root, "go.mod")
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", file, err)
	}
	mod, err := modfile.Parse(file, data, nil)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", file, err)
	}
	if mod.Module == nil {
		return "", errors.New("missing module path")
	}
	return mod.Module.Mod.Path, nil
}

func sameModuleMajorBase(a, b string) bool {
	return trimMajorSuffix(a) == trimMajorSuffix(b)
}

func trimMajorSuffix(path string) string {
	i := strings.LastIndexByte(path, '/')
	if i < 0 {
		return path
	}
	suffix := path[i+1:]
	if len(suffix) < 2 || suffix[0] != 'v' {
		return path
	}
	major, valid := moduleMajor(suffix[1:])
	if !valid || major < 2 {
		return path
	}
	return path[:i]
}

func moduleMajor(value string) (int, bool) {
	major := 0
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, false
		}
		if major < 2 {
			major = min(major*10+int(digit-'0'), 2)
		}
	}
	return major, value != ""
}

func sameOwner(project, dependency string) bool {
	a, b := strings.Split(strings.Trim(project, "/"), "/"), strings.Split(strings.Trim(dependency, "/"), "/")
	if project == "" || dependency == "" || len(a) == 0 || len(b) == 0 {
		return false
	}
	if a[0] == "github.com" || a[0] == "gitlab.com" || a[0] == "bitbucket.org" {
		return len(a) > 1 && len(b) > 1 && a[0] == b[0] && a[1] == b[1]
	}
	return a[0] == b[0]
}

func hasModulePrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		p = strings.TrimSuffix(p, "/")
		if p != "" && (path == p || strings.HasPrefix(path, p+"/")) {
			return true
		}
	}
	return false
}

func resolveRelative(base, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(base, path))
}

func activeGoWork(root string) (string, error) {
	cmd := exec.Command("go", "env", "GOWORK")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("query active workspace from %s: %w", root, err)
	}
	work := strings.TrimSpace(string(out))
	if work == "" || work == "off" {
		return "", nil
	}
	return work, nil
}

type workspacePaths struct {
	modules      map[string]string
	replacements map[string]string
}

func workspaceModulePaths(work string) (workspacePaths, error) {
	data, err := os.ReadFile(work)
	if err != nil {
		return workspacePaths{}, fmt.Errorf("read workspace %s: %w", work, err)
	}
	wf, err := modfile.ParseWork(work, data, nil)
	if err != nil {
		return workspacePaths{}, fmt.Errorf("parse workspace %s: %w", work, err)
	}
	paths := workspacePaths{modules: make(map[string]string), replacements: make(map[string]string)}
	for _, use := range wf.Use {
		dir := resolveRelative(filepath.Dir(work), use.Path)
		path, err := readProjectModule(dir)
		if err != nil {
			return workspacePaths{}, fmt.Errorf("read module in workspace use %s: %w", dir, err)
		}
		paths.modules[path] = dir
	}
	for _, rep := range wf.Replace {
		if rep.New.Version == "" {
			paths.replacements[rep.Old.Path] = resolveRelative(filepath.Dir(work), rep.New.Path)
		}
	}
	return paths, nil
}

// dependencySource distinguishes an absent module source from failures reading it.
func dependencySource(root string, dep libraryDependency) (string, string, bool, error) {
	if dep.dir != "" {
		found, err := sourceModuleExists(dep.dir)
		if err != nil || !found {
			return "", "", false, err
		}
		hash, err := core.HashGoModuleTree(dep.dir)
		if err != nil {
			return "", "", false, fmt.Errorf("hash local module tree %s: %w", dep.dir, err)
		}
		return dep.dir, "local:" + hash, true, nil
	}
	cache, err := moduleCacheDir(root)
	if err != nil {
		return "", "", false, err
	}
	escapedPath, err := module.EscapePath(dep.path)
	if err != nil {
		return "", "", false, fmt.Errorf("escape module path %q: %w", dep.path, err)
	}
	escapedVersion, err := module.EscapeVersion(dep.version)
	if err != nil {
		return "", "", false, fmt.Errorf("escape module version %q: %w", dep.version, err)
	}
	dir := filepath.Join(cache, escapedPath+"@"+escapedVersion)
	found, err := sourceModuleExists(dir)
	if err != nil || !found {
		return "", "", false, err
	}
	return dir, dep.version, true, nil
}

func libraryDependencyAvailability(dir string) (string, error) {
	goMod := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goMod)
	if err != nil {
		return "", fmt.Errorf("read library module file %s: %w", goMod, err)
	}
	mod, err := modfile.Parse(goMod, data, nil)
	if err != nil {
		return "", fmt.Errorf("parse library module file %s: %w", goMod, err)
	}
	slices.SortFunc(mod.Require, func(a, b *modfile.Require) int {
		if order := strings.Compare(a.Mod.Path, b.Mod.Path); order != 0 {
			return order
		}
		return strings.Compare(a.Mod.Version, b.Mod.Version)
	})
	var parts [][]byte
	cacheRoot := ""
	for _, req := range mod.Require {
		targetPath, targetVersion := req.Mod.Path, req.Mod.Version
		localTarget := ""
		if replacement := libraryReplacement(mod.Replace, req.Mod); replacement != nil {
			if replacement.New.Version == "" {
				localTarget = resolveRelative(dir, replacement.New.Path)
			} else {
				targetPath, targetVersion = replacement.New.Path, replacement.New.Version
			}
		}
		var target string
		if localTarget != "" {
			target = localTarget
		} else {
			if cacheRoot == "" {
				cacheRoot, err = moduleCacheDir(dir)
				if err != nil {
					return "", fmt.Errorf("locate module cache for library %s: %w", dir, err)
				}
			}
			escapedPath, err := module.EscapePath(targetPath)
			if err != nil {
				return "", fmt.Errorf("escape required module path %q: %w", targetPath, err)
			}
			escapedVersion, err := module.EscapeVersion(targetVersion)
			if err != nil {
				return "", fmt.Errorf("escape required module version %q: %w", targetVersion, err)
			}
			target = filepath.Join(cacheRoot, escapedPath+"@"+escapedVersion)
		}
		present, err := sourceModuleExists(target)
		if err != nil {
			return "", fmt.Errorf("check required module %s@%s: %w", req.Mod.Path, req.Mod.Version, err)
		}
		parts = append(parts, fmt.Appendf(nil, "%s@%s=>%s=%t", req.Mod.Path, req.Mod.Version, target, present))
	}
	return toolcache.Key(parts...), nil
}

func libraryReplacement(replacements []*modfile.Replace, required module.Version) *modfile.Replace {
	var generic *modfile.Replace
	for _, replacement := range replacements {
		if replacement.Old.Path != required.Path {
			continue
		}
		if replacement.Old.Version == required.Version {
			return replacement
		}
		if replacement.Old.Version == "" {
			generic = replacement
		}
	}
	return generic
}

func sourceModuleExists(dir string) (bool, error) {
	_, err := os.Stat(filepath.Join(dir, "go.mod"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat module source %s: %w", dir, err)
	}
	return true, nil
}

func moduleCacheDir(root string) (string, error) {
	if cache := os.Getenv("GOMODCACHE"); cache != "" {
		return cache, nil
	}
	cmd := exec.Command("go", "env", "GOMODCACHE")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("query module cache from %s: %w", root, err)
	}
	return strings.TrimSpace(string(out)), nil
}

var duplicateLibraryBuildHash = toolcache.ExecutableHash

func libraryCacheKey(dep libraryDependency, digest, buildHash string) string {
	return toolcache.Key([]byte(dep.path), []byte(dep.version), []byte(digest), []byte(buildHash))
}

func loadLibraryFunctionKeys(dir string) (libraryCacheEntry, error) {
	fset := token.NewFileSet()
	pkgs, err := packages.Load(&packages.Config{Mode: packages.LoadSyntax | packages.NeedModule, Dir: dir, Fset: fset, Tests: false}, "./...")
	if err != nil {
		return libraryCacheEntry{}, fmt.Errorf("load packages from %s: %w", dir, err)
	}

	entry := libraryCacheEntry{Keys: map[string][]libraryFunction{}}
	for _, pkg := range pkgs {
		if pkg == nil || pkg.Name == "main" || pkg.TypesInfo == nil || pkg.Types == nil || len(pkg.Errors) > 0 {
			continue
		}
		for _, file := range pkg.Syntax {
			if ast.IsGenerated(file) {
				continue
			}
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Name == nil || !fd.Name.IsExported() || !IsDuplicateFuncBodyCandidate(fd, pkg.TypesInfo) {
					continue
				}
				fn, ok := pkg.TypesInfo.Defs[fd.Name].(*types.Func)
				if !ok || fn == nil || fn.Signature().Recv() != nil {
					continue
				}
				n := newFunctionBlockNormalizer(pkg.TypesInfo, fd)
				n.walk(fd.Body)
				if n.nodes >= minimumDuplicateBodyNodes {
					entry.Keys[n.b.String()] = append(entry.Keys[n.b.String()], libraryFunction{Name: fd.Name.Name, Package: pkg.Name, ImportPath: pkg.PkgPath})
				}
			}
		}
	}
	return entry, nil
}
