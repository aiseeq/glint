package duplication

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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
// listed in library_modules. Function names do not affect a match. Besides a
// body equal token for token, a near copy counts (nearCopyThreshold): one with
// independent statements swapped, or a method that runs the body of a library
// function over its own element type. The TypeScript of the project is
// compared with the exported TypeScript functions those libraries ship.
type DuplicateFuncOfLibraryRule struct {
	*rules.BaseRule
	warningWriter   io.Writer
	loadCache       func(*toolcache.Cache, string) (libraryCacheEntry, bool, error)
	storeCache      func(*toolcache.Cache, string, libraryCacheEntry) error
	loadLibraryKeys func(string) (libraryCacheEntry, error)

	// mu guards the libraries of the root: AnalyzeGoProject loads them for
	// the Go files, UseProjectFiles reuses them for the TypeScript files.
	mu        sync.Mutex
	libraries map[string]*moduleLibrary
	tsFiles   map[string]*nearIndex
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
			"Compares function bodies with exported functions from required libraries and git HEADs of same-owner peer modules in peer_roots; function names do not matter",
			core.SeverityMedium,
		).DeclareSettings(
			rules.NewSettingSpec("library_modules", "string list", []string{}, "Module path prefixes treated as libraries.", []string{"example.com/shared"}),
			rules.NewSettingSpec("peer_roots", "string list", []string{}, "Glob patterns for sibling module directories checked at their git HEAD.", []string{"~/work/*"}),
		)}
}

// ReportsOn reports the files the rule names: Go and TypeScript sources.
func (r *DuplicateFuncOfLibraryRule) ReportsOn(ctx *core.FileContext) bool {
	return ctx.IsGoFile() || ctx.IsTypeScriptFile()
}

// ReadsNonGoFiles marks that AnalyzeFile reads the TypeScript files.
func (r *DuplicateFuncOfLibraryRule) ReadsNonGoFiles() {}

// ReadsOtherFiles reports that findings depend on the library sources.
func (r *DuplicateFuncOfLibraryRule) ReadsOtherFiles() bool { return true }

// CacheInputs adds the git HEADs of configured peer modules to project findings.
func (r *DuplicateFuncOfLibraryRule) CacheInputs(root string) (string, error) {
	roots, _, err := r.GetStringListSetting("peer_roots")
	if err != nil || len(roots) == 0 {
		return "", err
	}
	path, err := readProjectModule(root)
	if err != nil {
		return "", err
	}
	project := goModule{path: path, dir: root, goMod: filepath.Join(root, "go.mod")}
	peers, err := peerModules(project, roots)
	if err != nil {
		return "", err
	}
	var inputs []string
	for _, peer := range peers {
		sha, err := peerHeadSHA(peer.dir)
		if err != nil {
			return "", fmt.Errorf("read peer module %s cache input: %w", peer.path, err)
		}
		inputs = append(inputs, peer.path+"="+sha)
	}
	slices.Sort(inputs)
	return toolcache.Key([]byte(strings.Join(inputs, "\x00"))), nil
}

// ResetState forgets the libraries of the previous root.
func (r *DuplicateFuncOfLibraryRule) ResetState() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.libraries, r.tsFiles = nil, nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DuplicateFuncOfLibraryRule) RequiresSSA() bool { return false }

// Used by tests to assert disk-cache hits do not load library packages again.
var libraryPackageLoads atomic.Int64

type libraryFunction struct {
	Name       string   `json:"name"`
	Package    string   `json:"package"`
	ImportPath string   `json:"import_path"`
	Types      []string `json:"types,omitempty"`
}

// libraryNearFunction is a library function in the form of the near
// comparison; File is the source of a TypeScript function in the library.
type libraryNearFunction struct {
	libraryFunction
	Lang string   `json:"lang"`
	File string   `json:"file,omitempty"`
	Body nearBody `json:"body"`
}
type libraryCacheEntry struct {
	Keys   map[string][]libraryFunction `json:"keys"`
	Near   []libraryNearFunction        `json:"near,omitempty"`
	Inline []inlineFunction             `json:"inline,omitempty"`
}
type libraryMatch struct {
	name, module, packageName, importPath string
	peer                                  bool
	types                                 []string
}

// moduleLibrary is what the libraries of one project module offer: the exact
// bodies of their Go functions and the near forms of their Go and TypeScript
// functions.
type moduleLibrary struct {
	keys         map[string]libraryMatch
	goCandidates []*nearCandidate
	goNear       *nearIndex
	tsNear       []*nearCandidate
	inline       []inlineCandidate
}
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
	peerRoots, _, err := r.GetStringListSetting("peer_roots")
	if err != nil {
		return nil, err
	}
	libraries := r.loadProjectLibraryKeys(modules, allowed, false)
	if len(peerRoots) > 0 {
		for id, project := range modules {
			if lib := libraries[id]; lib != nil {
				r.mergePeerModules(lib, project, peerRoots)
			}
		}
	}
	return rules.AnalyzeTypedRunFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		id := fileModules[filepath.Clean(file.Path)]
		return r.findLibraryDuplicates(ctx, file, info, libraries[id], modules[id].path)
	})
}

func (r *DuplicateFuncOfLibraryRule) mergePeerModules(lib *moduleLibrary, project goModule, roots []string) {
	modules, err := peerModules(project, roots)
	if err != nil {
		r.warnLibraryInput(project.path, "find peer modules", err)
		return
	}
	cache := toolcache.New("duplicate-func-of-library")
	for _, peer := range modules {
		sha, err := peerHeadSHA(peer.dir)
		if err != nil {
			r.warnLibraryInput(peer.path, "read peer git HEAD", err)
			continue
		}
		buildHash, err := duplicateLibraryBuildHash()
		if err != nil {
			r.warnLibraryInput(peer.path, "identify analyzer", err)
			continue
		}
		key := toolcache.Key([]byte("peer-types-v1"), []byte(peer.path), []byte(sha), []byte(buildHash))
		entry, hit, err := r.loadCache(cache, key)
		if err != nil {
			r.warnLibraryInput(peer.path, "read cache", err)
		}
		if !hit {
			source, tempRoot, err := peerHeadSource(peer.dir, sha)
			if err != nil {
				r.warnLibraryInput(peer.path, "read peer git HEAD", err)
				continue
			}
			entry, err = loadPeerFunctionKeys(source)
			if removeErr := os.RemoveAll(tempRoot); removeErr != nil {
				r.warnLibraryInput(peer.path, "remove temporary peer source", removeErr)
			}
			if err != nil {
				r.warnLibraryInput(peer.path, "load source", err)
				continue
			}
			if err := r.storeCache(cache, key, entry); err != nil {
				r.warnLibraryInput(peer.path, "write cache", err)
			}
		}
		for body, functions := range entry.Keys {
			for _, fn := range functions {
				candidate := libraryMatch{name: fn.Name, module: peer.path, packageName: fn.Package, importPath: fn.ImportPath, peer: true, types: fn.Types}
				if current, ok := lib.keys[body]; !ok || libraryMatchLess(candidate, current) {
					lib.keys[body] = candidate
				}
			}
		}
		for i := range entry.Near {
			fn := &entry.Near[i]
			if fn.Lang == "go" {
				candidate := libraryMatch{name: fn.Name, module: peer.path, packageName: fn.Package, importPath: fn.ImportPath, peer: true, types: fn.Types}
				lib.goCandidates = append(lib.goCandidates, newNearCandidate(candidate, fn.Body))
			}
		}
	}
	lib.goNear = newNearIndex(lib.goCandidates, minGoNearCopyTokens)
}

func peerModules(project goModule, roots []string) ([]goModule, error) {
	required := make(map[string]bool)
	goModPath := filepath.Join(project.dir, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("read project module file: %w", err)
	}
	mod, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse project module file: %w", err)
	}
	for _, req := range mod.Require {
		required[req.Mod.Path] = true
	}
	seen := make(map[string]bool)
	var peers []goModule
	for _, pattern := range roots {
		pattern, err = expandPeerHome(pattern)
		if err != nil {
			return nil, err
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", pattern, err)
		}
		for _, dir := range matches {
			info, err := os.Stat(dir)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("stat peer root %s: %w", dir, err)
			}
			if !info.IsDir() {
				continue
			}
			path, err := readProjectModule(dir)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("read peer module in %s: %w", dir, err)
			}
			if path == project.path || required[path] || !sameOwner(project.path, path) {
				continue
			}
			peer := goModule{path: path, dir: dir, goMod: filepath.Join(dir, "go.mod")}
			id := moduleIdentity(peer)
			if !seen[id] && filepath.Clean(peer.goMod) != filepath.Clean(project.goMod) {
				seen[id] = true
				peers = append(peers, peer)
			}
		}
	}
	slices.SortFunc(peers, func(a, b goModule) int { return strings.Compare(a.path, b.path) })
	return peers, nil
}

func expandPeerHome(pattern string) (string, error) {
	if pattern != "~" && !strings.HasPrefix(pattern, "~/") {
		return pattern, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand home in peer root %q: %w", pattern, err)
	}
	return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(pattern, "~"), string(filepath.Separator))), nil
}

func peerHeadSHA(dir string) (string, error) {
	shaCmd := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	shaBytes, err := shaCmd.Output()
	if err != nil {
		return "", fmt.Errorf("module is not available in git HEAD: %w", err)
	}
	return strings.TrimSpace(string(shaBytes)), nil
}

func peerHeadSource(dir, sha string) (string, string, error) {
	repoCmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	repoBytes, err := repoCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("find peer repository root: %w", err)
	}
	repoRoot := strings.TrimSpace(string(repoBytes))
	prefixCmd := exec.Command("git", "-C", dir, "rev-parse", "--show-prefix")
	prefixBytes, err := prefixCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("find module path inside git repository: %w", err)
	}
	prefix := filepath.Clean(filepath.FromSlash(strings.TrimSpace(string(prefixBytes))))
	archiveArgs := []string{"-C", repoRoot, "archive", "--format=tar", sha}
	if prefix != "." {
		archiveArgs = append(archiveArgs, "--", ":(literal)"+filepath.ToSlash(prefix))
	}
	archiveCmd := exec.Command("git", archiveArgs...)
	archive, err := archiveCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("archive HEAD %s: %w", sha, err)
	}
	root, err := os.MkdirTemp("", "glint-peer-head-")
	if err != nil {
		return "", "", fmt.Errorf("create temporary peer source: %w", err)
	}
	if err := extractPeerArchive(root, archive); err != nil {
		if removeErr := os.RemoveAll(root); removeErr != nil {
			return "", "", errors.Join(err, fmt.Errorf("remove partial peer source %s: %w", root, removeErr))
		}
		return "", "", err
	}
	tempRoot := root
	if prefix != "." {
		root = filepath.Join(root, prefix)
	}
	return root, tempRoot, nil
}

func extractPeerArchive(root string, data []byte) error {
	reader := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read peer HEAD archive: %w", err)
		}
		name := filepath.Clean(filepath.FromSlash(header.Name))
		if name == "." || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe peer HEAD archive path %q", header.Name)
		}
		path := filepath.Join(root, name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, fs.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("create peer source directory %s: %w", path, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return fmt.Errorf("create peer source parent directory for %s: %w", path, err)
			}
			file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("create peer source file %s: %w", path, err)
			}
			_, copyErr := io.Copy(file, reader)
			closeErr := file.Close()
			if copyErr != nil {
				return fmt.Errorf("copy peer source file %s: %w", path, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close peer source file %s: %w", path, closeErr)
			}
		}
	}
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

// loadProjectLibraryKeys loads the libraries of the modules. AnalyzeGoProject
// loads them anew each run (reuse false) and keeps them for UseProjectFiles,
// which runs after it in the same run (reuse true).
func (r *DuplicateFuncOfLibraryRule) loadProjectLibraryKeys(modules map[string]goModule, allowed []string, reuse bool) map[string]*moduleLibrary {
	moduleIDs := slices.Sorted(maps.Keys(modules))
	out := make(map[string]*moduleLibrary, len(modules))
	cache := toolcache.New("duplicate-func-of-library")
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.libraries == nil {
		r.libraries = make(map[string]*moduleLibrary)
	}
	for _, id := range moduleIDs {
		lib, ok := r.libraries[id]
		if !ok || !reuse {
			lib = r.loadModuleLibraryKeys(modules[id], allowed, cache)
			r.libraries[id] = lib
		}
		out[id] = lib
	}
	return out
}

func (r *DuplicateFuncOfLibraryRule) loadModuleLibraryKeys(m goModule, allowed []string, cache *toolcache.Cache) *moduleLibrary {
	lib := &moduleLibrary{keys: make(map[string]libraryMatch)}
	deps, err := libraryDependencies(m.dir, m.path, allowed)
	if err != nil {
		r.warnLibraryInput(m.path, "read dependencies", err)
		return lib
	}
	for _, dep := range deps {
		r.mergeDependencyKeys(lib, m, dep, cache)
	}
	lib.goNear = newNearIndex(lib.goCandidates, minGoNearCopyTokens)
	return lib
}

func (r *DuplicateFuncOfLibraryRule) mergeDependencyKeys(lib *moduleLibrary, project goModule, dep libraryDependency, cache *toolcache.Cache) {
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
	mergeImportableFunctions(lib.keys, project, dep, entry)
	mergeNearFunctions(lib, project, dep, entry)
	for _, fn := range entry.Inline {
		if packageImportableFrom(project.path, fn.ImportPath) {
			lib.inline = append(lib.inline, inlineCandidate{inlineFunction: fn, module: dep.path})
		}
	}
}

// mergeNearFunctions adds the near forms of the entry: the Go functions the
// project can import and the TypeScript ones.
func mergeNearFunctions(lib *moduleLibrary, project goModule, dep libraryDependency, entry libraryCacheEntry) {
	for i := range entry.Near {
		fn := &entry.Near[i]
		match := libraryMatch{name: fn.Name, module: dep.path, packageName: fn.Package, importPath: fn.ImportPath}
		switch fn.Lang {
		case "go":
			if packageImportableFrom(project.path, fn.ImportPath) {
				lib.goCandidates = append(lib.goCandidates, newNearCandidate(match, fn.Body))
			}
		case "ts":
			lib.tsNear = append(lib.tsNear, newNearCandidate(match, fn.Body))
		}
	}
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

func (r *DuplicateFuncOfLibraryRule) findLibraryDuplicates(ctx *core.GoProjectContext, file *core.FileContext, info *types.Info, lib *moduleLibrary, projectPath string) []*core.Violation {
	if lib == nil || len(lib.keys) == 0 && lib.goNear.empty() && len(lib.inline) == 0 {
		return nil
	}
	var out []*core.Violation
	for _, decl := range file.GoAST.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		if !nearCopyCandidate(fd, info) {
			out = append(out, r.inlineDuplicates(ctx, file, info, fd, lib)...)
			continue
		}
		line := ctx.FileSet.Position(fd.Pos()).Line
		functionTypes := functionNamedTypes(fd, info, projectPath)
		functionTypeSet := stringSet(functionTypes)
		if match, ok := exactLibraryMatch(fd, info, lib.keys); ok {
			if !match.peer || sameStrings(functionTypeSet, stringSet(match.types)) {
				if !file.IsSuppressed(line, r.Name()) {
					out = append(out, r.libraryViolation(file, fd, line, match, 1, true))
				}
				continue
			}
		}
		candidate, score, _ := lib.goNear.bestFiltered(goNearBody(info, fd, false), func() nearBody { return goNearBody(info, fd, true) }, func(candidate *nearCandidate) bool {
			return !candidate.fn.peer || sameStrings(functionTypeSet, stringSet(candidate.fn.types))
		})
		if candidate == nil {
			out = append(out, r.inlineDuplicates(ctx, file, info, fd, lib)...)
			continue
		}
		if file.IsSuppressed(line, r.Name()) {
			continue
		}
		out = append(out, r.libraryViolation(file, fd, line, candidate.fn, score, false))
	}
	return out
}

func functionNamedTypes(fd *ast.FuncDecl, info *types.Info, modulePath string) []string {
	if fd == nil || info == nil || modulePath == "" {
		return nil
	}
	found := make(map[string]struct{})
	if fn, ok := info.Defs[fd.Name].(*types.Func); ok {
		collectNamedTypes(fn.Type(), modulePath, make(map[types.Type]bool), found)
	}
	ast.Inspect(fd, func(node ast.Node) bool {
		if node == nil {
			return true
		}
		if ident, ok := node.(*ast.Ident); ok {
			collectObjectNamedTypes(info.Uses[ident], modulePath, found)
			collectObjectNamedTypes(info.Defs[ident], modulePath, found)
		}
		if expr, ok := node.(ast.Expr); ok {
			if value, ok := info.Types[expr]; ok {
				collectNamedTypes(value.Type, modulePath, make(map[types.Type]bool), found)
			}
		}
		return true
	})
	return slices.Sorted(maps.Keys(found))
}

func collectObjectNamedTypes(object types.Object, modulePath string, found map[string]struct{}) {
	if object != nil {
		collectNamedTypes(object.Type(), modulePath, make(map[types.Type]bool), found)
	}
}

func collectNamedTypes(typ types.Type, modulePath string, seen map[types.Type]bool, found map[string]struct{}) {
	if typ == nil || seen[typ] {
		return
	}
	seen[typ] = true
	var object *types.TypeName
	switch t := typ.(type) {
	case *types.Named:
		object = t.Obj()
	case *types.Alias:
		object = t.Obj()
	}
	if object != nil && object.Pkg() != nil {
		path := object.Pkg().Path()
		identity := path + "." + object.Name()
		if path == modulePath {
			identity = "." + object.Name()
		} else if strings.HasPrefix(path, strings.TrimSuffix(modulePath, "/")+"/") {
			identity = strings.TrimPrefix(path, strings.TrimSuffix(modulePath, "/")) + "." + object.Name()
		}
		found[identity] = struct{}{}
	}
	for _, child := range typeChildren(typ) {
		collectNamedTypes(child, modulePath, seen, found)
	}
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}
func sameStrings(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for value := range a {
		if _, ok := b[value]; !ok {
			return false
		}
	}
	return true
}

func typeChildren(typ types.Type) []types.Type {
	var children []types.Type
	appendType := func(child types.Type) { children = append(children, child) }
	switch t := typ.(type) {
	case *types.Named:
		for arg := range t.TypeArgs().Types() {
			appendType(arg)
		}
	case *types.Alias:
		appendType(types.Unalias(t))
	case *types.Pointer:
		appendType(t.Elem())
	case *types.Slice:
		appendType(t.Elem())
	case *types.Array:
		appendType(t.Elem())
	case *types.Map:
		appendType(t.Key())
		appendType(t.Elem())
	case *types.Chan:
		appendType(t.Elem())
	case *types.Signature:
		if t.Recv() != nil {
			appendType(t.Recv().Type())
		}
		appendType(t.Params())
		appendType(t.Results())
	case *types.Tuple:
		for variable := range t.Variables() {
			appendType(variable.Type())
		}
	case *types.Struct:
		for field := range t.Fields() {
			appendType(field.Type())
		}
	case *types.Interface:
		t.Complete()
		for method := range t.Methods() {
			appendType(method.Type())
		}
		for embedded := range t.EmbeddedTypes() {
			appendType(embedded)
		}
	case *types.TypeParam:
		appendType(t.Constraint())
	case *types.Union:
		for term := range t.Terms() {
			appendType(term.Type())
		}
	}
	return children
}

// nearCopyCandidate admits what IsDuplicateFuncBodyCandidate admits and
// methods as well: a method may run the body of a library function over the
// fields of its receiver, with the parameters of the library function among
// them or among its own. A method that only calls a function of another
// package needs no check of its own: no library function is such a call.
func nearCopyCandidate(fd *ast.FuncDecl, info *types.Info) bool {
	if fd.Recv == nil {
		return IsDuplicateFuncBodyCandidate(fd, info)
	}
	if fd.Body == nil || fd.Name == nil || fd.Type == nil || fd.Type.Params == nil || info == nil {
		return false
	}
	return fd.Type.Params.NumFields() > 0 || len(fd.Recv.List) == 1 && len(fd.Recv.List[0].Names) == 1
}

func exactLibraryMatch(fd *ast.FuncDecl, info *types.Info, keys map[string]libraryMatch) (libraryMatch, bool) {
	if fd.Recv != nil || len(keys) == 0 {
		return libraryMatch{}, false
	}
	n := newFunctionBlockNormalizer(info, fd)
	n.walk(fd.Body)
	if n.nodes < minimumDuplicateBodyNodes {
		return libraryMatch{}, false
	}
	match, ok := keys[n.b.String()]
	return match, ok
}

func (r *DuplicateFuncOfLibraryRule) libraryViolation(file *core.FileContext, fd *ast.FuncDecl, line int, match libraryMatch, score float64, exact bool) *core.Violation {
	if match.peer {
		message := fmt.Sprintf("Function %s duplicates function %s in peer module %s", fd.Name.Name, match.name, match.module)
		if !exact {
			message = fmt.Sprintf("Function %s is a near copy (%d%% alike) of function %s in peer module %s", funcDisplayName(fd), int(score*100), match.name, match.module)
		}
		v := r.CreateViolation(file.RelPath, line, message)
		v.WithCode(strings.TrimSpace(file.GetLine(line)))
		v.WithSuggestion(fmt.Sprintf("Move the shared function %s into a common module", match.name))
		return v
	}
	packageName := match.packageName
	for _, spec := range file.GoAST.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err == nil && importPath == match.importPath && spec.Name != nil {
			packageName = spec.Name.Name
			break
		}
	}
	message := fmt.Sprintf("Function %s duplicates function %s of library %s — call %s.%s instead", fd.Name.Name, match.name, match.module, packageName, match.name)
	if !exact {
		message = fmt.Sprintf("Function %s is a near copy (%d%% alike) of function %s of library %s — call %s.%s instead", funcDisplayName(fd), int(score*100), match.name, match.module, packageName, match.name)
	}
	v := r.CreateViolation(file.RelPath, line, message)
	v.WithCode(strings.TrimSpace(file.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Call %s.%s instead of keeping a copy", packageName, match.name))
	return v
}

func (r *DuplicateFuncOfLibraryRule) warnLibraryInput(path, action string, err error) {
	writer := r.warningWriter
	if writer == nil {
		writer = os.Stderr
	}
	_, _ = fmt.Fprintf(writer, "warning: duplicate-func-of-library could not %s %s: %v\n", action, path, err)
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
		tsHash, err := hashLibraryTSFiles(dep.dir)
		if err != nil {
			return "", "", false, fmt.Errorf("hash local module tree %s: %w", dep.dir, err)
		}
		return dep.dir, "local:" + hash + ":" + tsHash, true, nil
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
	return loadFunctionKeys(dir, false)
}

func loadPeerFunctionKeys(dir string) (libraryCacheEntry, error) {
	return loadFunctionKeys(dir, true)
}

func loadFunctionKeys(dir string, includeUnexported bool) (libraryCacheEntry, error) {
	fset := token.NewFileSet()
	pkgs, err := packages.Load(&packages.Config{Mode: packages.LoadSyntax | packages.NeedModule, Dir: dir, Fset: fset, Tests: false, BuildFlags: []string{"-trimpath"}}, "./...")
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
				if ok && !includeUnexported {
					modulePath := pkg.PkgPath
					if pkg.Module != nil {
						modulePath = pkg.Module.Path
					}
					if fn, found := inlineLibraryFunction(fd, pkg.TypesInfo, pkg.PkgPath, pkg.Name, modulePath); found {
						entry.Inline = append(entry.Inline, fn)
					}
				}
				if !ok || fd.Name == nil || !includeUnexported && !fd.Name.IsExported() || !IsDuplicateFuncBodyCandidate(fd, pkg.TypesInfo) {
					continue
				}
				fn, ok := pkg.TypesInfo.Defs[fd.Name].(*types.Func)
				if !ok || fn == nil || fn.Signature().Recv() != nil {
					continue
				}
				n := newFunctionBlockNormalizer(pkg.TypesInfo, fd)
				n.walk(fd.Body)
				if n.nodes >= minimumDuplicateBodyNodes {
					found := libraryFunction{Name: fd.Name.Name, Package: pkg.Name, ImportPath: pkg.PkgPath}
					if includeUnexported {
						found.Types = functionNamedTypes(fd, pkg.TypesInfo, pkg.Module.Path)
					}
					entry.Keys[n.b.String()] = append(entry.Keys[n.b.String()], found)
					if body := goNearBody(pkg.TypesInfo, fd, true); len(body.Tokens) >= minGoNearCopyTokens {
						entry.Near = append(entry.Near, libraryNearFunction{libraryFunction: found, Lang: "go", Body: body})
					}
				}
			}
		}
	}
	tsFuncs, err := libraryTSFunctions(dir)
	if err != nil {
		return libraryCacheEntry{}, err
	}
	entry.Near = append(entry.Near, tsFuncs...)
	return entry, nil
}
