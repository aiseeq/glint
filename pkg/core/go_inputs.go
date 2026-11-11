package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/mod/modfile"
)

// goEnvKeys are the go env values that change what a typed load sees.
var goEnvKeys = []string{"GOVERSION", "GOOS", "GOARCH", "GOFLAGS", "CGO_ENABLED", "GOEXPERIMENT", "GOWORK", "GOAMD64", "GOARM", "GOARM64"}

// cgoSourceExts are the non-Go sources cgo compiles into a package.
var cgoSourceExts = map[string]bool{
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true, ".hh": true, ".hpp": true,
	".hxx": true, ".m": true, ".s": true, ".S": true, ".sx": true, ".f": true, ".F": true,
	".for": true, ".f90": true, ".syso": true, ".swig": true, ".swigcxx": true,
}

// goInputs memoizes the input hashes of the modules of one run: the roots of
// a module share them.
type goInputs struct {
	mu      sync.Mutex
	modules map[string]moduleInputs
}

type moduleInputs struct {
	hash      string
	cacheable bool
	err       error
}

// GoInputs identifies everything the typed load of root reads, and the SQL
// and template files under root, which project rules check code against: the
// analyzed Go, SQL and template files, every Go and cgo source and module
// file of the modules that own them and of their workspace, and the Go
// toolchain and build environment, and the names hand-written TypeScript
// imports from generated TypeScript (GeneratedTSImports).
// Modules come from the module cache by the versions go.sum pins, so they are
// covered by go.sum. cacheable is false when the load reads a local replace
// target that is not a Go module.
//
// The walk skips what the go command ignores (directories starting with . or
// _, testdata, nested modules) and node_modules, which holds no Go packages.
func (l *GoProjectLoader) GoInputs(root string, contexts []*FileContext, tolerate bool) (hash string, cacheable bool, err error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", false, fmt.Errorf("make Go project root absolute: %w", err)
	}
	var goFiles, analyzed []*FileContext
	for _, fileCtx := range contexts {
		if fileCtx == nil {
			continue
		}
		if fileCtx.IsGoFile() {
			goFiles = append(goFiles, fileCtx)
		}
		if fileCtx.IsGoFile() || strings.EqualFold(filepath.Ext(fileCtx.RelPath), ".sql") || fileCtx.IsTemplate() {
			analyzed = append(analyzed, fileCtx)
		}
	}
	moduleDirs, _, err := goModuleDirs(absRoot, goFiles, tolerate)
	if err != nil {
		return "", false, err
	}

	sum := sha256.New()
	writeHashLine(sum, "GOPACKAGESDRIVER=%s\n", os.Getenv("GOPACKAGESDRIVER"))
	for _, moduleDir := range moduleDirs {
		inputs := l.moduleInputs(moduleDir)
		if inputs.err != nil || !inputs.cacheable {
			return "", false, inputs.err
		}
		writeHashLine(sum, "module %s %s\n", moduleDir, inputs.hash)
	}
	relPaths := make([]string, 0, len(analyzed))
	for _, fileCtx := range analyzed {
		relPaths = append(relPaths, fileCtx.RelPath)
	}
	sort.Strings(relPaths)
	byPath := make(map[string]*FileContext, len(analyzed))
	for _, fileCtx := range analyzed {
		byPath[fileCtx.RelPath] = fileCtx
	}
	for _, relPath := range relPaths {
		content := sha256.Sum256(byPath[relPath].Content)
		writeHashLine(sum, "analyzed %s %x\n", relPath, content)
	}
	imports := slices.Sorted(maps.Keys(GeneratedTSImports(contexts)))
	writeHashLine(sum, "generated TS imports %q\n", imports)
	return hex.EncodeToString(sum.Sum(nil)), true, nil
}

func (l *GoProjectLoader) moduleInputs(moduleDir string) moduleInputs {
	l.inputs.mu.Lock()
	defer l.inputs.mu.Unlock()
	if l.inputs.modules == nil {
		l.inputs.modules = make(map[string]moduleInputs)
	}
	if inputs, ok := l.inputs.modules[moduleDir]; ok {
		return inputs
	}
	hash, cacheable, err := hashModuleInputs(moduleDir)
	inputs := moduleInputs{hash: hash, cacheable: cacheable, err: err}
	l.inputs.modules[moduleDir] = inputs
	return inputs
}

// hashModuleInputs hashes the go env of the module, its sources and those of
// the other modules of its workspace.
func hashModuleInputs(moduleDir string) (string, bool, error) {
	env, err := goEnv(moduleDir)
	if err != nil {
		return "", false, err
	}
	sum := sha256.New()
	for _, key := range goEnvKeys {
		writeHashLine(sum, "%s=%s\n", key, env[key])
	}
	dirs := []string{moduleDir}
	if work := env["GOWORK"]; work != "" && work != "off" {
		uses, localReplaces, err := workspaceModules(work)
		if err != nil {
			return "", false, err
		}
		for _, target := range localReplaces {
			cacheable, err := isLocalReplaceModule(target)
			if err != nil || !cacheable {
				return "", false, err
			}
		}
		if err := hashFile(sum, work); err != nil {
			return "", false, err
		}
		if err := hashOptionalFile(sum, work+".sum"); err != nil {
			return "", false, err
		}
		dirs = append(dirs, uses...)
		dirs = append(dirs, localReplaces...)
	}
	slices.Sort(dirs)
	dirs = slices.Compact(dirs)
	visited := make(map[string]struct{})
	for _, dir := range dirs {
		cacheable, err := hashModuleTree(sum, dir, visited)
		if err != nil || !cacheable {
			return "", false, err
		}
	}
	return hex.EncodeToString(sum.Sum(nil)), true, nil
}

func goEnv(dir string) (map[string]string, error) {
	cmd := exec.Command("go", append([]string{"env", "-json"}, goEnvKeys...)...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go env in %s: %w", dir, err)
	}
	env := make(map[string]string, len(goEnvKeys))
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, fmt.Errorf("decode go env in %s: %w", dir, err)
	}
	return env, nil
}

// workspaceModules returns the module directories and local replace targets
// a go.work makes the load read.
func workspaceModules(workFile string) ([]string, []string, error) {
	data, err := os.ReadFile(workFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", workFile, err)
	}
	work, err := modfile.ParseWork(workFile, data, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", workFile, err)
	}
	dirs := make([]string, 0, len(work.Use))
	localReplaces := make([]string, 0, len(work.Replace))
	for _, use := range work.Use {
		dir := use.Path
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(workFile), dir)
		}
		dirs = append(dirs, filepath.Clean(dir))
	}
	for _, replace := range work.Replace {
		if replace.New.Version != "" {
			continue
		}
		dir := replace.New.Path
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(workFile), dir)
		}
		localReplaces = append(localReplaces, filepath.Clean(dir))
	}
	return dirs, localReplaces, nil
}

// hashModuleTree hashes the sources and module files of the module rooted at
// dir, along with the modules reached through local replace directives.
func hashModuleTree(sum hash.Hash, dir string, visited map[string]struct{}) (bool, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return false, fmt.Errorf("make module directory absolute: %w", err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return false, fmt.Errorf("resolve module directory: %w", err)
	}
	dir = filepath.Clean(dir)
	if _, ok := visited[dir]; ok {
		return true, nil
	}
	visited[dir] = struct{}{}
	goMod := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goMod)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", goMod, err)
	}
	mod, err := modfile.Parse(goMod, data, nil)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", goMod, err)
	}
	var localReplaces []string
	for _, replace := range mod.Replace {
		if replace.New.Version != "" {
			continue
		}
		target := replace.New.Path
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir, target)
		}
		target = filepath.Clean(target)
		writeHashLine(sum, "replace %s\n", target)
		localReplaces = append(localReplaces, target)
	}
	if err := hashModuleSources(sum, dir, dir, visited, false); err != nil {
		var linkedErr *linkedTreeReadError
		if errors.As(err, &linkedErr) {
			return false, nil
		}
		return false, fmt.Errorf("hash Go sources of %s: %w", dir, err)
	}
	for _, target := range localReplaces {
		cacheable, err := isLocalReplaceModule(target)
		if err != nil || !cacheable {
			return false, err
		}
		cacheable, err = hashModuleTree(sum, target, visited)
		if err != nil || !cacheable {
			return cacheable, err
		}
	}
	return true, nil
}

func isLocalReplaceModule(target string) (bool, error) {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return false, fmt.Errorf("make local replace target absolute: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absTarget)
	if unresolvableLink(absTarget, err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("resolve local replace target %s: %w", target, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return false, fmt.Errorf("stat local replace target %s: %w", target, err)
	}
	if !info.IsDir() {
		return false, nil
	}
	if _, err := os.Stat(filepath.Join(resolved, "go.mod")); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("stat local replace module file in %s: %w", target, err)
	}
	return true, nil
}

type linkedTreeReadError struct {
	err error
}

func (e *linkedTreeReadError) Error() string { return e.err.Error() }
func (e *linkedTreeReadError) Unwrap() error { return e.err }

// hashModuleSources walks module files and Go sources, following symlinks.
func hashModuleSources(sum hash.Hash, dir, moduleRoot string, visited map[string]struct{}, underExternalLink bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return markLinkedTreeReadError(err, underExternalLink)
	}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			if os.IsNotExist(err) && !underExternalLink {
				continue
			}
			return markLinkedTreeReadError(err, underExternalLink)
		}
		isSymlink := info.Mode()&fs.ModeSymlink != 0
		resolved := path
		childUnderExternalLink := underExternalLink
		if isSymlink {
			resolved, err = filepath.EvalSymlinks(path)
			if unresolvableLink(path, err) {
				writeHashLine(sum, "link %s -> dangling\n", path)
				continue
			}
			if err != nil {
				return markLinkedTreeReadError(err, underExternalLink)
			}
			writeHashLine(sum, "link %s -> %s\n", path, resolved)
			info, err = os.Stat(resolved)
			if err != nil {
				if os.IsNotExist(err) {
					writeHashLine(sum, "link %s -> dangling\n", path)
					continue
				}
				return markLinkedTreeReadError(err, underExternalLink)
			}
			childUnderExternalLink = underExternalLink || !pathWithin(moduleRoot, resolved)
		}
		if info.IsDir() {
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "node_modules" {
				continue
			}
			if _, err := os.Stat(filepath.Join(resolved, "go.mod")); err == nil {
				continue
			} else if !os.IsNotExist(err) {
				return markLinkedTreeReadError(err, childUnderExternalLink)
			}
			resolved, err = filepath.Abs(resolved)
			if err != nil {
				return markLinkedTreeReadError(err, childUnderExternalLink)
			}
			resolved = filepath.Clean(resolved)
			if _, ok := visited[resolved]; ok {
				continue
			}
			visited[resolved] = struct{}{}
			if err := hashModuleSources(sum, resolved, moduleRoot, visited, childUnderExternalLink); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		isModuleFile := filepath.Dir(path) == dir && (name == "go.mod" || name == "go.sum")
		isVendorList := name == "modules.txt" && filepath.Base(filepath.Dir(path)) == "vendor"
		if strings.HasSuffix(name, ".go") || cgoSourceExts[filepath.Ext(name)] || isModuleFile || isVendorList {
			if err := hashFile(sum, path); err != nil {
				return markLinkedTreeReadError(err, childUnderExternalLink)
			}
		}
	}
	return nil
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func markLinkedTreeReadError(err error, underExternalLink bool) error {
	if underExternalLink {
		return &linkedTreeReadError{err: err}
	}
	return err
}

// writeHashLine adds a formatted line to a hash. hash.Hash.Write never
// returns an error, so there is none to handle.
func writeHashLine(sum hash.Hash, format string, args ...any) {
	_, _ = fmt.Fprintf(sum, format, args...)
}

func hashFile(sum hash.Hash, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	writeHashLine(sum, "file %s %x\n", path, sha256.Sum256(data))
	return nil
}

func hashOptionalFile(sum hash.Hash, path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		writeHashLine(sum, "absent %s\n", path)
		return nil
	}
	return hashFile(sum, path)
}

// unresolvableLink reports a symlink that leads nowhere: its target is
// missing, or the links loop. The go command reads neither, so the link counts
// as dangling rather than as an error of the hash.
func unresolvableLink(path string, err error) bool {
	if err == nil {
		return false
	}
	if os.IsNotExist(err) {
		return true
	}
	_, statErr := os.Stat(path)
	return os.IsNotExist(statErr) || errors.Is(statErr, syscall.ELOOP)
}
