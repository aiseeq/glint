package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

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
// toolchain and build environment.
// Modules come from the module cache by the versions go.sum pins, so they are
// covered by go.sum. cacheable is false when the load reads what the hash
// cannot cover: a replace directive pointing at a local directory.
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
		uses, cacheable, err := workspaceModules(work)
		if err != nil || !cacheable {
			return "", false, err
		}
		if err := hashFile(sum, work); err != nil {
			return "", false, err
		}
		if err := hashOptionalFile(sum, work+".sum"); err != nil {
			return "", false, err
		}
		dirs = append(dirs, uses...)
	}
	slices.Sort(dirs)
	dirs = slices.Compact(dirs)
	for _, dir := range dirs {
		cacheable, err := hashModuleTree(sum, dir)
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

// workspaceModules returns the module directories a go.work uses. A replace
// to a local directory makes the workspace uncacheable.
func workspaceModules(workFile string) ([]string, bool, error) {
	data, err := os.ReadFile(workFile)
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", workFile, err)
	}
	work, err := modfile.ParseWork(workFile, data, nil)
	if err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", workFile, err)
	}
	for _, replace := range work.Replace {
		if replace.New.Version == "" {
			return nil, false, nil
		}
	}
	dirs := make([]string, 0, len(work.Use))
	for _, use := range work.Use {
		dir := use.Path
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(workFile), dir)
		}
		dirs = append(dirs, filepath.Clean(dir))
	}
	return dirs, true, nil
}

// hashModuleTree hashes the sources and module files of the module rooted at
// dir. A replace to a local directory makes the module uncacheable.
func hashModuleTree(sum hash.Hash, dir string) (bool, error) {
	goMod := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goMod)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", goMod, err)
	}
	mod, err := modfile.Parse(goMod, data, nil)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", goMod, err)
	}
	for _, replace := range mod.Replace {
		if replace.New.Version == "" {
			return false, nil
		}
	}
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if path == dir {
				return nil
			}
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		isModuleFile := filepath.Dir(path) == dir && (name == "go.mod" || name == "go.sum")
		isVendorList := name == "modules.txt" && filepath.Base(filepath.Dir(path)) == "vendor"
		if strings.HasSuffix(name, ".go") || cgoSourceExts[filepath.Ext(name)] || isModuleFile || isVendorList {
			return hashFile(sum, path)
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("hash Go sources of %s: %w", dir, err)
	}
	return true, nil
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
