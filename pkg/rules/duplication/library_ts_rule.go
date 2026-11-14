package duplication

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/toolcache"
)

func (idx *nearIndex) empty() bool { return idx == nil || len(idx.groups) == 0 }

// UseProjectFiles prepares the TypeScript comparison of the root: every
// TypeScript file is compared with the TypeScript functions of the libraries
// its Go module requires, or of all modules of the root when it lies in none
// (a frontend next to the backend). The libraries are the ones
// AnalyzeGoProject loaded, or are loaded here when its findings came from the
// cache.
func (r *DuplicateFuncOfLibraryRule) UseProjectFiles(files []*core.FileContext) {
	var tsFiles []*core.FileContext
	for _, file := range files {
		if libraryTSSourceFile(file) {
			tsFiles = append(tsFiles, file)
		}
	}
	if len(tsFiles) == 0 {
		return
	}
	allowed, _, err := r.GetStringListSetting("library_modules")
	if err != nil {
		r.warnLibraryInput(r.Name(), "read library_modules", err)
		return
	}
	moduleDirs := make(map[string]string)
	modules := make(map[string]goModule)
	fileModule := make(map[string]string, len(tsFiles))
	for _, file := range files {
		if !file.IsGoFile() && !libraryTSSourceFile(file) {
			continue
		}
		dir := nearestModuleDir(filepath.Dir(file.Path), moduleDirs)
		if dir == "" {
			continue
		}
		m := goModule{dir: dir, goMod: filepath.Join(dir, "go.mod")}
		id := moduleIdentity(m)
		if _, seen := modules[id]; !seen {
			path, err := readProjectModule(dir)
			if err != nil {
				r.warnLibraryInput(dir, "read module", err)
				continue
			}
			m.path = path
			modules[id] = m
		}
		fileModule[file.Path] = id
	}
	libraries := r.loadProjectLibraryKeys(modules, allowed, true)
	byModule := make(map[string]*nearIndex, len(libraries))
	var all []*nearCandidate
	for _, id := range slices.Sorted(maps.Keys(libraries)) {
		lib := libraries[id]
		byModule[id] = newNearIndex(lib.tsNear, minTSNearCopyTokens)
		all = append(all, lib.tsNear...)
	}
	union := newNearIndex(uniqueNearCandidates(all), minTSNearCopyTokens)
	index := make(map[string]*nearIndex, len(tsFiles))
	for _, file := range tsFiles {
		if id, ok := fileModule[file.Path]; ok {
			index[file.Path] = byModule[id]
		} else {
			index[file.Path] = union
		}
	}
	r.mu.Lock()
	r.tsFiles = index
	r.mu.Unlock()
}

func uniqueNearCandidates(list []*nearCandidate) []*nearCandidate {
	seen := make(map[string]bool, len(list))
	out := list[:0:0]
	for _, c := range list {
		key := c.fn.module + "\x00" + c.fn.importPath + "\x00" + c.fn.name
		if !seen[key] {
			seen[key] = true
			out = append(out, c)
		}
	}
	return out
}

// nearestModuleDir is the directory of the go.mod nearest above dir, or ""
// when there is none; known remembers the answer of every directory asked.
func nearestModuleDir(dir string, known map[string]string) string {
	var asked []string
	found := ""
	for {
		if answer, ok := known[dir]; ok {
			found = answer
			break
		}
		asked = append(asked, dir)
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && info.Mode().IsRegular() {
			found = dir
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	for _, d := range asked {
		known[d] = found
	}
	return found
}

// libraryTSSourceFile is a TypeScript source the comparison reads: no test,
// declaration or generated file.
func libraryTSSourceFile(file *core.FileContext) bool {
	return file.IsTypeScriptFile() && !file.IsTestFile() && !strings.HasSuffix(file.Path, ".d.ts") && !file.IsGenerated()
}

// AnalyzeFile compares the TypeScript functions of a file with the exported
// TypeScript functions of the libraries; UseProjectFiles prepared them for the
// TypeScript sources only, so a Go file finds none and is AnalyzeGoProject's.
func (r *DuplicateFuncOfLibraryRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	r.mu.Lock()
	idx := r.tsFiles[ctx.Path]
	r.mu.Unlock()
	if idx.empty() {
		return nil
	}
	src := parseTSSource(ctx.Lines)
	var out []*core.Violation
	for _, f := range src.funcs {
		candidate, score, body := idx.best(src.tsNearBody(f, false), func() nearBody { return src.tsNearBody(f, true) })
		if candidate == nil || ctx.IsSuppressed(f.line, r.Name()) {
			continue
		}
		match := candidate.fn
		message := fmt.Sprintf("%s duplicates function %s of library %s (%s) — import %s from %s instead", src.displayName(f), match.name, match.module, match.importPath, match.name, match.packageName)
		if !slices.Equal(body.Tokens, candidate.body.Tokens) || !slices.Equal(body.Vars, candidate.body.Vars) {
			message = fmt.Sprintf("%s is a near copy (%d%% alike) of function %s of library %s (%s) — import %s from %s instead", src.displayName(f), int(score*100), match.name, match.module, match.importPath, match.name, match.packageName)
		}
		v := r.CreateViolation(ctx.RelPath, f.line, message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(f.line)))
		v.WithSuggestion(fmt.Sprintf("Import %s from %s instead of keeping a copy", match.name, match.packageName))
		out = append(out, v)
	}
	return out
}

// libraryTSFiles lists the TypeScript sources of a library module: not its
// tests, declarations, dependencies or nested modules.
func libraryTSFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if path == dir {
				return nil
			}
			switch {
			case strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_"),
				name == "node_modules", name == "testdata", name == "vendor", name == "test", name == "tests", name == "__tests__":
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			} else if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			return nil
		}
		if !entry.Type().IsRegular() || !slices.Contains(core.TypeScriptExtensions, filepath.Ext(name)) ||
			strings.HasSuffix(name, ".d.ts") || strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list TypeScript of library %s: %w", dir, err)
	}
	return files, nil
}

// libraryTSFunctions reads the exported TypeScript functions of a library
// module; the package name is the one of its package.json, which a project
// imports, or the module path without one.
func libraryTSFunctions(dir string) ([]libraryNearFunction, error) {
	files, err := libraryTSFiles(dir)
	if err != nil || len(files) == 0 {
		return nil, err
	}
	packageName, err := libraryPackageName(dir)
	if err != nil {
		return nil, err
	}
	var out []libraryNearFunction
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read library TypeScript %s: %w", path, err)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil, fmt.Errorf("locate library TypeScript %s: %w", path, err)
		}
		rel = filepath.ToSlash(rel)
		src := parseTSSource(strings.Split(string(data), "\n"))
		for _, f := range src.funcs {
			if !f.exported {
				continue
			}
			body := src.tsNearBody(f, true)
			if len(body.Tokens) < minTSNearCopyTokens {
				continue
			}
			fn := libraryFunction{Name: f.name, Package: packageName, ImportPath: rel}
			out = append(out, libraryNearFunction{libraryFunction: fn, Lang: "ts", File: rel, Body: body})
		}
	}
	return out, nil
}

func libraryPackageName(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if errors.Is(err, fs.ErrNotExist) {
		module, err := readProjectModule(dir)
		if err != nil {
			return "", err
		}
		return module, nil
	}
	if err != nil {
		return "", fmt.Errorf("read package.json of library %s: %w", dir, err)
	}
	var manifest struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", fmt.Errorf("parse package.json of library %s: %w", dir, err)
	}
	if manifest.Name != "" {
		return manifest.Name, nil
	}
	return readProjectModule(dir)
}

// hashLibraryTSFiles is the digest of the TypeScript sources of a local
// library, which HashGoModuleTree does not read.
func hashLibraryTSFiles(dir string) (string, error) {
	files, err := libraryTSFiles(dir)
	if err != nil {
		return "", err
	}
	sum := sha256.New()
	for _, path := range append(files, filepath.Join(dir, "package.json")) {
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("hash library TypeScript %s: %w", path, err)
		}
		_, _ = sum.Write([]byte(path + "\x00"))
		digest := toolcache.Key(data)
		_, _ = sum.Write([]byte(digest + "\x00"))
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
