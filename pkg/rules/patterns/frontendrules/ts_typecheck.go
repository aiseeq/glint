package frontendrules

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// tsconfigScope is what one tsconfig compiles: the files under its directory
// that its include patterns take and its exclude patterns leave.
type tsconfigScope struct {
	path             string
	include, exclude []tsGlob // patterns relative to base; include nil means everything
	base             string   // the directory the patterns are relative to
}

// covers reports a file the tsconfig compiles.
func (s tsconfigScope) covers(file string) (bool, error) {
	rel, err := filepath.Rel(s.base, file)
	if err != nil {
		return false, fmt.Errorf("place %s against %s: %w", file, s.path, err)
	}
	// The default include takes the tsconfig's directory; an explicit one
	// may reach outside it (../shared/**/*.test.ts).
	rel = filepath.ToSlash(rel)
	if s.include == nil && strings.HasPrefix(rel, "../") {
		return false, nil
	}
	included := s.include == nil
	for _, glob := range s.include {
		included = included || glob.match(rel)
	}
	if !included {
		return false, nil
	}
	for _, glob := range s.exclude {
		if glob.match(rel) {
			return false, nil
		}
	}
	return true, nil
}

// tsGlob is a tsconfig include or exclude pattern: ** spans directories, *
// and ? stay within one, and a pattern without a wildcard or an extension
// names a directory and everything under it.
type tsGlob struct {
	dir     string         // set for a directory pattern
	re      *regexp.Regexp // set for a wildcard or file pattern
	outside bool           // the pattern starts above the tsconfig's directory (../shared/**)
}

func (g tsGlob) match(rel string) bool {
	// ** spans directories but not up out of the tsconfig's own: a file
	// above it matches only a pattern that names the way there.
	if strings.HasPrefix(rel, "../") && !g.outside {
		return false
	}
	if g.re == nil {
		return g.dir != "" && (rel == g.dir || strings.HasPrefix(rel, g.dir+"/"))
	}
	return g.re.MatchString(rel)
}

// compileTSGlob builds the matcher of one pattern.
func compileTSGlob(pattern string) (tsGlob, error) {
	pattern = strings.TrimPrefix(filepath.ToSlash(pattern), "./")
	outside := strings.HasPrefix(pattern, "../")
	if !strings.ContainsAny(pattern, "*?") && filepath.Ext(pattern) == "" {
		return tsGlob{dir: strings.TrimSuffix(pattern, "/"), outside: outside}, nil
	}
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch {
		case strings.HasPrefix(pattern[i:], "**/"):
			re.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(pattern[i:], "**"):
			re.WriteString(".*")
			i++
		case pattern[i] == '*':
			re.WriteString("[^/]*")
		case pattern[i] == '?':
			re.WriteString("[^/]")
		default:
			re.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	re.WriteString("$")
	compiled, err := regexp.Compile(re.String())
	if err != nil {
		return tsGlob{}, fmt.Errorf("tsconfig pattern %q: %w", pattern, err)
	}
	return tsGlob{re: compiled, outside: outside}, nil
}

// tsconfigFile is the part of a tsconfig the scope needs.
type tsconfigFile struct {
	Extends json.RawMessage `json:"extends"`
	Include []string        `json:"include"`
	Exclude []string        `json:"exclude"`
}

var (
	jsoncComment       = regexp.MustCompile(`(?s)"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/`)
	jsoncTrailingComma = regexp.MustCompile(`,(\s*[}\]])`)
)

// readJSONC unmarshals a JSON file that may hold comments and trailing commas,
// as tsconfig.json does.
func readJSONC(path string, into any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read a TypeScript configuration: %w", err)
	}
	text := jsoncComment.ReplaceAllStringFunc(string(data), func(m string) string {
		if strings.HasPrefix(m, `"`) {
			return m
		}
		return ""
	})
	text = jsoncTrailingComma.ReplaceAllString(text, "$1")
	if err := json.Unmarshal([]byte(text), into); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// loadTSConfigScope reads a tsconfig with the include and exclude it takes
// from the configs it extends, each relative to the config that sets it.
func loadTSConfigScope(path string) (tsconfigScope, error) {
	scope := tsconfigScope{path: path, base: filepath.Dir(path)}
	includeSet, excludeSet := false, false
	chain, err := tsconfigChain(path)
	if err != nil {
		return tsconfigScope{}, fmt.Errorf("read tsconfig chain: %w", err)
	}
	for _, current := range chain {
		var file tsconfigFile
		if err := readJSONC(current, &file); err != nil {
			return tsconfigScope{}, fmt.Errorf("read tsconfig: %w", err)
		}
		dir := filepath.Dir(current)
		if !includeSet && file.Include != nil {
			patterns, err := rebase(file.Include, dir, scope.base)
			if err != nil {
				return tsconfigScope{}, err
			}
			globs, err := compileTSGlobs(patterns)
			if err != nil {
				return tsconfigScope{}, fmt.Errorf("%s include: %w", current, err)
			}
			scope.include, includeSet = globs, true
		}
		if !excludeSet && file.Exclude != nil {
			patterns, err := rebase(file.Exclude, dir, scope.base)
			if err != nil {
				return tsconfigScope{}, err
			}
			globs, err := compileTSGlobs(patterns)
			if err != nil {
				return tsconfigScope{}, fmt.Errorf("%s exclude: %w", current, err)
			}
			scope.exclude, excludeSet = globs, true
		}
	}
	return scope, nil
}

// tsconfigChain returns the config and its bases in precedence order.
func tsconfigChain(path string) ([]string, error) {
	seen := map[string]bool{}
	visiting := map[string]bool{}
	var chain []string
	var visit func(string) error
	visit = func(config string) error {
		absolute, err := filepath.Abs(config)
		if err != nil {
			return fmt.Errorf("resolve tsconfig path %s: %w", config, err)
		}
		absolute = filepath.Clean(absolute)
		if visiting[absolute] {
			return fmt.Errorf("tsconfig extends cycle at %s", absolute)
		}
		if seen[absolute] {
			return nil
		}
		var file tsconfigFile
		if err := readJSONC(absolute, &file); err != nil {
			return err
		}
		extends, err := tsconfigExtends(file.Extends)
		if err != nil {
			return fmt.Errorf("%s extends: %w", absolute, err)
		}
		seen[absolute] = true
		visiting[absolute] = true
		chain = append(chain, absolute)
		for i := len(extends) - 1; i >= 0; i-- {
			base, err := resolveTSConfigExtends(filepath.Dir(absolute), extends[i])
			if err != nil {
				return fmt.Errorf("resolve tsconfig extends %q from %s: %w", extends[i], absolute, err)
			}
			if err := visit(base); err != nil {
				return err
			}
		}
		delete(visiting, absolute)
		return nil
	}
	if err := visit(path); err != nil {
		return nil, err
	}
	return chain, nil
}

func tsconfigExtends(raw json.RawMessage) ([]string, error) {
	shape := strings.TrimSpace(string(raw))
	if shape == "" || shape == "null" {
		return nil, nil
	}
	switch shape[0] {
	case '"':
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, fmt.Errorf("decode extends path: %w", err)
		}
		return []string{single}, nil
	case '[':
		var multiple []string
		if err := json.Unmarshal(raw, &multiple); err != nil {
			return nil, fmt.Errorf("decode extends paths: %w", err)
		}
		return multiple, nil
	default:
		return nil, fmt.Errorf("must be a path or an array of paths")
	}
}

func resolveTSConfigExtends(dir, target string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("path is empty")
	}
	if filepath.IsAbs(target) || strings.HasPrefix(target, ".") {
		candidate := filepath.Join(dir, target)
		resolved, err := resolveTSConfigCandidate(candidate)
		if err != nil {
			return "", err
		}
		return resolved, nil
	}
	for current := dir; ; current = filepath.Dir(current) {
		candidate := filepath.Join(current, "node_modules", filepath.FromSlash(target))
		resolved, err := resolveTSConfigCandidate(candidate)
		if err == nil {
			return resolved, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return "", fmt.Errorf("configuration %q was not found", target)
}

func resolveTSConfigCandidate(candidate string) (string, error) {
	paths := []string{candidate, candidate + ".json", filepath.Join(candidate, "tsconfig.json")}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, nil
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("stat tsconfig candidate %s: %w", path, err)
		}
	}
	packageJSON := filepath.Join(candidate, "package.json")
	var metadata struct {
		TSConfig string `json:"tsconfig"`
	}
	if err := readJSONC(packageJSON, &metadata); err == nil && metadata.TSConfig != "" {
		path := filepath.Join(candidate, metadata.TSConfig)
		if filepath.Ext(path) == "" {
			path += ".json"
		}
		info, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("stat package tsconfig %s: %w", path, err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("package tsconfig %s is a directory", path)
		}
		return path, nil
	}
	return "", fs.ErrNotExist
}

// compileTSGlobs builds the matchers of a pattern list; an empty list stays
// empty, not nil.
func compileTSGlobs(patterns []string) ([]tsGlob, error) {
	globs := make([]tsGlob, 0, len(patterns))
	for _, pattern := range patterns {
		glob, err := compileTSGlob(pattern)
		if err != nil {
			return nil, err
		}
		globs = append(globs, glob)
	}
	return globs, nil
}

// rebase rewrites patterns relative to from as patterns relative to to.
func rebase(patterns []string, from, to string) ([]string, error) {
	if from == to {
		return patterns, nil
	}
	out := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		rel, err := filepath.Rel(to, filepath.Join(from, pattern))
		if err != nil {
			return nil, fmt.Errorf("rebase tsconfig pattern %q: %w", pattern, err)
		}
		out = append(out, filepath.ToSlash(rel))
	}
	return out, nil
}

// tscCommand finds a tsc run in a package.json script and the project it
// names with -p or --project.
var tscCommand = regexp.MustCompile(`(?:^|[\s;&|(])(?:npx\s+)?(?:vue-)?tsc\b([^;&|]*)`)
var tscProjectFlag = regexp.MustCompile(`(?:^|\s)(?:-p|--project)(?:\s+|=)(\S+)`)
var nextBuild = regexp.MustCompile(`(?:^|[\s;&|])next\s+build\b`)

// checkedTSConfigs returns the tsconfigs of the project that a package.json
// script type-checks: tsc -p <path>, a plain tsc (the tsconfig.json beside
// the package.json) and next build, which checks that one too.
func checkedTSConfigs(root string) ([]tsconfigScope, error) {
	var scopes []tsconfigScope
	seen := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if path != root && (patternkit.EnvFileSkipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") || strings.Count(rel, string(filepath.Separator)) >= 4) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" {
			return nil
		}
		var pkg struct {
			Scripts map[string]string `json:"scripts"`
		}
		if err := readJSONC(path, &pkg); err != nil {
			return err
		}
		dir := filepath.Dir(path)
		names := make([]string, 0, len(pkg.Scripts))
		for name := range pkg.Scripts {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			script := pkg.Scripts[name]
			var targets []string
			for _, m := range tscCommand.FindAllStringSubmatch(script, -1) {
				target := "tsconfig.json"
				if p := tscProjectFlag.FindStringSubmatch(m[1]); p != nil {
					target = p[1]
				}
				targets = append(targets, target)
			}
			if nextBuild.MatchString(script) {
				targets = append(targets, "tsconfig.json")
			}
			for _, target := range targets {
				config := filepath.Join(dir, target)
				if filepath.Ext(config) != ".json" {
					config = filepath.Join(config, "tsconfig.json")
				}
				if seen[config] {
					continue
				}
				seen[config] = true
				_, err := os.Stat(config)
				if errors.Is(err, fs.ErrNotExist) {
					continue // a script for a config that is not there checks nothing
				}
				if err != nil {
					return fmt.Errorf("stat %s: %w", config, err)
				}
				scope, err := loadTSConfigScope(config)
				if err != nil {
					return err
				}
				scopes = append(scopes, scope)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find type-checked tsconfigs under %s: %w", root, err)
	}
	return scopes, nil
}

var (
	checkedTSConfigsMu    sync.Mutex
	checkedTSConfigsCache = make(map[string]tsCheckResult)
)

type tsCheckResult struct {
	scopes []tsconfigScope
	err    error
}

// projectCheckedTSConfigs returns the type-checked tsconfigs of the project
// at root, read once per root.
func projectCheckedTSConfigs(root string) ([]tsconfigScope, error) {
	checkedTSConfigsMu.Lock()
	defer checkedTSConfigsMu.Unlock()
	result, ok := checkedTSConfigsCache[root]
	if !ok {
		result.scopes, result.err = checkedTSConfigs(root)
		checkedTSConfigsCache[root] = result
	}
	return result.scopes, result.err
}

// tsFileTypeChecked reports a TS file that a type-checked tsconfig of the
// project compiles.
func tsFileTypeChecked(root, file string) (bool, error) {
	scopes, err := projectCheckedTSConfigs(root)
	if err != nil {
		return false, err
	}
	for _, scope := range scopes {
		covered, err := scope.covers(file)
		if err != nil {
			return false, err
		}
		if covered {
			return true, nil
		}
	}
	return false, nil
}

// jestConfigNames are the files a jest config lives in.
var jestConfigNames = []string{"jest.config.js", "jest.config.cjs", "jest.config.mjs", "jest.config.ts"}

// typeCheckedByRunner reports a test file whose jest config, the nearest one
// above it, compiles it with ts-jest: ts-jest reports type errors itself.
func typeCheckedByRunner(root, file string) (bool, error) {
	for dir := filepath.Dir(file); ; dir = filepath.Dir(dir) {
		for _, name := range jestConfigNames {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return false, fmt.Errorf("read jest config: %w", err)
			}
			return strings.Contains(string(data), "ts-jest"), nil
		}
		if dir == root || dir == filepath.Dir(dir) || !strings.HasPrefix(dir, root) {
			return false, nil
		}
	}
}
