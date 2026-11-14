package main

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/deadcode"
)

type broadEntry struct {
	pattern   string
	line      int
	exception bool
	// skipDir is a directory name of settings.skip_dirs: the walk leaves
	// out every directory of that name.
	skipDir bool
}

func configNode(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func broadFiles(n *yaml.Node, entries *[]broadEntry) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		collectBroadExceptions(n, entries)
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			if key.Value != "exceptions" {
				broadFiles(value, entries)
			}
		}
		return
	}
	for _, child := range n.Content {
		broadFiles(child, entries)
	}
}

func collectBroadExceptions(n *yaml.Node, entries *[]broadEntry) {
	exceptions := configNode(n, "exceptions")
	if exceptions == nil || exceptions.Kind != yaml.SequenceNode {
		return
	}
	for _, exception := range exceptions.Content {
		if configNode(exception, "pattern") != nil || configNode(exception, "function") != nil || configNode(exception, "line") != nil {
			continue
		}
		for _, key := range []string{"files", "file"} {
			path := configNode(exception, key)
			if path != nil && path.Kind == yaml.ScalarNode {
				*entries = append(*entries, broadEntry{pattern: path.Value, line: path.Line, exception: true})
			}
		}
	}
}

func ignoredBroadPattern(pattern string) bool {
	lower := strings.ToLower(pattern)
	if strings.Contains(lower, "generated") {
		return true
	}
	ignored := map[string]bool{"third_party": true, "vendor": true, "external": true, "node_modules": true, "testdata": true, "gen": true, "out": true, "dist": true, "build": true, "site": true}
	for _, segment := range strings.FieldsFunc(lower, func(r rune) bool { return r == '/' || r == '\\' }) {
		if ignored[segment] {
			return true
		}
	}
	return false
}

// broadLineHasReason reports a marker of broad-exclusion with a reason on the
// line of the entry or the line above, read like every inline marker
// (core.SuppressionMarkers).
func broadLineHasReason(ctx *core.FileContext, line int) bool {
	for _, marker := range ctx.SuppressionMarkers() {
		if (marker.Line == line || marker.Line == line-1) && slices.Contains(marker.Rules, broadExclusionRule) && core.SuppressionHasReason(marker.Text, broadExclusionRule) {
			return true
		}
	}
	return false
}

const broadExclusionRule = "broad-exclusion"

// broadMarkerAdvice tells how to keep an intentional broad exclusion. It
// ends with the marker to copy, whose placeholder is no reason: a copy stays a
// finding until the reason is written in its place.
const broadMarkerAdvice = "keep an intentional one with a marker on its line or the line above: # broad-exclusion: safe — <reason>"

// collectProjectSourceFiles returns the source files the walker visits in the
// project when its own exclusions (settings.exclude, settings.skip_dirs) are
// left out: .gitignore, nested repositories and the default artifact
// directories keep theirs, so an exclusion of what the walk never reaches is
// no finding. Generated files and foreign, test-data and generated
// directories are left out too.
func collectProjectSourceFiles(root string, cfg *core.Config) ([]string, error) {
	unexcluded := *cfg
	unexcluded.Settings.Exclude, unexcluded.Settings.SkipDirs = nil, nil
	walker := core.NewWalker(root, &unexcluded).WithGoParsing(false).WithRequiredFilePredicate(isSourceFile)
	contexts, walkErrors := walker.WalkSync()
	for _, err := range walkErrors {
		// A directory or file the user cannot read holds no source glint checks.
		if !errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("walk project source files: %w", err)
		}
	}
	files := make([]string, 0, len(contexts))
	for _, ctx := range contexts {
		rel := filepath.ToSlash(ctx.RelPath)
		if ctx.IsGenerated() || inIgnoredBroadDirectory(ctx.RelPath) {
			continue
		}
		files = append(files, rel)
	}
	slices.Sort(files)
	return files, nil
}

// inIgnoredBroadDirectory reports a file below a directory broad-exclusion
// leaves out of the project's sources.
func inIgnoredBroadDirectory(rel string) bool {
	dir := filepath.ToSlash(filepath.Dir(rel))
	return dir != "." && slices.ContainsFunc(strings.Split(dir, "/"), ignoredBroadDirectory)
}

func ignoredBroadDirectory(name string) bool {
	return name == ".git" || strings.HasPrefix(name, ".") || ignoredBroadPattern(name)
}

func isSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return strings.Contains("|.go|.ts|.tsx|.js|.jsx|.mts|.cts|.mjs|.cjs|", "|"+ext+"|")
}

func parseBroadEntries(cfg *core.Config, data []byte) ([]broadEntry, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse configuration for broad exclusions: %w", err)
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	top := doc.Content[0]
	entries := make([]broadEntry, 0)
	if settings := configNode(top, "settings"); settings != nil {
		if excluded := configNode(settings, "exclude"); excluded != nil {
			for _, value := range excluded.Content {
				entries = append(entries, broadEntry{pattern: value.Value, line: value.Line})
			}
		}
		if skipped := configNode(settings, "skip_dirs"); skipped != nil {
			for _, value := range skipped.Content {
				entries = append(entries, broadEntry{pattern: value.Value, line: value.Line, skipDir: true})
			}
		}
	}
	broadFiles(top, &entries)
	categories := configNode(top, "categories")
	for _, name := range slices.Sorted(maps.Keys(cfg.Categories)) {
		category := cfg.Categories[name]
		if category.Enabled || categories == nil {
			continue
		}
		node := configNode(categories, name)
		if node == nil {
			continue
		}
		line := node.Line
		if enabled := configNode(node, "enabled"); enabled != nil {
			line = enabled.Line
		}
		entries = append(entries, broadEntry{pattern: "<category>", line: line})
	}
	return entries, nil
}

func broadExclusionFindings(cfg *core.Config) ([]*core.Violation, error) {
	if cfg.ConfigPath() == "" {
		return nil, nil
	}
	root := filepath.Dir(cfg.ConfigPath())
	files, err := collectProjectSourceFiles(root, cfg)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(cfg.ConfigPath())
	if err != nil {
		return nil, fmt.Errorf("read configuration for broad exclusions: %w", err)
	}
	entries, err := parseBroadEntries(cfg, data)
	if err != nil {
		return nil, err
	}
	catalog := sourceCatalog(files)
	configContext := core.NewFileContext(cfg.ConfigPath(), root, data, cfg)
	configName, err := filepath.Rel(root, cfg.ConfigPath())
	if err != nil {
		return nil, fmt.Errorf("relative configuration path: %w", err)
	}
	findings, err := checkBroadEntries(entries, files, catalog, configContext, filepath.ToSlash(configName))
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func sourceCatalog(files []string) map[string]int {
	catalog := make(map[string]int)
	for _, file := range files {
		for dir := filepath.ToSlash(filepath.Dir(file)); ; dir = filepath.ToSlash(filepath.Dir(dir)) {
			catalog[dir]++
			if dir == "." || dir == "" {
				break
			}
		}
	}
	return catalog
}

func checkBroadEntries(entries []broadEntry, files []string, catalog map[string]int, configContext *core.FileContext, configName string) ([]*core.Violation, error) {
	rule := deadcode.NewBroadExclusionRule()
	findings := make([]*core.Violation, 0)
	for _, entry := range entries {
		if broadLineHasReason(configContext, entry.line) {
			continue
		}
		message, err := checkBroadEntry(entry, files, catalog)
		if err != nil {
			return nil, err
		}
		if message == "" {
			continue
		}
		findings = append(findings, rule.CreateViolation(configName, entry.line, message))
	}
	return findings, nil
}

func broadFindingMessage(entry broadEntry, files []string) string {
	if entry.skipDir {
		return fmt.Sprintf("settings.skip_dirs leaves out every directory named %s, and the project's sources are in one; "+broadMarkerAdvice, entry.pattern)
	}
	if language := coveredLanguage(entry, files); language != "" {
		return fmt.Sprintf("Exclusion covers every %s file of the project; "+broadMarkerAdvice, language)
	}
	if entry.pattern == "<category>" {
		return "An entire rule category is disabled; " + broadMarkerAdvice
	}
	if entry.exception {
		return "Exception covers the whole project for one rule; switch the rule off instead, or " + broadMarkerAdvice
	}
	return "Exclusion covers all source files in a project directory; " + broadMarkerAdvice
}

// testsFindingMessage is the finding of an exclusion that takes out every
// test file of a language.
func testsFindingMessage(language string) string {
	return fmt.Sprintf("Exclusion covers every %s test file of the project, so no rule reads its tests; except the tests per rule instead, or "+broadMarkerAdvice, language)
}

// checkBroadEntry returns the finding message of an entry, "" when it is
// narrow. An exclusion of a whole directory or language keeps that message
// even when it takes out every test too.
func checkBroadEntry(entry broadEntry, files []string, catalog map[string]int) (string, error) {
	covers, err := coversBroadly(entry, files, catalog)
	if err != nil {
		return "", err
	}
	if covers {
		return broadFindingMessage(entry, files), nil
	}
	if language := coveredTestLanguage(entry, files); language != "" {
		return testsFindingMessage(language), nil
	}
	return "", nil
}

// coversBroadly reports an entry that disables a category, skips a directory
// of sources, or excludes a whole language, a whole source directory, or the
// whole project for one rule.
func coversBroadly(entry broadEntry, files []string, catalog map[string]int) (bool, error) {
	if entry.pattern == "<category>" {
		return true, nil
	}
	if entry.skipDir {
		return skipsSourceDirectory(entry.pattern, files), nil
	}
	if !broadGlob(entry.pattern) {
		return false, nil
	}
	if coveredLanguage(entry, files) != "" {
		return true, nil
	}
	matched := make(map[string]int)
	projectMatches := 0
	for _, file := range files {
		match, err := matchesBroadPattern(entry.pattern, file)
		if err != nil {
			return false, err
		}
		if !match && !entry.exception {
			match, err = matchesBroadPattern(entry.pattern, "./"+file)
			if err != nil {
				return false, err
			}
		}
		if !match {
			continue
		}
		projectMatches++
		addMatchedCatalogDirs(file, matched)
	}
	if entry.exception {
		return projectMatches == len(files), nil
	}
	for directory, total := range catalog {
		if total > 0 && matched[directory] == total {
			return true, nil
		}
	}
	return false, nil
}

// skipsSourceDirectory reports whether a settings.skip_dirs name leaves out a
// directory with sources of the project. The walk's default artifact
// directories and the foreign, generated and test-data ones are no finding.
func skipsSourceDirectory(name string, files []string) bool {
	if ignoredBroadDirectory(name) || slices.Contains(core.DefaultSkipDirs, name) {
		return false
	}
	for _, file := range files {
		if slices.Contains(strings.Split(filepath.ToSlash(filepath.Dir(file)), "/"), name) {
			return true
		}
	}
	return false
}

// sourceExtensions are the extensions of the project's source files.
var sourceExtensions = slices.Concat([]string{".go"}, core.TypeScriptExtensions, core.JavaScriptExtensions)

// extensionGlob is the last path element of a pattern that names files by
// their extension alone ("*.go", "*.{ts,tsx}").
var extensionGlob = regexp.MustCompile(`^\*\.[A-Za-z0-9{},]+$`)

// coveredLanguage returns the extension (".ts") every file of which in the
// project an exclude pattern that names files by extension ("*.go",
// "**/*.ts") takes out, matched as the exclusion matches (core.MatchGlob);
// "" when none. Each extension counts by itself: "**/*.ts" takes out the
// TypeScript of a project whose views stay in .tsx all the same.
func coveredLanguage(entry broadEntry, files []string) string {
	if entry.exception || entry.skipDir || !extensionGlob.MatchString(entry.pattern[strings.LastIndex(entry.pattern, "/")+1:]) {
		return ""
	}
	for _, ext := range sourceExtensions {
		total, covered := 0, 0
		for _, file := range files {
			if strings.ToLower(filepath.Ext(file)) != ext {
				continue
			}
			total++
			if core.MatchGlob(entry.pattern, file) {
				covered++
			}
		}
		if total > 0 && covered == total {
			return ext
		}
	}
	return ""
}

// broadGlob reports a pattern that may take out more than one file of the
// project's own: a glob over no foreign, generated or test-data path.
func broadGlob(pattern string) bool {
	return !ignoredBroadPattern(pattern) && strings.ContainsAny(pattern, "*?[{")
}

// testFileLanguage returns the language of a source file ("Go",
// "TypeScript", "JavaScript", "" for none) and whether it is a test of that
// language: x_test.go, x.test.ts or x.spec.ts and so for every TypeScript and
// JavaScript extension.
func testFileLanguage(file string) (string, bool) {
	base := filepath.Base(filepath.ToSlash(file))
	ext := strings.ToLower(filepath.Ext(base))
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	switch {
	case ext == ".go":
		return "Go", strings.HasSuffix(stem, "_test")
	case slices.Contains(core.TypeScriptExtensions, ext):
		return "TypeScript", isTestStem(stem)
	case slices.Contains(core.JavaScriptExtensions, ext):
		return "JavaScript", isTestStem(stem)
	}
	return "", false
}

func isTestStem(stem string) bool {
	return strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".spec")
}

// coveredTestLanguage returns the language ("Go") every test file of which
// in the project a settings.exclude pattern takes out, matched as the walk
// matches it (core.MatchGlob: a pattern without a separator matches the base
// name); "" when none, or when the project has no test of that language.
// Each language counts by itself, all its extensions together: "**/*.test.ts"
// leaves the tests of a project that has .test.tsx ones too.
func coveredTestLanguage(entry broadEntry, files []string) string {
	if entry.exception || entry.skipDir || !broadGlob(entry.pattern) {
		return ""
	}
	for _, language := range []string{"Go", "TypeScript", "JavaScript"} {
		tests, covered := 0, 0
		for _, file := range files {
			if fileLanguage, test := testFileLanguage(file); fileLanguage != language || !test {
				continue
			}
			tests++
			if core.MatchGlob(entry.pattern, file) {
				covered++
			}
		}
		if tests > 0 && covered == tests {
			return language
		}
	}
	return ""
}

func matchesBroadPattern(pattern, file string) (bool, error) {
	matched, err := doublestar.Match(pattern, file)
	if errors.Is(err, doublestar.ErrBadPattern) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("match broad exclusion %q against %q: %w", pattern, file, err)
	}
	return matched, nil
}

func addMatchedCatalogDirs(file string, matched map[string]int) {
	for dir := filepath.ToSlash(filepath.Dir(file)); ; dir = filepath.ToSlash(filepath.Dir(dir)) {
		matched[dir]++
		if dir == "." || dir == "" {
			return
		}
	}
}
