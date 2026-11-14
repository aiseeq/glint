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
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/deadcode"
)

type broadEntry struct {
	pattern   string
	line      int
	exception bool
	// skipDir is a directory name of settings.skip_dirs: the walk leaves
	// out every directory of that name.
	skipDir bool
	// rule is the rule watching suppressions that the entry switches off by
	// name; "" for other entries.
	rule string
	// oversight marks an entry that switches off a rule watching
	// suppressions, by name or with its category.
	oversight bool
	// file is the configuration file, absolute, the entry is reported in and
	// whose marker keeps it.
	file string
	// origin is the base file outside the project the entry is set in, and
	// originLine its line there; "" when it is set in file itself.
	origin     string
	originLine int
}

// oversightRules are the rules that watch suppressions: switching one off
// takes that watch away from the whole project.
var oversightRules = []string{"suppression-without-reason", "stale-suppression", broadExclusionRule}

// broadConfigFile is one file of the extends chain of the project's
// configuration, the project's own file first.
type broadConfigFile struct {
	path string
	data []byte
	top  *yaml.Node
	// reportIn and reportLine place what a base file outside the project
	// sets: on the extends line that leads out of the project. reportLine is
	// 0 for a file of the project, whose own lines are its places.
	reportIn   string
	reportLine int
}

// entry places an entry read at a line of the file.
func (f broadConfigFile) entry(entry broadEntry) broadEntry {
	entry.file = f.path
	if f.reportLine != 0 {
		entry.origin, entry.originLine = f.path, entry.line
		entry.file, entry.line = f.reportIn, f.reportLine
	}
	return entry
}

// readBroadChain reads the configuration and every file it extends, as
// core.LoadConfig resolves them: extends is relative to the directory of the
// file that declares it.
func readBroadChain(configPath, root string) ([]broadConfigFile, error) {
	var chain []broadConfigFile
	seen := make(map[string]bool)
	reportIn, reportLine := configPath, 0
	for path := configPath; !seen[path]; {
		seen[path] = true
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read configuration for broad exclusions: %w", err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse configuration %q for broad exclusions: %w", path, err)
		}
		file := broadConfigFile{path: path, data: data, reportIn: reportIn, reportLine: reportLine}
		if len(doc.Content) > 0 {
			file.top = doc.Content[0]
		}
		inProject := inBroadProject(root, path)
		if inProject {
			file.reportIn, file.reportLine = path, 0
		}
		chain = append(chain, file)
		extends := configNode(file.top, "extends")
		if extends == nil || extends.Value == "" {
			break
		}
		if inProject {
			reportIn, reportLine = path, extends.Line
		}
		next := extends.Value
		if !filepath.IsAbs(next) {
			next = filepath.Join(filepath.Dir(path), next)
		}
		path = next
	}
	return chain, nil
}

// inBroadProject reports a path under the project's directory.
func inBroadProject(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && !strings.HasPrefix(filepath.ToSlash(rel), "../")
}

// forEachPair calls fn with every key and value of a mapping node.
func forEachPair(n *yaml.Node, fn func(key, value *yaml.Node)) {
	if n == nil || n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		fn(n.Content[i], n.Content[i+1])
	}
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

// foreignBroadNames are directories of foreign code and test data: no source
// of the project's own is in them.
var foreignBroadNames = map[string]bool{"third_party": true, "vendor": true, "external": true, "node_modules": true, "testdata": true}

// ignoredBroadPattern reports a pattern over a foreign, test-data or
// generated path. A build, out, dist, bin, site or gen directory is none: the
// walk reads a tracked one, and an untracked one it leaves out holds none of
// the sources an exclusion is judged by.
func ignoredBroadPattern(pattern string) bool {
	lower := strings.ToLower(pattern)
	if strings.Contains(lower, "generated") {
		return true
	}
	for _, segment := range strings.FieldsFunc(lower, func(r rune) bool { return r == '/' || r == '\\' }) {
		if foreignBroadNames[segment] {
			return true
		}
	}
	return false
}

// broadLineHasReason reports a marker of broad-exclusion with a reason on the
// line of the entry, or on the line above when it covers the line under it,
// read like every inline marker (core.SuppressionMarkers): one after an entry
// keeps that entry alone.
func broadLineHasReason(ctx *core.FileContext, line int) bool {
	for _, marker := range ctx.SuppressionMarkers() {
		if (marker.Line == line || marker.Line == line-1 && !marker.LineOnly) && slices.Contains(marker.Rules, broadExclusionRule) && core.SuppressionHasReason(marker.Text, broadExclusionRule) {
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
// no finding, and one of a tracked build directory the walk reads is judged
// as any other. Generated files are left out too, and so are foreign and
// test-data directories.
func collectProjectSourceFiles(root string, cfg *core.Config) (broadSources, error) {
	unexcluded := *cfg
	unexcluded.Settings.Exclude, unexcluded.Settings.SkipDirs = nil, nil
	walker := core.NewWalker(root, &unexcluded).WithGoParsing(false).WithRequiredFilePredicate(isSourceFile)
	contexts, walkErrors := walker.WalkSync()
	for _, err := range walkErrors {
		// A directory or file the user cannot read holds no source glint checks.
		if !errors.Is(err, fs.ErrPermission) {
			return broadSources{}, fmt.Errorf("walk project source files: %w", err)
		}
	}
	var files []string
	for _, ctx := range contexts {
		rel := filepath.ToSlash(ctx.RelPath)
		if ctx.IsGenerated() || inBroadDirectory(rel, foreignBroadDirectory) {
			continue
		}
		files = append(files, rel)
	}
	slices.Sort(files)
	return newBroadSources(files), nil
}

// broadSources are the sources broad-exclusion judges an entry by.
type broadSources struct {
	// files are the project's own sources the walk reads without the
	// configuration's exclusions.
	files   []string
	catalog map[string]int
}

func newBroadSources(files []string) broadSources {
	return broadSources{files: files, catalog: sourceCatalog(files)}
}

// inBroadDirectory reports a file below a directory the predicate names.
func inBroadDirectory(rel string, directory func(string) bool) bool {
	dir := filepath.ToSlash(filepath.Dir(rel))
	return dir != "." && slices.ContainsFunc(strings.Split(dir, "/"), directory)
}

// foreignBroadDirectory reports a hidden, foreign, test-data or generated
// directory: none holds a source of the project's own, by name or by
// settings.skip_dirs.
func foreignBroadDirectory(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(name, ".") || strings.Contains(lower, "generated") || foreignBroadNames[lower]
}

func isSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return strings.Contains("|.go|.ts|.tsx|.js|.jsx|.mts|.cts|.mjs|.cjs|", "|"+ext+"|")
}

// parseBroadEntries returns the entries of the extends chain that are in
// effect, as core.MergeConfigs merges the files: a list or a switch is set by
// the first file of the chain, from the project's own, that sets it.
func parseBroadEntries(cfg *core.Config, chain []broadConfigFile) []broadEntry {
	entries := make([]broadEntry, 0)
	if file, list := firstBroadSetting(chain, "exclude"); list != nil {
		for _, value := range list.Content {
			entries = append(entries, file.entry(broadEntry{pattern: value.Value, line: value.Line}))
		}
	}
	if file, list := firstBroadSetting(chain, "skip_dirs"); list != nil {
		for _, value := range list.Content {
			entries = append(entries, file.entry(broadEntry{pattern: value.Value, line: value.Line, skipDir: true}))
		}
	}
	entries = append(entries, broadRuleExceptions(chain)...)
	for _, name := range slices.Sorted(maps.Keys(cfg.Categories)) {
		if cfg.Categories[name].Enabled {
			continue
		}
		file, node := firstBroadNode(chain, name)
		if node == nil {
			continue
		}
		line := node.Line
		if enabled := configNode(node, "enabled"); enabled != nil {
			line = enabled.Line
		}
		entries = append(entries, file.entry(broadEntry{pattern: "<category>", line: line, oversight: holdsOversightRule(name)}))
	}
	for _, name := range oversightRules {
		category := oversightCategory(name)
		if !cfg.IsRuleDisabled(category, name) {
			continue
		}
		file, node := firstBroadNode(chain, category, "rules", name)
		if node == nil {
			continue
		}
		line := node.Line
		if enabled := configNode(node, "enabled"); enabled != nil {
			line = enabled.Line
		}
		entries = append(entries, file.entry(broadEntry{pattern: "<rule>", line: line, rule: name, oversight: true}))
	}
	return entries
}

// firstBroadSetting returns the first file of the chain that sets a list of
// settings, and the list: an empty one sets nothing.
func firstBroadSetting(chain []broadConfigFile, key string) (broadConfigFile, *yaml.Node) {
	for _, file := range chain {
		if list := configNode(configNode(file.top, "settings"), key); list != nil && len(list.Content) > 0 {
			return file, list
		}
	}
	return broadConfigFile{}, nil
}

// firstBroadNode returns the first file of the chain that names a node under
// categories, and the node.
func firstBroadNode(chain []broadConfigFile, path ...string) (broadConfigFile, *yaml.Node) {
	for _, file := range chain {
		node := configNode(file.top, "categories")
		for _, key := range path {
			node = configNode(node, key)
		}
		if node != nil {
			return file, node
		}
	}
	return broadConfigFile{}, nil
}

// broadRuleExceptions returns the file exceptions of every rule, each from
// the first file of the chain that lists the rule's exceptions.
func broadRuleExceptions(chain []broadConfigFile) []broadEntry {
	var entries []broadEntry
	listed := make(map[string]bool)
	for _, file := range chain {
		forEachPair(configNode(file.top, "categories"), func(category, categoryNode *yaml.Node) {
			forEachPair(configNode(categoryNode, "rules"), func(rule, ruleNode *yaml.Node) {
				exceptions := configNode(ruleNode, "exceptions")
				key := category.Value + "/" + rule.Value
				if exceptions == nil || exceptions.Tag == "!!null" || listed[key] {
					return
				}
				listed[key] = true
				var found []broadEntry
				collectBroadExceptions(ruleNode, &found)
				for _, entry := range found {
					entries = append(entries, file.entry(entry))
				}
			})
		})
	}
	return entries
}

// oversightCategory returns the category of a rule watching suppressions.
func oversightCategory(name string) string {
	rule, ok := rules.Get(name)
	if !ok {
		return ""
	}
	return rule.Category()
}

// holdsOversightRule reports a category with a rule watching suppressions.
func holdsOversightRule(category string) bool {
	return slices.ContainsFunc(oversightRules, func(name string) bool { return oversightCategory(name) == category })
}

func broadExclusionFindings(cfg *core.Config) ([]*core.Violation, error) {
	if cfg.ConfigPath() == "" {
		return nil, nil
	}
	root := filepath.Dir(cfg.ConfigPath())
	sources, err := collectProjectSourceFiles(root, cfg)
	if err != nil {
		return nil, err
	}
	chain, err := readBroadChain(cfg.ConfigPath(), root)
	if err != nil {
		return nil, err
	}
	entries := parseBroadEntries(cfg, chain)
	// broad-exclusion switched off by name runs only to report that it is.
	if cfg.IsRuleDisabled(oversightCategory(broadExclusionRule), broadExclusionRule) {
		entries = slices.DeleteFunc(entries, func(entry broadEntry) bool { return !entry.oversight })
	}
	return checkBroadEntries(entries, sources, chain, root, cfg)
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

func checkBroadEntries(entries []broadEntry, sources broadSources, chain []broadConfigFile, root string, cfg *core.Config) ([]*core.Violation, error) {
	rule := deadcode.NewBroadExclusionRule()
	contexts := make(map[string]*core.FileContext, len(chain))
	for _, file := range chain {
		contexts[file.path] = core.NewFileContext(file.path, root, file.data, cfg)
	}
	findings := make([]*core.Violation, 0)
	for _, entry := range entries {
		if broadLineHasReason(contexts[entry.file], entry.line) {
			continue
		}
		message, err := checkBroadEntry(entry, sources)
		if err != nil {
			return nil, err
		}
		if message == "" {
			continue
		}
		name, err := broadRelPath(root, entry.file)
		if err != nil {
			return nil, err
		}
		if entry.origin != "" {
			origin, err := broadRelPath(root, entry.origin)
			if err != nil {
				return nil, err
			}
			message = fmt.Sprintf("%s:%d, outside the project, through extends: %s", origin, entry.originLine, message)
		}
		findings = append(findings, rule.CreateViolation(name, entry.line, message))
	}
	return findings, nil
}

// broadRelPath is a configuration file relative to the project.
func broadRelPath(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("relative configuration path: %w", err)
	}
	return filepath.ToSlash(rel), nil
}

func broadFindingMessage(entry broadEntry, files []string) string {
	if entry.rule != "" {
		return fmt.Sprintf("Rule %s, which watches suppressions, is switched off for the whole project; "+broadMarkerAdvice, entry.rule)
	}
	if entry.skipDir {
		return fmt.Sprintf("settings.skip_dirs leaves out every directory named %s, and the project's sources are in one; "+broadMarkerAdvice, entry.pattern)
	}
	if language := coveredLanguage(entry, files); language != "" {
		return fmt.Sprintf("Exclusion covers every %s file of the project; "+broadMarkerAdvice, language)
	}
	if entry.pattern == "<category>" && entry.oversight {
		return "An entire rule category is disabled, and with it the rules that watch suppressions; " + broadMarkerAdvice
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
func checkBroadEntry(entry broadEntry, sources broadSources) (string, error) {
	covers, err := coversBroadly(entry, sources)
	if err != nil {
		return "", err
	}
	if covers {
		return broadFindingMessage(entry, sources.files), nil
	}
	if language := coveredTestLanguage(entry, sources.files); language != "" {
		return testsFindingMessage(language), nil
	}
	return "", nil
}

// coversBroadly reports an entry that disables a category or a rule watching
// suppressions, skips a directory of sources, or excludes a whole language, a
// whole source directory, or the whole project for one rule.
func coversBroadly(entry broadEntry, sources broadSources) (bool, error) {
	if entry.pattern == "<category>" || entry.rule != "" {
		return true, nil
	}
	if entry.skipDir {
		return skipsSourceDirectory(entry.pattern, sources.files), nil
	}
	if !broadGlob(entry.pattern) {
		return false, nil
	}
	files := sources.files
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
	for directory, total := range sources.catalog {
		if total > 0 && matched[directory] == total {
			return true, nil
		}
	}
	return false, nil
}

// skipsSourceDirectory reports whether a settings.skip_dirs name leaves out a
// directory with sources the walk reads: an artifact one such as a tracked
// build directory too. A hidden, foreign, generated or test-data one holds
// none of them.
func skipsSourceDirectory(name string, walked []string) bool {
	for _, file := range walked {
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
