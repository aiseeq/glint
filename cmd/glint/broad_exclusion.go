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
	// oversight marks an entry that switches off a rule watching
	// suppressions, by name, with its category or by an exception of it.
	oversight bool
	// rule is the rule watching suppressions that the entry switches off by
	// name; "" for other entries.
	rule string
	// excepted is the rule watching suppressions an exception keeps off for
	// what it covers; "" for other entries.
	excepted string
	// oneLine names the files of an exception of a rule watching
	// suppressions that keeps a line of files named by base name or by a
	// glob: one line of one file when the project holds at most one file
	// they name; nil for other entries.
	oneLine *core.Exception
	// excepts is an exception of another rule that names files, judged by the
	// files it covers (core.Exception.CoversFile); nil for other entries.
	excepts *core.Exception
	// declaredAt is the line of an exception's entry that declares the
	// exception, in origin when it is set and in file otherwise: what the
	// exception silenced is found there (silencedSeverities.exception).
	declaredAt int
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
		expandBroadAliases(&doc)
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

// expandBroadAliases replaces every YAML alias under n with a copy of the
// node it names, placed on the line of the alias: the load of the
// configuration follows an alias (core.LoadConfig), so what it names is in
// effect where it is used, and is judged and kept by a marker there. The load
// refuses an alias of a node that holds it, so the copies end. Every scalar
// holds the string the load decodes of it (decodeBroadScalar), and a mapping
// holds the keys the load reads of it (mergeBroadKeys).
func expandBroadAliases(n *yaml.Node) {
	if n.Kind == yaml.ScalarNode {
		decodeBroadScalar(n)
	}
	for i, child := range n.Content {
		if child.Kind == yaml.AliasNode {
			n.Content[i] = relinedBroadNode(child.Alias, child.Line)
		}
		expandBroadAliases(n.Content[i])
	}
	if n.Kind == yaml.MappingNode {
		mergeBroadKeys(n)
	}
}

// decodeBroadScalar sets the value of a scalar to the string the load
// decodes of it, whatever its tag: a !!binary key or value is its decoded
// bytes, a null one is "". A decoded one is a plain string from then on, so
// decoding it again (decodeBroadException) keeps it; a null one stays null,
// a list of none. One the load cannot decode into a string is left as it is:
// the load refuses it where it wants one.
func decodeBroadScalar(n *yaml.Node) {
	var decoded string
	if n.Decode(&decoded) != nil || decoded == n.Value {
		return
	}
	n.Value = decoded
	if n.ShortTag() != "!!null" {
		n.Tag = "!!str"
	}
}

// isBroadMergeKey reports a merge key (<<) as the load tells one (yaml.v3,
// isMerge): a key tagged !!merge of any other name is a key of that name.
func isBroadMergeKey(key *yaml.Node) bool {
	return key.Value == "<<" && key.ShortTag() == "!!merge"
}

// mergeBroadKeys sets the keys of a mapping to those the load reads of it.
// Of keys the load decodes to one name, the last is the one in effect
// (yaml.v3 sets the map entry anew; it refuses the same name spelled the same
// way, and in a struct any two). The merge key (<<) is replaced with the keys
// it brings, as the load merges them (yaml.v3, decoder.merge): a key the
// mapping sets itself wins, and of a list of mappings the earlier one wins.
// The keys it brings are placed on the line of the merge key, where they take
// effect. A merged mapping has had its own merge key replaced before
// (expandBroadAliases).
func mergeBroadKeys(n *yaml.Node) {
	var sources []*yaml.Node
	line := 0
	content := make([]*yaml.Node, 0, len(n.Content))
	set := make(map[string]bool)
	last := make(map[string]int)
	for i := 0; i+1 < len(n.Content); i += 2 {
		if !isBroadMergeKey(n.Content[i]) {
			last[n.Content[i].Value] = i
		}
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if key := n.Content[i]; isBroadMergeKey(key) {
			sources, line = []*yaml.Node{n.Content[i+1]}, key.Line
			if n.Content[i+1].Kind == yaml.SequenceNode {
				sources = n.Content[i+1].Content
			}
			continue
		}
		if last[n.Content[i].Value] != i {
			continue
		}
		content = append(content, n.Content[i], n.Content[i+1])
		set[n.Content[i].Value] = true
	}
	for _, source := range sources {
		for i := 0; i+1 < len(source.Content); i += 2 {
			if key := source.Content[i]; !set[key.Value] {
				set[key.Value] = true
				content = append(content, relinedBroadNode(key, line), relinedBroadNode(source.Content[i+1], line))
			}
		}
	}
	n.Content = content
}

// relinedBroadNode copies a node and everything under it onto one line.
func relinedBroadNode(n *yaml.Node, line int) *yaml.Node {
	clone := *n
	clone.Line = line
	clone.Content = make([]*yaml.Node, len(n.Content))
	for i, child := range n.Content {
		clone.Content[i] = relinedBroadNode(child, line)
	}
	return &clone
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

// collectBroadExceptions returns the exceptions of a rule. One of another rule
// is an entry when it names files and nothing narrows it further; every one
// of a rule watching suppressions is, since it takes that watch away from
// what it covers (oversightException).
func collectBroadExceptions(exceptions *yaml.Node, rule string, entries *[]broadEntry) error {
	for _, exception := range broadListItems(exceptions) {
		decoded, err := decodeBroadException(exception, rule)
		if err != nil {
			return err
		}
		if slices.Contains(oversightRules, rule) {
			if entry, wide := oversightException(exception, decoded, rule); wide {
				*entries = append(*entries, entry)
			}
			continue
		}
		// A pattern, a function or a line above 0 narrows an exception; an
		// empty one or a line of 0 or less narrows nothing
		// (core.Exception.matchesViolation). The files it keeps are those it
		// covers (coversBroadly).
		if decoded.Pattern != "" || decoded.Function != "" || decoded.Line > 0 {
			continue
		}
		// One that names files is reported on the line of its files, one
		// without on its own line.
		entry := broadEntry{line: exception.Line, exception: true, excepts: &decoded, declaredAt: exception.Line}
		if decoded.Files != "" {
			entry.line = configNode(exception, "files").Line
		}
		*entries = append(*entries, entry)
	}
	return nil
}

// oversightException is the entry of an exception of a rule watching
// suppressions, on the line of the exception: whatever narrows it - a
// pattern, a function, a line, a directory - a marker it covers goes
// unwatched. One of a line of a file named by its path - file, or files with
// no glob - keeps one line of one file and is none: wide is false. One of a
// line of files named by base name or by a glob keeps their names in oneLine,
// and is none when they name one file of the project
// (narrowOversightExceptions). One that names no file names every file, the
// configuration among them, so it is never one.
func oversightException(exception *yaml.Node, decoded core.Exception, rule string) (entry broadEntry, wide bool) {
	entry = broadEntry{line: exception.Line, exception: true, oversight: true, excepted: rule, declaredAt: exception.Line}
	// A line of 0 or less is none (core.Exception.matchesViolation).
	if decoded.Line <= 0 {
		return entry, true
	}
	// A name with a directory matches the file of that path alone, and the
	// exception matches a file both file and files name
	// (core.Exception.NamesFile); file is never a glob.
	if strings.Contains(decoded.File, "/") || strings.Contains(decoded.Files, "/") && !strings.ContainsAny(decoded.Files, "*?[{") {
		return entry, false
	}
	entry.oneLine = &decoded
	return entry, true
}

// decodeBroadException reads an exception of a rule as the load reads it.
func decodeBroadException(exception *yaml.Node, rule string) (core.Exception, error) {
	var decoded core.Exception
	if err := exception.Decode(&decoded); err != nil {
		return core.Exception{}, fmt.Errorf("decode the exception of %s at line %d: %w", rule, exception.Line, err)
	}
	return decoded, nil
}

// narrowOversightExceptions drops the exceptions of a rule watching
// suppressions that keep one line of one file: a line of files named by base
// name or by a glob that cover at most one file the run reads
// (broadRunFiles), as the run matches them (core.Exception.CoversFile).
func narrowOversightExceptions(entries []broadEntry, cfg *core.Config) ([]broadEntry, error) {
	var oneLine []core.Exception
	for _, entry := range entries {
		if entry.oneLine != nil {
			oneLine = append(oneLine, *entry.oneLine)
		}
	}
	if len(oneLine) == 0 {
		return entries, nil
	}
	files, err := broadRunFiles(cfg, func(file string) bool {
		return slices.ContainsFunc(oneLine, func(exc core.Exception) bool { return exc.CoversFile(file) })
	})
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(entries, func(entry broadEntry) bool {
		return entry.oneLine != nil && len(slices.DeleteFunc(slices.Clone(files), func(file string) bool { return !entry.oneLine.CoversFile(file) })) <= 1
	}), nil
}

// broadRunFiles returns the files, relative to the configuration's
// directory, that a check of it reads and a finding about a suppression can
// be on, of those keep accepts: what the walk of the run reads - the
// configuration's exclude, skip_dirs and .gitignore apply, and so does git
// for a tracked artifact directory. The configuration is not: the run judges
// its markers whatever its exceptions say (analyzeConfigurationRules), and
// those of the configurations it extends never. The nested repositories are
// in: a check scoped to one reads them, under the same configuration.
func broadRunFiles(cfg *core.Config, keep func(string) bool) ([]string, error) {
	root := filepath.Dir(cfg.ConfigPath())
	// The walk of root visits paths below it alone.
	walker := core.NewWalker(root, cfg.AtConfigDir()).WithGoParsing(false).WithNestedRepositories(true).
		WithRequiredFilePredicate(func(path string) bool {
			rel, err := filepath.Rel(root, path)
			return err == nil && keep(filepath.ToSlash(rel))
		})
	contexts, walkErrors := walker.WalkSync()
	for _, err := range walkErrors {
		// A directory or file the user cannot read holds no finding of the run.
		if !errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("walk the files exceptions of one line cover: %w", err)
		}
	}
	var files []string
	for _, ctx := range contexts {
		files = append(files, filepath.ToSlash(ctx.RelPath))
	}
	return files, nil
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
func parseBroadEntries(cfg *core.Config, chain []broadConfigFile) ([]broadEntry, error) {
	entries := make([]broadEntry, 0)
	file, list := firstBroadSetting(chain, "exclude")
	for _, value := range list {
		entries = append(entries, file.entry(broadEntry{pattern: value.Value, line: value.Line}))
	}
	file, list = firstBroadSetting(chain, "skip_dirs")
	for _, value := range list {
		entries = append(entries, file.entry(broadEntry{pattern: value.Value, line: value.Line, skipDir: true}))
	}
	exceptions, err := broadRuleExceptions(chain)
	if err != nil {
		return nil, err
	}
	entries = append(entries, exceptions...)
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
	return entries, nil
}

// firstBroadSetting returns the first file of the chain that sets a list of
// settings, and the items of the list: an empty one sets nothing.
func firstBroadSetting(chain []broadConfigFile, key string) (broadConfigFile, []*yaml.Node) {
	for _, file := range chain {
		if items := broadListItems(configNode(configNode(file.top, "settings"), key)); len(items) > 0 {
			return file, items
		}
	}
	return broadConfigFile{}, nil
}

// broadListItems returns the items of a list the load reads: it drops a null
// item of a list of strings or of exceptions (yaml.v3 decodes null into
// nothing but a pointer, map, slice or interface), so a list of nulls alone
// sets nothing. A scalar holds no item; the load refuses a mapping there.
func broadListItems(list *yaml.Node) []*yaml.Node {
	if list == nil {
		return nil
	}
	return slices.DeleteFunc(slices.Clone(list.Content), func(item *yaml.Node) bool { return item.ShortTag() == "!!null" })
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

// broadExceptionList is the list of exceptions of a rule in effect, and the
// file of the chain that sets it.
type broadExceptionList struct {
	file           broadConfigFile
	category, rule string
	exceptions     *yaml.Node
}

// broadExceptionLists returns the exceptions of every rule, each list from
// the first file of the chain that lists the rule's exceptions, as
// core.MergeConfigs merges them: a null list sets none.
func broadExceptionLists(chain []broadConfigFile) []broadExceptionList {
	var lists []broadExceptionList
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
				lists = append(lists, broadExceptionList{file: file, category: category.Value, rule: rule.Value, exceptions: exceptions})
			})
		})
	}
	return lists
}

// broadRuleExceptions returns the file exceptions of every rule, each from
// the first file of the chain that lists the rule's exceptions.
func broadRuleExceptions(chain []broadConfigFile) ([]broadEntry, error) {
	var entries []broadEntry
	for _, list := range broadExceptionLists(chain) {
		var found []broadEntry
		if err := collectBroadExceptions(list.exceptions, list.rule, &found); err != nil {
			return nil, fmt.Errorf("%s: %w", list.file.path, err)
		}
		for _, entry := range found {
			entries = append(entries, list.file.entry(entry))
		}
	}
	return entries, nil
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

// broadExclusionFindings reports the broad exclusions of the configuration;
// one of an exception is as severe as the findings it silenced in the run
// (silenced).
func broadExclusionFindings(cfg *core.Config, silenced silencedSeverities) ([]*core.Violation, error) {
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
	entries, err := parseBroadEntries(cfg, chain)
	if err != nil {
		return nil, err
	}
	entries, err = narrowOversightExceptions(entries, cfg)
	if err != nil {
		return nil, err
	}
	// broad-exclusion switched off by name runs only to report that it is.
	if cfg.IsRuleDisabled(oversightCategory(broadExclusionRule), broadExclusionRule) {
		entries = slices.DeleteFunc(entries, func(entry broadEntry) bool { return !entry.oversight })
	}
	return checkBroadEntries(entries, sources, chain, root, cfg, silenced)
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

func checkBroadEntries(entries []broadEntry, sources broadSources, chain []broadConfigFile, root string, cfg *core.Config, silenced silencedSeverities) ([]*core.Violation, error) {
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
		finding := rule.CreateViolation(name, entry.line, message)
		finding.Severity = max(finding.Severity, silenced.exception(entry.declaredIn(), entry.declaredAt))
		findings = append(findings, finding)
	}
	return findings, nil
}

// declaredIn is the configuration file, absolute, that holds the entry: the
// base file outside the project for one set there.
func (entry broadEntry) declaredIn() string {
	if entry.origin != "" {
		return entry.origin
	}
	return entry.file
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
	if entry.excepted != "" {
		return fmt.Sprintf("Exception keeps rule %s, which watches suppressions, off for more than one line, so a marker there goes unwatched; narrow it to one line of one file (files and line), or "+broadMarkerAdvice, entry.excepted)
	}
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
	if entry.pattern == "<category>" || entry.rule != "" || entry.excepted != "" {
		return true, nil
	}
	// An exception covers the project when the run excepts every source of
	// it with the exception, whatever its files name.
	if entry.excepts != nil {
		return len(sources.files) > 0 && !slices.ContainsFunc(sources.files, func(file string) bool { return !entry.excepts.CoversFile(file) }), nil
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
	for _, file := range files {
		match, err := matchesBroadPattern(entry.pattern, file)
		if err != nil {
			return false, err
		}
		if !match {
			match, err = matchesBroadPattern(entry.pattern, "./"+file)
			if err != nil {
				return false, err
			}
		}
		if !match {
			continue
		}
		addMatchedCatalogDirs(file, matched)
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
