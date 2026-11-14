package main

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
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

func broadLineHasReason(ctx *core.FileContext, line int) bool {
	if line < 1 || line > len(ctx.Lines) {
		return false
	}
	comment := ctx.CommentOf(ctx.Lines[line-1])
	names, _ := core.ParseSuppressionComment(comment)
	if !containsString(names, "broad-exclusion") {
		return false
	}
	text := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(comment), "/#*"))
	for _, marker := range []string{"broad-exclusion: safe", "broad-exclusion:safe"} {
		if _, after, ok := strings.Cut(text, marker); ok {
			tail := strings.TrimSpace(strings.TrimSuffix(after, "*/"))
			return strings.TrimLeft(tail, "-—: \t") != ""
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	return slices.Contains(values, target)
}

func collectProjectSourceFiles(root string, cfg *core.Config) ([]string, error) {
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if errors.Is(walkErr, fs.ErrPermission) {
			return skipUnreadable(entry) // a directory the user cannot read holds no source glint checks
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if ignoredBroadDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isSourceFile(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrPermission) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read source file %s: %w", path, err)
		}
		if core.NewFileContext(path, root, data, cfg).IsGenerated() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("relative source path %s: %w", path, err)
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk project source files: %w", err)
	}
	return files, nil
}

// skipUnreadable skips an entry the walk could not read: the whole
// directory when it is one.
func skipUnreadable(entry os.DirEntry) error {
	if entry != nil && entry.IsDir() {
		return filepath.SkipDir
	}
	return nil
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

func broadExclusionFindings(cfg *core.Config, contexts []*core.FileContext) ([]*core.Violation, error) {
	if cfg.ConfigPath() == "" || len(contexts) == 0 {
		return nil, nil
	}
	root := contexts[0].ProjectRoot
	files, err := collectProjectSourceFiles(root, cfg)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
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
		found, err := checkBroadEntry(entry, files, catalog)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		findings = append(findings, rule.CreateViolation(configName, entry.line, broadFindingMessage(entry)))
	}
	return findings, nil
}

func broadFindingMessage(entry broadEntry) string {
	if entry.pattern == "<category>" {
		return "An entire rule category is disabled; intentional cases can be marked # broad-exclusion: safe — <reason>"
	}
	if entry.exception {
		return "Exception covers the whole project for one rule; switch the rule off instead, or mark an intentional case # broad-exclusion: safe — <reason>"
	}
	return "Exclusion covers all source files in a project directory; intentional cases can be marked # broad-exclusion: safe — <reason>"
}

func checkBroadEntry(entry broadEntry, files []string, catalog map[string]int) (bool, error) {
	if entry.pattern == "<category>" {
		return true, nil
	}
	if ignoredBroadPattern(entry.pattern) || !strings.ContainsAny(entry.pattern, "*?[{") {
		return false, nil
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
