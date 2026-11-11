package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/toolcache"
)

// cacheFormat changes whenever the stored layout does.
const cacheFormat = "glint-results-7"

// maxProjectCacheVariants keeps room for the five Go input modes in the
// adversary scenario, plus variants created by edits and concurrent runs.
const maxProjectCacheVariants = 8

// resultCache keeps the findings of file-local rules (rules.FileLocal) per
// file of one project root between runs. A file whose content is unchanged
// gets them back instead of being analyzed again: between two commits most
// files are.
//
// The stamp covers everything else a file-local finding depends on: the glint
// build, the configuration, where the Go syntax trees came from and the
// tolerance flag. Each stamp has an independent cache file.
type resultCache struct {
	path             string
	root             string
	dir              string
	build            string
	stamp            string
	keyDescription   string
	ruleFingerprints map[string]string
	// previous is what the last run stored, by path relative to the root.
	previous map[string]cacheEntry
	loaded   bool
	// current is what this run stores: only the files it analyzed, so files
	// that are gone drop out.
	current map[string]cacheEntry
	reused  int

	// The project findings are stored for the inputs of the typed load
	// (core.GoProjectLoader.GoInputs); projectKeyed is false when this run
	// could not identify them, and nothing is stored then.
	previousProject      *projectEntry
	projectInputs        string
	projectPath          string
	projectScope         string
	projectRules         []string
	projectFingerprints  map[string]string
	projectKeyed         bool
	projectHit           *projectEntry
	currentProject       *projectEntry
	projectRulesCached   int
	projectRulesRerun    int
	rootMiss             string
	projectMiss          string
	rootFingerprint      string
	rootRuleFindings     map[string]map[string][]core.Violation
	rootRuleFingerprints map[string]string
	rootRuleHits         map[string]bool
	rootContentHashes    map[string][sha256.Size]byte
	rootRunComplete      bool
	scopeSpecific        bool
	rootScopeComplete    bool
}

// projectEntry holds the findings of the project rules, filtered like every
// finding, the names of the rules that produced them, and the packages the
// load left out.
type projectEntry struct {
	Inputs            string
	Scope             string
	Rules             []string
	Fingerprints      map[string]string
	Violations        map[string][]core.Violation
	Skipped           []core.SkippedPackage
	RuleState         map[string][]byte
	StateFingerprints map[string]string
	RootFingerprint   string
	RootRules         map[string]string
	RootViolations    map[string]map[string][]core.Violation
}

type cacheEntry struct {
	Content        [sha256.Size]byte
	Fingerprints   map[string]string
	FingerprintSet int
	// Findings by rule name, after exceptions, suppression and severity
	// overrides — all of which the file and the stamp decide.
	Rules map[string][]core.Violation
}

type cacheContents struct {
	Stamp           string
	Entries         map[string]cacheEntry
	Project         *projectEntry
	FingerprintSets []map[string]string
}

// openRootCache opens the result cache of a root walked over scopes: a run
// over other scopes stores other files, so it keeps a cache of its own. A cache that cannot be used is reported and the root is analyzed
// in full: the cache only saves time, it never decides a finding.
func openRootCache(root string, scopes []string, cfg *core.Config, goTreesFromLoader bool) *resultCache {
	seed, err := mainWorktreeKey(root, scopes)
	var cache *resultCache
	if err == nil {
		cache, err = newRootCache(strings.Join(append([]string{root}, scopes...), "\n"), seed, cfg, goTreesFromLoader)
		if err == nil {
			cache.scopeSpecific = len(scopes) > 0
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: result cache off for %s: %v\n", root, err)
		return nil
	}
	return cache
}

// mainWorktreeKey returns the cache key of the root and scopes in the main
// worktree when the root is in a linked worktree, else "".
func mainWorktreeKey(root string, scopes []string) (string, error) {
	paths := append([]string{root}, scopes...)
	for i, path := range paths {
		mainPath, ok, err := core.MainWorktreePath(path)
		if err != nil || !ok {
			return "", err
		}
		paths[i] = mainPath
	}
	return strings.Join(paths, "\n"), nil
}

func newRootCache(root, seed string, cfg *core.Config, goTreesFromLoader bool) (*resultCache, error) {
	dir, err := resultCacheDir()
	if err != nil {
		return nil, err
	}
	key, err := cacheBuildKey()
	if err != nil {
		return nil, err
	}
	stamp, err := cacheStamp(cfg, goTreesFromLoader, flagTolerant, key.core)
	if err != nil {
		return nil, err
	}
	cache, err := openResultCache(dir, root, seed, key.core, stamp)
	if err == nil {
		cache.ruleFingerprints = key.packages
		cache.keyDescription = key.description
	}
	return cache, err
}

type resultCacheKey struct {
	core        string
	packages    map[string]string
	description string
}

func cacheBuildKey() (resultCacheKey, error) {
	manifest := cacheKeyManifest()
	if manifest.trusted {
		return resultCacheKey{
			core:        manifest.core,
			packages:    manifest.packages,
			description: fmt.Sprintf("result cache key: rule fingerprints (core %s)", manifest.core),
		}, nil
	}
	binary, err := executableHash()
	if err != nil {
		return resultCacheKey{}, err
	}
	core := buildTag(binary)
	return resultCacheKey{
		core:        core,
		packages:    map[string]string{},
		description: fmt.Sprintf("result cache key: binary hash %s (build without verified fingerprints)", core),
	}, nil
}

// buildTag is the part of a glint build's hash that names its caches.
func buildTag(build string) string {
	const tagLength = 16
	return build[:min(len(build), tagLength)]
}

// openResultCache reads the cache of root from dir, named after the root and
// the build: a cache of another build can never match its stamp. A cache
// written under another stamp is ignored, a missing one starts from the
// file entries of the cache of seed - the root in the main worktree, for a
// root in a fresh worktree of the same repository: they are keyed by
// relative path and content, so the files the worktree did not change are
// reused - or empty. A cache that is read is marked used (its mtime), which the size
// limit of pruneResultCaches goes by.
func openResultCache(dir, root, seed, build, stamp string) (*resultCache, error) {
	cache := &resultCache{
		path:             stampedResultCachePath(dir, root, build, stamp),
		root:             root,
		dir:              dir,
		build:            build,
		stamp:            stamp,
		ruleFingerprints: make(map[string]string),
		previous:         make(map[string]cacheEntry),
		current:          make(map[string]cacheEntry),
	}
	found, err := cache.read(cache.path)
	if !found && err == nil {
		cache.rootMiss = "file"
		stampMiss := false
		matches, err := filepath.Glob(filepath.Join(dir, cacheRootPrefix(root)+"-*.gob"))
		if err != nil {
			return nil, fmt.Errorf("list result caches of the root: %w", err)
		}
		for _, match := range matches {
			name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(match), cacheRootPrefix(root)+"-"), ".gob")
			if name == filepath.Base(match) || name == "" {
				continue
			}
			base := filepath.Base(match)
			if !cacheBuildMatches(base, build) {
				cache.rootMiss = "build"
				break
			}
			if strings.Contains(base, "-"+build+"-s") {
				stampMiss = true
			}
		}
		if cache.rootMiss != "build" && stampMiss {
			cache.rootMiss = "stamp"
		}
	} else if found && err == nil && !cache.loaded {
		cache.rootMiss = "stamp"
	}
	if !found && err == nil && seed != "" {
		_, err = cache.read(stampedResultCachePath(dir, seed, build, stamp))
		// The project findings of the main worktree went by its files
		// outside git too, which a fresh worktree lacks.
		cache.previousProject = nil
	}
	if err != nil {
		return nil, err
	}
	return cache, nil
}

func stampedResultCachePath(dir, root, build, stamp string) string {
	name := sha256.Sum256([]byte(root))
	stampHash := sha256.Sum256([]byte(stamp))
	return filepath.Join(dir, hex.EncodeToString(name[:])+"-"+build+"-s"+hex.EncodeToString(stampHash[:])+".gob")
}

func cacheRootPrefix(root string) string {
	name := sha256.Sum256([]byte(root))
	return hex.EncodeToString(name[:])
}

func projectCachePath(dir, root, build, inputs string) string {
	rootHash := sha256.Sum256([]byte(root))
	inputHash := sha256.Sum256([]byte(inputs))
	return filepath.Join(dir, hex.EncodeToString(rootHash[:])+"-"+build+"-p"+hex.EncodeToString(inputHash[:])+".gob")
}

func (c *resultCache) readProject(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read project result cache: %w", err)
	}
	var entry projectEntry
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&entry); err != nil {
		return false, fmt.Errorf("decode project result cache: %w", err)
	}
	c.previousProject = &entry
	now := time.Now()
	if err := os.Chtimes(path, now, now); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("mark project result cache used: %w", err)
	}
	return true, nil
}

func (c *resultCache) loadProject(path string) {
	c.projectPath = path
	c.previousProject = nil
	if _, err := c.readProject(path); err != nil {
		fmt.Fprintf(os.Stderr, "warning: project result cache %s not used: %v\n", path, err)
		c.projectMiss = "corrupt"
		c.previousProject = nil
	} else if c.previousProject == nil {
		c.projectMiss = "inputs"
	}
}

// read takes the entries of the cache file at path when its stamp matches;
// found is false when there is no such file.
func (c *resultCache) read(path string) (found bool, err error) {
	// The file is replaced by rename and removed whole, so a read sees one
	// complete version or none: a cache another run pruned meanwhile is a
	// missing one.
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read result cache: %w", err)
	}
	var stored cacheContents
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&stored); err != nil {
		return false, fmt.Errorf("decode result cache %s: %w", path, err)
	}
	if err := expandCacheFingerprints(&stored); err != nil {
		return false, fmt.Errorf("decode result cache %s: %w", path, err)
	}
	if stored.Stamp == c.stamp {
		c.previous = stored.Entries
		c.previousProject = stored.Project
		c.loaded = true
		now := time.Now()
		if err := os.Chtimes(path, now, now); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("mark result cache used: %w", err)
		}
	}
	return true, nil
}

// lookup returns the stored findings of an unchanged file, by rule name.
func (c *resultCache) lookup(relPath string, content [sha256.Size]byte, fingerprints map[string]string) map[string][]core.Violation {
	entry, ok := c.previous[relPath]
	if !ok || entry.Content != content {
		return nil
	}
	found := make(map[string][]core.Violation)
	for name, values := range entry.Rules {
		if fingerprints[name] != "" && entry.Fingerprints[name] == fingerprints[name] {
			found[name] = values
		}
	}
	return found
}

// store records the findings of one file for the next run. A run with a
// partial rule set keeps findings from rules it did not execute.
func (c *resultCache) store(relPath string, content [sha256.Size]byte, found map[string][]core.Violation, fingerprints map[string]string) {
	merged := make(map[string][]core.Violation, len(found))
	mergedFingerprints := make(map[string]string, len(found))
	if old, ok := c.previous[relPath]; ok && old.Content == content && !c.rootRunComplete {
		maps.Copy(merged, old.Rules)
		maps.Copy(mergedFingerprints, old.Fingerprints)
	}
	maps.Copy(merged, found)
	maps.Copy(mergedFingerprints, fingerprints)
	c.current[relPath] = cacheEntry{Content: content, Rules: merged, Fingerprints: mergedFingerprints}
}

// keyProject records the inputs of this run's typed load and the project
// rules it runs (sorted names), and returns stored project findings when they
// were computed by the same rules for the same inputs and an equal or broader scope.
func (c *resultCache) keyProject(inputs string, projectRules []string, enabled []rules.Rule, scope string) *projectEntry {
	c.projectHit = nil
	c.projectInputs, c.projectScope, c.projectRules, c.projectKeyed = inputs, scope, projectRules, true
	c.projectRulesCached, c.projectRulesRerun = 0, len(projectRules)
	c.projectFingerprints = make(map[string]string, len(projectRules))
	projectNames := make(map[string]bool, len(projectRules))
	for _, name := range projectRules {
		projectNames[name] = true
	}
	for _, rule := range enabled {
		if _, indexes := rule.(rules.ProjectFilesRule); indexes {
			// A project-files rule can build or consume a cached index. Keep its
			// code in the project key even when it has no findings of its own.
			c.projectFingerprints[rule.Name()] = c.fingerprint(rule)
		}
	}
	for _, rule := range enabled {
		if projectNames[rule.Name()] {
			c.projectFingerprints[rule.Name()] = c.fingerprint(rule)
		}
	}
	var indexDependencies []string
	for _, rule := range enabled {
		_, indexes := rule.(rules.ProjectFilesRule)
		_, analyzesProject := rule.(rules.GoProjectRule)
		if indexes || analyzesProject {
			indexDependencies = append(indexDependencies, rule.Name()+"="+c.projectFingerprints[rule.Name()])
		}
	}
	slices.Sort(indexDependencies)
	for _, rule := range enabled {
		if !projectNames[rule.Name()] {
			continue
		}
		fingerprint := c.fingerprint(rule)
		if _, ok := rule.(rules.GoProjectRule); ok {
			dependencies := fingerprint + "\n" + strings.Join(indexDependencies, "\n")
			sum := sha256.Sum256([]byte(dependencies))
			fingerprint = buildTag(hex.EncodeToString(sum[:]))
		}
		c.projectFingerprints[rule.Name()] = fingerprint
	}
	if c.dir != "" {
		c.loadProject(projectCachePath(c.dir, c.root, c.build, inputs))
	}
	if c.previousProject != nil && c.previousProject.Inputs == inputs && c.previousProject.Scope != scope && c.previousProject.Scope != "" {
		c.projectMiss = "scope"
	} else if c.previousProject != nil && c.previousProject.Inputs == inputs {
		c.projectHit = c.previousProject
		c.currentProject = c.previousProject
		c.projectRulesRerun = 0
		for _, name := range projectRules {
			previous, previousOK := c.previousProject.Fingerprints[name]
			current, currentOK := c.projectFingerprints[name]
			if previousOK && currentOK && previous == current {
				c.projectRulesCached++
			} else {
				c.projectRulesRerun++
			}
		}
		if c.projectRulesRerun > 0 {
			c.projectMiss = "rules"
		} else {
			c.projectMiss = ""
		}
	} else if c.previousProject != nil {
		c.projectMiss = "rules"
	}
	return c.projectHit
}

func (c *resultCache) projectRuleReusable(rule rules.Rule) bool {
	if c.projectHit == nil || c.projectHit.Fingerprints[rule.Name()] != c.projectFingerprints[rule.Name()] {
		return false
	}
	return true
}

func (c *resultCache) projectFindings(enabled []rules.Rule) []core.Violation {
	if c.projectHit == nil {
		return nil
	}
	var found []core.Violation
	for _, rule := range enabled {
		if _, ok := rule.(rules.GoProjectRule); !ok || !c.projectRuleReusable(rule) {
			continue
		}
		found = append(found, c.projectHit.Violations[rule.Name()]...)
	}
	return found
}

func (c *resultCache) projectStateReusable(rule rules.Rule) bool {
	return c.projectHit != nil && c.projectHit.RuleState[rule.Name()] != nil && c.projectHit.StateFingerprints[rule.Name()] == c.fingerprint(rule)
}

// keyRootFiles binds project-file findings to the exact loaded root inputs.
// Hashes are supplied by the caller so files are never reread for this key.
func (c *resultCache) keyRootFiles(files []*core.FileContext, hashes map[string][sha256.Size]byte, enabled []rules.Rule) {
	c.rootContentHashes = hashes
	type rootFileDigest struct {
		path string
		hash [sha256.Size]byte
	}
	entries := make([]rootFileDigest, 0, len(files))
	for _, file := range files {
		entries = append(entries, rootFileDigest{path: file.RelPath, hash: hashes[file.RelPath]})
	}
	slices.SortFunc(entries, func(a, b rootFileDigest) int { return strings.Compare(a.path, b.path) })
	hasher := sha256.New()
	for _, entry := range entries {
		_, _ = hasher.Write([]byte(entry.path))
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write(entry.hash[:])
	}
	c.rootFingerprint = hex.EncodeToString(hasher.Sum(nil))
	if c.projectPath == "" && c.dir != "" {
		c.projectInputs = "root:" + c.rootFingerprint
		c.loadProject(projectCachePath(c.dir, c.root, c.build, c.projectInputs))
	}
	c.rootRuleFindings = make(map[string]map[string][]core.Violation)
	c.rootRuleFingerprints = make(map[string]string)
	c.rootRuleHits = make(map[string]bool)
	for _, rule := range enabled {
		if !rootProjectRuleCacheable(rule) {
			continue
		}
		fingerprint := c.fingerprint(rule)
		if input, ok := rule.(rules.RootFilesAndCacheInputs); ok {
			if len(files) == 0 {
				continue
			}
			value, err := input.CacheInputs(files[0].ProjectRoot)
			if err != nil {
				if flagTiming || flagVerbose {
					fmt.Fprintf(os.Stderr, "result cache: %s inputs unavailable: %v\n", rule.Name(), err)
				}
				continue
			}
			sum := sha256.Sum256([]byte(fingerprint + "\x00" + value))
			fingerprint = hex.EncodeToString(sum[:])
		}
		c.rootRuleFingerprints[rule.Name()] = fingerprint
	}
	if c.previousProject == nil || c.previousProject.RootFingerprint != c.rootFingerprint {
		return
	}
	for _, rule := range enabled {
		if !rootProjectRuleCacheable(rule) {
			continue
		}
		fingerprint := c.rootRuleFingerprints[rule.Name()]
		if fingerprint == "" || c.previousProject.RootRules[rule.Name()] != fingerprint {
			continue
		}
		c.rootRuleHits[rule.Name()] = true
		c.rootRuleFindings[rule.Name()] = c.previousProject.RootViolations[rule.Name()]
	}
}

func (c *resultCache) rootRuleReusable(rule rules.Rule) bool {
	return c.rootRuleHits[rule.Name()]
}

func (c *resultCache) rootRuleFindingsFor(rule rules.Rule, contexts []*core.FileContext) core.ViolationList {
	var found core.ViolationList
	for _, ctx := range contexts {
		violations := c.rootRuleFindings[rule.Name()][ctx.RelPath]
		for i := range violations {
			found = append(found, &violations[i])
		}
	}
	return found
}

// rootProjectRuleCacheable is the audited allow policy for project-file
// rules. Most indexes are pure functions of the supplied root contexts and
// configuration. These exceptions have additional machine or disk inputs.
func rootProjectRuleCacheable(rule rules.Rule) bool {
	if _, ok := rule.(rules.ProjectFilesRule); !ok {
		return false
	}
	_, keyed := rule.(rules.RootFilesAndCacheInputs)
	if _, ok := rule.(rules.RootFilesOnlyProjectFiles); !ok && !keyed {
		return false
	}
	if reader, ok := rule.(rules.ReadsOtherFiles); ok && reader.ReadsOtherFiles() && !keyed {
		return false
	}
	if _, ok := rule.(rules.ExternalToolRule); ok {
		return false
	}
	_, excluded := rule.(rules.ProjectFilesCacheExclusion)
	return !excluded
}

// storeProject records the project findings of this run's load.
func (c *resultCache) storeProject(found core.ViolationList, skipped []core.SkippedPackage, ruleState map[string][]byte) {
	if !c.projectEntryComplete() {
		return
	}
	violations := make(map[string][]core.Violation)
	active := make(map[string]bool)
	for _, name := range c.projectRules {
		active[name] = true
	}
	for _, violation := range found {
		if active[violation.Rule] {
			violations[violation.Rule] = append(violations[violation.Rule], *violation)
		}
	}
	stateFingerprints := make(map[string]string)
	for name := range ruleState {
		stateFingerprints[name] = c.projectFingerprints[name]
	}
	fingerprints := maps.Clone(c.projectFingerprints)
	rootFingerprint, rootRules, rootViolations := c.rootFingerprint, c.rootRuleFingerprints, c.rootRuleFindings
	if !c.rootRunComplete && c.previousProject != nil {
		rootFingerprint, rootRules, rootViolations = c.previousProject.RootFingerprint, c.previousProject.RootRules, c.previousProject.RootViolations
	}
	c.currentProject = &projectEntry{
		Inputs:            c.projectInputs,
		Scope:             c.projectScope,
		Rules:             c.projectRules,
		Fingerprints:      fingerprints,
		Violations:        violations,
		Skipped:           append([]core.SkippedPackage(nil), skipped...),
		RuleState:         ruleState,
		StateFingerprints: stateFingerprints,
		RootFingerprint:   rootFingerprint,
		RootRules:         rootRules,
		RootViolations:    rootViolations,
	}
}

// projectEntryComplete reports whether this run covers the project entry's
// full scope and rule set, so it may replace that entry.
func (c *resultCache) projectEntryComplete() bool {
	if !c.projectKeyed || c.projectScope != "" {
		return false
	}
	return c.previousProject == nil || c.previousProject.Inputs != c.projectInputs || !projectRulesAreSubset(c.projectRules, c.previousProject.Rules)
}

func projectRulesAreSubset(current, previous []string) bool {
	if len(current) >= len(previous) {
		return false
	}
	previousSet := make(map[string]bool, len(previous))
	for _, name := range previous {
		previousSet[name] = true
	}
	for _, name := range current {
		if !previousSet[name] {
			return false
		}
	}
	return true
}

// storeRootProjectResults keeps results for a complete root or an isolated
// scope. Other partial runs leave the previous complete record untouched.
func (c *resultCache) storeRootProjectResults(found map[string]core.ViolationList) {
	if (!c.rootRunComplete && !c.rootScopeComplete) || c.rootFingerprint == "" {
		return
	}
	entry := c.currentProject
	if entry == nil && c.previousProject != nil {
		copy := *c.previousProject
		entry = &copy
	}
	if entry == nil {
		entry = &projectEntry{}
	}
	rootRules := make(map[string]string)
	rootViolations := make(map[string]map[string][]core.Violation)
	if previous := c.previousProject; previous != nil && previous.RootFingerprint == c.rootFingerprint {
		maps.Copy(rootRules, previous.RootRules)
		maps.Copy(rootViolations, previous.RootViolations)
	}
	for name, findings := range c.rootRuleFindings {
		if !c.rootRuleHits[name] {
			continue
		}
		rootViolations[name] = findings
		rootRules[name] = c.rootRuleFingerprints[name]
	}
	for name, violations := range found {
		byFile := make(map[string][]core.Violation)
		for _, violation := range violations {
			byFile[violation.File] = append(byFile[violation.File], *violation)
		}
		rootViolations[name] = byFile
		rootRules[name] = c.fingerprintByName(name)
	}
	entry.RootRules = rootRules
	entry.RootViolations = rootViolations
	entry.RootFingerprint = c.rootFingerprint
	c.currentProject = entry
}

func (c *resultCache) fingerprintByName(name string) string {
	if fingerprint := c.rootRuleFingerprints[name]; fingerprint != "" {
		return fingerprint
	}
	return c.build
}

// projectState describes for --timing where the project findings came from.
func (c *resultCache) projectState() string {
	return fmt.Sprintf("%d cached, %d rerun", c.projectRulesCached, c.projectRulesRerun)
}

// storeFile records the findings of a file's file-local rules and counts the
// file as reused when every one of them came from the cache.
func (c *resultCache) storeFile(relPath string, content [sha256.Size]byte, list []rules.Rule, local []bool, found []core.ViolationList, reused map[string][]core.Violation, keys map[string]string) {
	stored := make(map[string][]core.Violation)
	fingerprints := make(map[string]string)
	allReused := true
	for i, rule := range list {
		if !local[i] {
			continue
		}
		stored[rule.Name()] = found[i].Values()
		fingerprints[rule.Name()] = keys[rule.Name()]
		if _, ok := reused[rule.Name()]; !ok {
			allReused = false
		}
	}
	if allReused {
		c.reused++
	}
	c.store(relPath, content, stored, fingerprints)
}

// save writes this run's entries. The file is replaced atomically, so a
// concurrent run reads either the old cache or the new one.
func (c *resultCache) save() error {
	project := c.currentProject
	entries := maps.Clone(c.current)
	if c.loaded && !c.rootRunComplete {
		for path, previous := range c.previous {
			if _, updated := entries[path]; !updated {
				entries[path] = previous
			}
		}
	}
	contents := cacheContents{Stamp: c.stamp, Entries: entries}
	rootChanged := !c.loaded || !cacheContentsEqual(contents, cacheContents{Stamp: c.stamp, Entries: c.previous})
	if !rootChanged {
		now := time.Now()
		err := os.Chtimes(c.path, now, now)
		// A file another run pruned meanwhile is written anew.
		rootChanged = errors.Is(err, fs.ErrNotExist)
		if err != nil && !rootChanged {
			return fmt.Errorf("mark result cache used: %w", err)
		}
	}
	if rootChanged {
		contents = compactCacheFingerprints(contents)
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(contents); err != nil {
			return fmt.Errorf("encode result cache: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
			return fmt.Errorf("create result cache directory: %w", err)
		}
		tmp, err := os.CreateTemp(filepath.Dir(c.path), tempCachePrefix+"*")
		if err != nil {
			return fmt.Errorf("create result cache: %w", err)
		}
		_, err = tmp.Write(buf.Bytes())
		err = errors.Join(err, tmp.Close())
		if err == nil {
			err = os.Rename(tmp.Name(), c.path)
		}
		if err != nil {
			return errors.Join(fmt.Errorf("write result cache: %w", err), os.Remove(tmp.Name()))
		}
	}
	projectChanged := project != nil && c.projectPath != "" && (c.previousProject == nil || !projectEntriesEqual(*project, *c.previousProject))
	if !projectChanged && project != nil && c.projectPath != "" {
		if _, err := os.Stat(c.projectPath); errors.Is(err, fs.ErrNotExist) {
			projectChanged = true
		} else if err != nil {
			return fmt.Errorf("stat project result cache: %w", err)
		}
	}
	if projectChanged {
		if err := writeProjectCache(c.projectPath, *project); err != nil {
			return err
		}
	}
	return c.prune()
}

func writeProjectCache(path string, entry projectEntry) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(entry); err != nil {
		return fmt.Errorf("encode project result cache: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create result cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), tempCachePrefix+"*")
	if err != nil {
		return fmt.Errorf("create project result cache: %w", err)
	}
	_, err = tmp.Write(buf.Bytes())
	err = errors.Join(err, tmp.Close())
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("write project result cache: %w", err), os.Remove(tmp.Name()))
	}
	now := time.Now()
	if err := os.Chtimes(path, now, now); err != nil {
		return fmt.Errorf("mark project result cache used: %w", err)
	}
	return pruneProjectCacheVariants(path)
}

func projectEntriesEqual(a, b projectEntry) bool {
	return cacheValuesEqual(reflect.ValueOf(a), reflect.ValueOf(b))
}

func pruneProjectCacheVariants(path string) error {
	base := filepath.Base(path)
	marker := strings.LastIndex(base, "-p")
	if marker < 0 || filepath.Ext(base) != ".gob" {
		return nil
	}
	prefix := base[:marker+2]
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list project result caches: %w", err)
	}
	type projectCacheFile struct {
		path    string
		name    string
		modTime time.Time
	}
	var files []projectCacheFile
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".gob" || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat project result cache %s: %w", entry.Name(), err)
		}
		files = append(files, projectCacheFile{path: filepath.Join(dir, entry.Name()), name: entry.Name(), modTime: info.ModTime()})
	}
	slices.SortFunc(files, func(a, b projectCacheFile) int {
		if cmp := b.modTime.Compare(a.modTime); cmp != 0 {
			return cmp
		}
		if a.path == path {
			return -1
		}
		if b.path == path {
			return 1
		}
		return strings.Compare(b.name, a.name)
	})
	if len(files) <= maxProjectCacheVariants {
		return nil
	}
	for _, file := range files[maxProjectCacheVariants:] {
		// A variant another run wrote or read moments ago may be in use.
		if time.Since(file.modTime) <= defaultCacheLimits.grace {
			continue
		}
		if err := os.Remove(file.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove old project result cache %s: %w", file.name, err)
		}
	}
	return nil
}

// cacheContentsEqual compares the stored data while treating nil and empty
// slices as the same content. Gob decodes empty slices as nil, and both have
// identical cache semantics.
func cacheContentsEqual(a, b cacheContents) bool {
	return cacheValuesEqual(reflect.ValueOf(a), reflect.ValueOf(b))
}

func cacheValuesEqual(a, b reflect.Value) bool {
	if !a.IsValid() || !b.IsValid() {
		return a.IsValid() == b.IsValid()
	}
	if a.Type() != b.Type() {
		return false
	}
	switch a.Kind() {
	case reflect.Interface, reflect.Pointer:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return cacheValuesEqual(a.Elem(), b.Elem())
	case reflect.Slice:
		if a.Len() == 0 || b.Len() == 0 {
			return a.Len() == b.Len()
		}
		if a.Len() != b.Len() {
			return false
		}
		for i := 0; i < a.Len(); i++ {
			if !cacheValuesEqual(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Map:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		if a.Len() != b.Len() {
			return false
		}
		iter := a.MapRange()
		for iter.Next() {
			other := b.MapIndex(iter.Key())
			if !other.IsValid() || !cacheValuesEqual(iter.Value(), other) {
				return false
			}
		}
		return true
	case reflect.Array:
		for i := 0; i < a.Len(); i++ {
			if !cacheValuesEqual(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			if !cacheValuesEqual(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a.Interface(), b.Interface())
	}
}

// compactCacheFingerprints stores each distinct rule fingerprint map once.
// File entries often have the same map, and repeating it for every file made
// the gob grow with the number of files despite identical metadata.
func compactCacheFingerprints(contents cacheContents) cacheContents {
	sets := make([]map[string]string, 0)
	byHash := make(map[[sha256.Size]byte][]int)
	entries := make(map[string]cacheEntry, len(contents.Entries))
	paths := slices.Sorted(maps.Keys(contents.Entries))
	for _, path := range paths {
		entry := contents.Entries[path]
		hash := fingerprintSetHash(entry.Fingerprints)
		setIndex := -1
		for _, candidate := range byHash[hash] {
			if reflect.DeepEqual(sets[candidate], entry.Fingerprints) {
				setIndex = candidate
				break
			}
		}
		if setIndex < 0 {
			setIndex = len(sets)
			sets = append(sets, maps.Clone(entry.Fingerprints))
			byHash[hash] = append(byHash[hash], setIndex)
		}
		entry.Fingerprints = nil
		entry.FingerprintSet = setIndex
		entries[path] = entry
	}
	contents.Entries = entries
	contents.FingerprintSets = sets
	return contents
}

func expandCacheFingerprints(contents *cacheContents) error {
	if len(contents.FingerprintSets) == 0 {
		return nil
	}
	for path, entry := range contents.Entries {
		if entry.FingerprintSet < 0 || entry.FingerprintSet >= len(contents.FingerprintSets) {
			return fmt.Errorf("file %q has invalid fingerprint set %d", path, entry.FingerprintSet)
		}
		entry.Fingerprints = contents.FingerprintSets[entry.FingerprintSet]
		entry.FingerprintSet = 0
		contents.Entries[path] = entry
	}
	contents.FingerprintSets = nil
	return nil
}

func fingerprintSetHash(fingerprints map[string]string) [sha256.Size]byte {
	keys := slices.Sorted(maps.Keys(fingerprints))
	hasher := sha256.New()
	var size [binary.MaxVarintLen64]byte
	for _, key := range keys {
		keySize := binary.PutUvarint(size[:], uint64(len(key)))
		_, _ = hasher.Write(size[:keySize])
		_, _ = hasher.Write([]byte(key))
		value := fingerprints[key]
		valueSize := binary.PutUvarint(size[:], uint64(len(value)))
		_, _ = hasher.Write(size[:valueSize])
		_, _ = hasher.Write([]byte(value))
	}
	var sum [sha256.Size]byte
	copy(sum[:], hasher.Sum(nil))
	return sum
}

func (c *resultCache) prune() error {
	if !pruned.CompareAndSwap(false, true) {
		return nil
	}
	return pruneResultCaches(filepath.Dir(c.path), time.Now(), c.build, defaultCacheLimits)
}

// pruned is set once a run has pruned the cache directory: once per run is
// enough, however many roots it saves.
var pruned atomic.Bool

// cacheLimits bound the cache directory.
type cacheLimits struct {
	// maxAge is how long a cache nobody reads or writes stays.
	maxAge time.Duration
	// grace protects files touched this recently from every rule but maxAge:
	// another run may be writing or reading them right now.
	grace time.Duration
	// maxBytes caps the caches of this build; the least recently used go.
	maxBytes   int64
	foreignAge time.Duration
}

var defaultCacheLimits = cacheLimits{maxAge: 7 * 24 * time.Hour, grace: 10 * time.Minute, maxBytes: 1 << 30, foreignAge: 24 * time.Hour}

// tempCachePrefix starts the temporary file a save writes before renaming it.
const tempCachePrefix = ".results-"

// pruneResultCaches bounds the cache directory: see pruneCacheEntries.
func pruneResultCaches(dir string, now time.Time, build string, limits cacheLimits) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list result caches: %w", err)
	}
	return pruneCacheEntries(dir, entries, now, build, limits)
}

// pruneCacheEntries removes the caches no run of this build can use — those
// of another build or of the layout without a build in the name — and the
// temporary files of crashed saves, once they are older than the grace
// period; any cache unused for maxAge; then the least recently used caches of
// this build until the rest fit maxBytes. A file another run removed first is
// no error.
func pruneCacheEntries(dir string, entries []fs.DirEntry, now time.Time, build string, limits cacheLimits) error {
	type cacheFile struct {
		path string
		info fs.FileInfo
	}
	var caches []cacheFile
	var errs []error
	remove := func(path string) {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		cache := filepath.Ext(name) == ".gob"
		if entry.IsDir() || (!cache && !strings.HasPrefix(name, tempCachePrefix)) {
			continue
		}
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		path := filepath.Join(dir, name)
		age := now.Sub(info.ModTime())
		switch {
		case age > limits.maxAge:
			remove(path)
		case !cache:
			if age > limits.grace {
				remove(path)
			}
		default:
			if !cacheBuildMatches(name, build) && age > limits.foreignAge {
				remove(path)
				continue
			}
			caches = append(caches, cacheFile{path: path, info: info})
		}
	}
	var total int64
	for _, file := range caches {
		total += file.info.Size()
	}
	slices.SortFunc(caches, func(a, b cacheFile) int {
		aOwn := cacheBuildMatches(filepath.Base(a.path), build)
		bOwn := cacheBuildMatches(filepath.Base(b.path), build)
		if aOwn != bOwn {
			if aOwn {
				return 1
			}
			return -1
		}
		return a.info.ModTime().Compare(b.info.ModTime())
	})
	for _, file := range caches {
		if total <= limits.maxBytes {
			break
		}
		if now.Sub(file.info.ModTime()) <= limits.grace {
			continue
		}
		remove(file.path)
		total -= file.info.Size()
	}
	return errors.Join(errs...)
}

func cacheBuildMatches(name, build string) bool {
	return strings.HasSuffix(name, "-"+build+".gob") || strings.Contains(name, "-"+build+"-s") || strings.Contains(name, "-"+build+"-p")
}

// resultCacheDir is where the caches of all roots live.
func resultCacheDir() (string, error) {
	if dir := os.Getenv("GLINT_CACHE_DIR"); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("GLINT_CACHE_DIR must be an absolute path: %q", dir)
		}
		return dir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate the user cache directory: %w", err)
	}
	return filepath.Join(base, "glint", "results"), nil
}

// cacheStamp identifies everything besides the file that a file-local finding
// depends on. Go trees parsed by the project loader skip object resolution,
// trees parsed by the walker do not, so their origin is part of it.
func cacheStamp(cfg *core.Config, goTreesFromLoader, tolerant bool, coreFingerprint string) (string, error) {
	// The severity filter, the failure threshold and the output format apply
	// to the findings after analysis, so they stay out of the stamp.
	analysis := *cfg
	analysis.Settings.MinSeverity, analysis.Settings.FailOn, analysis.Settings.Output = "", "", ""
	config, err := yaml.Marshal(&analysis)
	if err != nil {
		return "", fmt.Errorf("serialize configuration for the result cache: %w", err)
	}
	header := fmt.Sprintf("%s\n%s\nloader=%t tolerant=%t\n", cacheFormat, coreFingerprint, goTreesFromLoader, tolerant)
	sum := sha256.Sum256(append([]byte(header), config...))
	return hex.EncodeToString(sum[:]), nil
}

func (c *resultCache) fingerprint(rule rules.Rule) string {
	t := reflect.TypeOf(rule)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t != nil && c.ruleFingerprints[t.PkgPath()] != "" {
		return c.ruleFingerprints[t.PkgPath()]
	}
	return c.build
}

func (c *resultCache) fingerprints(list []rules.Rule) map[string]string {
	fingerprints := make(map[string]string, len(list))
	for _, rule := range list {
		fingerprints[rule.Name()] = c.fingerprint(rule)
	}
	return fingerprints
}

// executableHash returns the process-wide executable hash shared with analysis rules.
var executableHash = toolcache.ExecutableHash

// fileLocalRules marks the rules whose findings the cache may keep.
func fileLocalRules(list []rules.Rule) []bool {
	local := make([]bool, len(list))
	for i, rule := range list {
		local[i] = rules.FileLocal(rule)
	}
	return local
}

func sameRootRuleNames(enabled, configured []rules.Rule) bool {
	rootRule := func(rule rules.Rule) bool {
		return rules.FileLocal(rule) || rootProjectRuleCacheable(rule)
	}
	enabledNames := make(map[string]bool)
	for _, rule := range enabled {
		if rootRule(rule) {
			enabledNames[rule.Name()] = true
		}
	}
	configuredNames := make(map[string]bool)
	for _, rule := range configured {
		if rootRule(rule) {
			configuredNames[rule.Name()] = true
		}
	}
	for name := range configuredNames {
		if !enabledNames[name] {
			return false
		}
	}
	return true
}
