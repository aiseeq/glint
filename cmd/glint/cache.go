package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// cacheFormat changes whenever the stored layout does.
const cacheFormat = "glint-results-4"

// resultCache keeps the findings of file-local rules (rules.FileLocal) per
// file of one project root between runs. A file whose content is unchanged
// gets them back instead of being analyzed again: between two commits most
// files are.
//
// The stamp covers everything else a file-local finding depends on: the glint
// build, the configuration, where the Go syntax trees came from and the
// tolerance flag. A different stamp discards the whole cache.
type resultCache struct {
	path  string
	build string
	stamp string
	// previous is what the last run stored, by path relative to the root.
	previous map[string]cacheEntry
	// current is what this run stores: only the files it analyzed, so files
	// that are gone drop out.
	current map[string]cacheEntry
	reused  int

	// The project findings are stored for the inputs of the typed load
	// (core.GoProjectLoader.GoInputs); projectKeyed is false when this run
	// could not identify them, and nothing is stored then.
	previousProject *projectEntry
	projectInputs   string
	projectRules    []string
	projectKeyed    bool
	projectHit      *projectEntry
	currentProject  *projectEntry
}

// projectEntry holds the findings of the project rules, filtered like every
// finding, the names of the rules that produced them, and the packages the
// load left out.
type projectEntry struct {
	Inputs     string
	Rules      []string
	Violations []core.Violation
	Skipped    []core.SkippedPackage
	RuleState  map[string][]byte
}

type cacheEntry struct {
	Content [sha256.Size]byte
	// Findings by rule name, after exceptions, suppression and severity
	// overrides — all of which the file and the stamp decide.
	Rules map[string][]core.Violation
}

type cacheContents struct {
	Stamp   string
	Entries map[string]cacheEntry
	Project *projectEntry
}

// openRootCache opens the result cache of a root walked over scopes: a run
// over other scopes stores other files, so it keeps a cache of its own. A cache that cannot be used is reported and the root is analyzed
// in full: the cache only saves time, it never decides a finding.
func openRootCache(root string, scopes []string, cfg *core.Config, goTreesFromLoader bool) *resultCache {
	seed, err := mainWorktreeKey(root, scopes)
	var cache *resultCache
	if err == nil {
		cache, err = newRootCache(strings.Join(append([]string{root}, scopes...), "\n"), seed, cfg, goTreesFromLoader)
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
	stamp, err := cacheStamp(cfg, goTreesFromLoader, flagTolerant)
	if err != nil {
		return nil, err
	}
	build, err := executableHash()
	if err != nil {
		return nil, err
	}
	return openResultCache(dir, root, seed, buildTag(build), stamp)
}

// buildTag is the part of a glint build's hash that names its caches.
func buildTag(build string) string {
	const tagLength = 16
	return build[:min(len(build), tagLength)]
}

// openResultCache reads the cache of root from dir, named after the root and
// the build: a cache of another build can never match its stamp. A cache
// written under another stamp is discarded, a missing one starts from the
// file entries of the cache of seed - the root in the main worktree, for a
// root in a fresh worktree of the same repository: they are keyed by
// relative path and content, so the files the worktree did not change are
// reused - or empty. A cache that is read is marked used (its mtime), which the size
// limit of pruneResultCaches goes by.
func openResultCache(dir, root, seed, build, stamp string) (*resultCache, error) {
	cache := &resultCache{
		path:     resultCachePath(dir, root, build),
		build:    build,
		stamp:    stamp,
		previous: make(map[string]cacheEntry),
		current:  make(map[string]cacheEntry),
	}
	found, err := cache.read(cache.path)
	if !found && err == nil && seed != "" {
		_, err = cache.read(resultCachePath(dir, seed, build))
		// The project findings of the main worktree went by its files
		// outside git too, which a fresh worktree lacks.
		cache.previousProject = nil
	}
	if err != nil {
		return nil, err
	}
	return cache, nil
}

func resultCachePath(dir, root, build string) string {
	name := sha256.Sum256([]byte(root))
	return filepath.Join(dir, hex.EncodeToString(name[:])+"-"+build+".gob")
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
	if stored.Stamp == c.stamp {
		c.previous = stored.Entries
		c.previousProject = stored.Project
		now := time.Now()
		if err := os.Chtimes(path, now, now); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("mark result cache used: %w", err)
		}
	}
	return true, nil
}

// lookup returns the stored findings of an unchanged file, by rule name.
func (c *resultCache) lookup(relPath string, content [sha256.Size]byte) map[string][]core.Violation {
	entry, ok := c.previous[relPath]
	if !ok || entry.Content != content {
		return nil
	}
	return entry.Rules
}

// store records the findings of one file for the next run. Rules the stored
// entry has and this run did not execute keep their findings: the content is
// the same.
func (c *resultCache) store(relPath string, content [sha256.Size]byte, found map[string][]core.Violation) {
	merged := make(map[string][]core.Violation, len(found))
	maps.Copy(merged, c.lookup(relPath, content))
	maps.Copy(merged, found)
	c.current[relPath] = cacheEntry{Content: content, Rules: merged}
}

// keyProject records the inputs of this run's typed load and the project
// rules it runs (sorted names), and returns the stored project findings when
// they were computed by the same rules for the same inputs.
func (c *resultCache) keyProject(inputs string, projectRules []string) *projectEntry {
	c.projectInputs, c.projectRules, c.projectKeyed = inputs, projectRules, true
	if c.previousProject != nil && c.previousProject.Inputs == inputs && slices.Equal(c.previousProject.Rules, projectRules) {
		c.projectHit = c.previousProject
		c.currentProject = c.previousProject
	}
	return c.projectHit
}

// storeProject records the project findings of this run's load.
func (c *resultCache) storeProject(found core.ViolationList, skipped []core.SkippedPackage, ruleState map[string][]byte) {
	if !c.projectKeyed {
		return
	}
	c.currentProject = &projectEntry{
		Inputs:     c.projectInputs,
		Rules:      c.projectRules,
		Violations: found.Values(),
		Skipped:    append([]core.SkippedPackage(nil), skipped...),
		RuleState:  ruleState,
	}
}

// projectState describes for --timing where the project findings came from.
func (c *resultCache) projectState() string {
	switch {
	case c.projectHit != nil:
		return "reused"
	case c.projectKeyed:
		return "analyzed"
	default:
		return "not cached"
	}
}

// storeFile records the findings of a file's file-local rules and counts the
// file as reused when every one of them came from the cache.
func (c *resultCache) storeFile(relPath string, content [sha256.Size]byte, list []rules.Rule, local []bool, found []core.ViolationList, reused map[string][]core.Violation) {
	stored := make(map[string][]core.Violation)
	allReused := true
	for i, rule := range list {
		if !local[i] {
			continue
		}
		stored[rule.Name()] = found[i].Values()
		if _, ok := reused[rule.Name()]; !ok {
			allReused = false
		}
	}
	if allReused {
		c.reused++
	}
	c.store(relPath, content, stored)
}

// save writes this run's entries. The file is replaced atomically, so a
// concurrent run reads either the old cache or the new one.
func (c *resultCache) save() error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(cacheContents{Stamp: c.stamp, Entries: c.current, Project: c.currentProject}); err != nil {
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
	maxBytes int64
}

var defaultCacheLimits = cacheLimits{maxAge: 7 * 24 * time.Hour, grace: 10 * time.Minute, maxBytes: 1 << 30}

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
	var own []cacheFile
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
		case !cache || !strings.HasSuffix(name, "-"+build+".gob"):
			if age > limits.grace {
				remove(path)
			}
		default:
			own = append(own, cacheFile{path: path, info: info})
		}
	}
	// Newest first: what is left once the limit is reached is the least
	// recently used.
	slices.SortFunc(own, func(a, b cacheFile) int { return b.info.ModTime().Compare(a.info.ModTime()) })
	var total int64
	for _, file := range own {
		total += file.info.Size()
		if total > limits.maxBytes && now.Sub(file.info.ModTime()) > limits.grace {
			remove(file.path)
		}
	}
	return errors.Join(errs...)
}

// resultCacheDir is where the caches of all roots live.
func resultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate the user cache directory: %w", err)
	}
	return filepath.Join(base, "glint", "results"), nil
}

// cacheStamp identifies everything besides the file that a file-local finding
// depends on. Go trees parsed by the project loader skip object resolution,
// trees parsed by the walker do not, so their origin is part of it.
func cacheStamp(cfg *core.Config, goTreesFromLoader, tolerant bool) (string, error) {
	build, err := executableHash()
	if err != nil {
		return "", err
	}
	config, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("serialize configuration for the result cache: %w", err)
	}
	header := fmt.Sprintf("%s\n%s\nloader=%t tolerant=%t\n", cacheFormat, build, goTreesFromLoader, tolerant)
	sum := sha256.Sum256(append([]byte(header), config...))
	return hex.EncodeToString(sum[:]), nil
}

// executableHash identifies the running glint build by its content: a version
// tag does not change between two development builds.
var executableHash = sync.OnceValues(func() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate the glint executable: %w", err)
	}
	sum, err := fileHash(path)
	if err != nil {
		return "", fmt.Errorf("read the glint executable: %w", err)
	}
	return sum, nil
})

func fileHash(path string) (sum string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("hash a file of the run: %w", err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// fileLocalRules marks the rules whose findings the cache may keep.
func fileLocalRules(list []rules.Rule) []bool {
	local := make([]bool, len(list))
	for i, rule := range list {
		local[i] = rules.FileLocal(rule)
	}
	return local
}
