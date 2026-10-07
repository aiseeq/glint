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
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// cacheFormat changes whenever the stored layout does.
const cacheFormat = "glint-results-3"

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
	cache, err := newRootCache(strings.Join(append([]string{root}, scopes...), "\n"), cfg, goTreesFromLoader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: result cache off for %s: %v\n", root, err)
		return nil
	}
	return cache
}

func newRootCache(root string, cfg *core.Config, goTreesFromLoader bool) (*resultCache, error) {
	dir, err := resultCacheDir()
	if err != nil {
		return nil, err
	}
	stamp, err := cacheStamp(cfg, goTreesFromLoader, flagTolerant)
	if err != nil {
		return nil, err
	}
	return openResultCache(dir, root, stamp)
}

// openResultCache reads the cache of root from dir. A cache written under
// another stamp is discarded, a missing one starts empty.
func openResultCache(dir, root, stamp string) (*resultCache, error) {
	name := sha256.Sum256([]byte(root))
	cache := &resultCache{
		path:     filepath.Join(dir, hex.EncodeToString(name[:])+".gob"),
		stamp:    stamp,
		previous: make(map[string]cacheEntry),
		current:  make(map[string]cacheEntry),
	}
	data, err := os.ReadFile(cache.path)
	if errors.Is(err, fs.ErrNotExist) {
		return cache, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read result cache: %w", err)
	}
	var stored cacheContents
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&stored); err != nil {
		return nil, fmt.Errorf("decode result cache %s: %w", cache.path, err)
	}
	if stored.Stamp == stamp {
		cache.previous = stored.Entries
		cache.previousProject = stored.Project
	}
	return cache, nil
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
func (c *resultCache) storeProject(found core.ViolationList, skipped []core.SkippedPackage) {
	if !c.projectKeyed {
		return
	}
	c.currentProject = &projectEntry{
		Inputs:     c.projectInputs,
		Rules:      c.projectRules,
		Violations: storedViolations(found),
		Skipped:    append([]core.SkippedPackage(nil), skipped...),
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
		stored[rule.Name()] = storedViolations(found[i])
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
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".results-*")
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
	return pruneResultCaches(filepath.Dir(c.path), time.Now(), resultCacheMaxAge)
}

// resultCacheMaxAge is how long the cache of a root nobody checks any more
// stays on disk.
const resultCacheMaxAge = 30 * 24 * time.Hour

// pruneResultCaches removes the caches of roots not checked for maxAge.
func pruneResultCaches(dir string, now time.Time, maxAge time.Duration) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list result caches: %w", err)
	}
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".gob" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if now.Sub(info.ModTime()) > maxAge {
			errs = append(errs, os.Remove(filepath.Join(dir, entry.Name())))
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
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// cachedViolations returns fresh copies of stored findings: callers change
// the violations they get.
func cachedViolations(stored []core.Violation) core.ViolationList {
	if len(stored) == 0 {
		return nil
	}
	list := make(core.ViolationList, len(stored))
	for i := range stored {
		violation := stored[i]
		violation.Context = maps.Clone(stored[i].Context)
		list[i] = &violation
	}
	return list
}

// storedViolations copies findings for the cache.
func storedViolations(list core.ViolationList) []core.Violation {
	stored := make([]core.Violation, len(list))
	for i, violation := range list {
		stored[i] = *violation
		stored[i].Context = maps.Clone(violation.Context)
	}
	return stored
}

// fileLocalRules marks the rules whose findings the cache may keep.
func fileLocalRules(list []rules.Rule) []bool {
	local := make([]bool, len(list))
	for i, rule := range list {
		local[i] = rules.FileLocal(rule)
	}
	return local
}
