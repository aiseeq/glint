// Package toolcache keeps what an external program (shellcheck, tsc)
// reported on an input between runs, under the user cache directory: a rule
// that runs one asks it again only when the input changed. The key names
// the input in full — the program's version, the files and the settings it
// read — so an entry is either right or never found.
package toolcache

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Disabled makes every Load miss: glint check --no-cache asks the
// programs again.
var Disabled bool

// maxAge is how long an entry nobody read stays on disk.
const maxAge = 30 * 24 * time.Hour

// Key hashes the parts of an input; each part is length-prefixed, so
// ("ab", "c") and ("a", "bc") differ.
func Key(parts ...[]byte) string {
	hash := sha256.New()
	var size [8]byte
	for _, part := range parts {
		binary.LittleEndian.PutUint64(size[:], uint64(len(part)))
		hash.Write(size[:])
		hash.Write(part)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// Cache holds the entries of one program.
type Cache struct {
	tool string
	// prune removes, once per process, the entries not used for maxAge.
	prune func() error
}

// New returns the cache of the program named tool.
func New(tool string) *Cache {
	return &Cache{tool: tool, prune: sync.OnceValue(func() error { return prune(tool) })}
}

// Load reads the entry under key into into and reports whether there was
// one.
func (c *Cache) Load(key string, into any) (bool, error) {
	if Disabled {
		return false, nil
	}
	path, err := entryPath(c.tool, key)
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, into); err != nil {
		return false, fmt.Errorf("cache entry %s: %w", path, err)
	}
	// A read keeps the entry: the pruning goes by the time of the last use.
	now := time.Now()
	if err := os.Chtimes(path, now, now); err != nil {
		return false, err
	}
	return true, nil
}

// Store writes v as the entry under key; a concurrent reader sees the old
// entry or the new one, never a part.
func (c *Cache) Store(key string, v any) error {
	path, err := entryPath(c.tool, key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".entry-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	if err := errors.Join(werr, tmp.Close()); err != nil {
		return errors.Join(err, os.Remove(tmp.Name()))
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errors.Join(err, os.Remove(tmp.Name()))
	}
	return c.prune()
}

// prune removes the entries of tool not used for maxAge.
func prune(tool string) error {
	dir, err := toolDir(tool)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue // another glint removed it
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if time.Since(info.ModTime()) > maxAge {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// baseDir is where the caches live; tests point it elsewhere.
var baseDir = func() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate the user cache directory: %w", err)
	}
	return filepath.Join(base, "glint", "tools"), nil
}

func toolDir(tool string) (string, error) {
	base, err := baseDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, tool)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func entryPath(tool, key string) (string, error) {
	dir, err := toolDir(tool)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, key+".json"), nil
}
