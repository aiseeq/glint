package rules

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// HashCacheInputs identifies the contents and relative names of files selected
// by the same walk as a project rule reads. The root keeps keys stable when it
// is supplied as a relative or absolute path.
func HashCacheInputs(root string, paths []string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("make input root absolute: %w", err)
	}
	paths = slices.Clone(paths)
	slices.Sort(paths)
	hash := sha256.New()
	for _, path := range paths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("make input path absolute: %w", err)
		}
		rel, err := filepath.Rel(absRoot, absPath)
		if err != nil {
			return "", fmt.Errorf("place input %s under %s: %w", path, absRoot, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read input %s: %w", path, err)
		}
		_, _ = fmt.Fprintf(hash, "%d:%s:%d:", len(rel), filepath.ToSlash(rel), len(data))
		_, _ = hash.Write(data)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
