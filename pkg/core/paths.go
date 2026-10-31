package core

import (
	"path/filepath"
	"strings"
)

// WithinPath reports whether path is dir or is contained within dir.
func WithinPath(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
