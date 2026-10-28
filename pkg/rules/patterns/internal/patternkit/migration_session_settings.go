package patternkit

import (
	"path/filepath"
	"slices"
	"strings"
)

// IsUpMigration reports a SQL file of a migrations directory that is not a
// down migration.
func IsUpMigration(path string) bool {
	if !strings.HasSuffix(path, ".sql") || strings.HasSuffix(path, ".down.sql") {
		return false
	}
	return slices.ContainsFunc(strings.Split(filepath.ToSlash(filepath.Dir(path)), "/"), func(dir string) bool {
		return dir == "migrations" || dir == "migration"
	})
}
