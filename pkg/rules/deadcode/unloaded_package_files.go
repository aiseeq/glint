package deadcode

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// addUnloadedPackageFiles records, as text, the Go files in the directory of
// a loaded package that the typed load leaves out and the analysis may not
// have been given: tests and build-excluded files a project excluded from its
// findings ("*_test.go" in the exclude list). Excluding a file from the
// findings does not remove its references, so a helper only such a file
// calls is still alive. The files are only split into words, never parsed:
// a build-ignored template costs nothing but a few spurious words.
func (m *testMentions) addUnloadedPackageFiles(pkg *core.GoPackageContext) error {
	if len(pkg.Files) == 0 || len(pkg.Package.GoFiles) == 0 {
		return nil
	}
	dir := filepath.Dir(pkg.Package.GoFiles[0])
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list package directory %q: %w", dir, err)
	}

	words := make(map[string]bool)
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			slices.Contains(pkg.Package.GoFiles, path) {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read package file %q: %w", path, err)
		}
		collectIdentifierWords(string(content), words)
	}

	// mentioned() looks names up by the directory of the declaring file's
	// context path, which may be relative; key the words the same way.
	for _, fileCtx := range pkg.Files {
		key := filepath.Dir(fileCtx.Path)
		set := m.names[key]
		if set == nil {
			set = make(map[string]bool)
			m.names[key] = set
		}
		for word := range words {
			set[word] = true
		}
	}
	return nil
}
