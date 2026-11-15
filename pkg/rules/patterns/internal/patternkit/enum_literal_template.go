package patternkit

import (
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// TemplateFiles returns the Go template files under the project root.
func TemplateFiles(root string, respectGitignore bool) ([]string, error) {
	return FilesWithExt(root, respectGitignore, ".html", ".tmpl", ".gohtml")
}

// FilesWithExt returns the files under root with one of the extensions,
// outside dependency, build and hidden directories and those the run does not
// walk under respectGitignore (core.RepositoryTree): templates and
// stylesheets, which the analysis does not list.
func FilesWithExt(root string, respectGitignore bool, exts ...string) ([]string, error) {
	tree, err := core.NewRepositoryTree(root, respectGitignore)
	if err != nil {
		return nil, err
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (EnvFileSkipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return tree.Enter(path)
		}
		if slices.Contains(exts, strings.ToLower(filepath.Ext(path))) {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}
