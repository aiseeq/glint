package patternkit

import (
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// TemplateFiles returns the Go template files under the project root.
func TemplateFiles(root string) ([]string, error) {
	return FilesWithExt(root, ".html", ".tmpl", ".gohtml")
}

// FilesWithExt returns the files under root with one of the extensions,
// outside dependency, build and hidden directories: templates and
// stylesheets, which the analysis does not list.
func FilesWithExt(root string, exts ...string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (EnvFileSkipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if slices.Contains(exts, strings.ToLower(filepath.Ext(path))) {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}
