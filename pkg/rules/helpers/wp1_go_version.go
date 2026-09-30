package helpers

import (
	"go/types"
	"go/version"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// GoVersions answers which Go language version a file of a loaded project is
// compiled with. A fix that introduces newer syntax or library calls (any,
// slices, maps) must know it: a module declaring `go 1.16` does not compile
// `any`.
type GoVersions struct {
	// modules is ordered by directory length, longest first, so the first
	// module containing a file is the one it belongs to.
	modules []moduleGoVersion
}

type moduleGoVersion struct {
	dir     string
	version string // "" when go.mod has no go directive
}

// NewGoVersions indexes the modules of the loaded packages.
func NewGoVersions(project *core.GoProjectContext) *GoVersions {
	index := &GoVersions{}
	if project == nil {
		return index
	}
	seen := make(map[string]bool)
	for _, pkg := range project.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.Module == nil {
			continue
		}
		module := pkg.Package.Module
		if module.Dir == "" || seen[module.Dir] {
			continue
		}
		seen[module.Dir] = true
		moduleVersion := ""
		if module.GoVersion != "" {
			moduleVersion = "go" + module.GoVersion
		}
		index.modules = append(index.modules, moduleGoVersion{dir: filepath.Clean(module.Dir), version: moduleVersion})
	}
	sort.SliceStable(index.modules, func(i, j int) bool {
		return len(index.modules[i].dir) > len(index.modules[j].dir)
	})
	return index
}

// FileVersion returns the Go version the file is compiled with ("go1.23"), or
// "" when it is unknown. The type checker's answer comes first: it also knows
// a //go:build constraint of the file. A file without type information - a
// test file, a file of a package that failed to load - takes the version of
// the loaded module that contains it.
func (g *GoVersions) FileVersion(fileCtx *core.FileContext, info *types.Info) string {
	if fileCtx == nil {
		return ""
	}
	if info != nil && fileCtx.GoAST != nil {
		if fileVersion := info.FileVersions[fileCtx.GoAST]; fileVersion != "" {
			return fileVersion
		}
	}
	path := filepath.Clean(fileCtx.Path)
	for _, module := range g.modules {
		if path == module.dir || strings.HasPrefix(path, module.dir+string(filepath.Separator)) {
			return module.version
		}
	}
	return ""
}

// AtLeast reports whether the file is known to be compiled with Go minimum
// ("go1.18") or later. An unknown version is not new enough.
func (g *GoVersions) AtLeast(fileCtx *core.FileContext, info *types.Info, minimum string) bool {
	fileVersion := g.FileVersion(fileCtx, info)
	return version.IsValid(fileVersion) && version.Compare(fileVersion, minimum) >= 0
}
