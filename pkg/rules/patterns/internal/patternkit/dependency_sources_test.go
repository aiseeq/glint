package patternkit

import (
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const standardLibraryUser = `package sample

import (
	"bytes"
	"os"
	"strings"
)

func Use(b *bytes.Buffer, mode os.FileMode) bool {
	return strings.HasPrefix(b.String(), "x") && mode.IsDir()
}
`

// The body of a standard library function is read from GOROOT, whether the
// go command trims the file paths it compiles into export data or not: a
// function of an imported package (strings.HasPrefix), a method
// ((*bytes.Buffer).String), and a method of a package the project reaches
// only through another (io/fs.FileMode.IsDir through os).
func TestDependencySourcesReadStandardLibrary(t *testing.T) {
	for _, flags := range []string{"", "-trimpath"} {
		t.Run("packages.Load "+flags, func(t *testing.T) {
			t.Setenv("GOFLAGS", flags)
			t.Setenv("GOWORK", "off")
			t.Setenv("GOTOOLCHAIN", "local")
			root, contexts := rulestest.Module(t, map[string]string{"sample.go": standardLibraryUser})
			project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
			require.NoError(t, err)
			assert.Equal(t, []string{"HasPrefix", "IsDir", "String"}, readStandardBodies(t, project, NewDependencySources(project)))
		})
	}
	// The in-process load of the rule tests lists the files of the packages
	// the project imports; one reached only through another has its types
	// alone, so the method of io/fs is left out.
	t.Run("rule test load", func(t *testing.T) {
		source := strings.Replace(standardLibraryUser, " && mode.IsDir()", "", 1)
		project := rulestest.Project(t, map[string]string{"sample.go": source})
		assert.Equal(t, []string{"HasPrefix", "String"}, readStandardBodies(t, project, NewDependencySources(project)))
	})
}

// readStandardBodies returns the names of the standard library functions the
// project calls whose bodies sources reads.
func readStandardBodies(t *testing.T, project *core.GoProjectContext, sources *DependencySources) []string {
	t.Helper()
	require.Len(t, project.Packages, 1)
	pkg := project.Packages[0].Package
	var read []string
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn := StaticFunc(pkg.TypesInfo, call)
			if fn == nil {
				return true
			}
			if decl := sources.FuncDecl(fn); decl != nil && decl.Body != nil && decl.Name.Name == fn.Name() {
				read = append(read, fn.Name())
			}
			return true
		})
	}
	sort.Strings(read)
	return read
}

// A position the compiler gave as an absolute path (a module a replace points
// at, built without -trimpath) names the file on disk: a listed file of the
// same base name elsewhere, another copy of the package, is not read in its
// place.
func TestDependencySourcesAbsolutePositionNamesTheFile(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	root, contexts := rulestest.Module(t, map[string]string{
		"go.mod":                 "module example.com/sample\n\ngo 1.24\n\nrequire example.com/lib v0.0.0\n\nreplace example.com/lib => ./third_party/lib\n",
		"third_party/lib/go.mod": "module example.com/lib\n\ngo 1.24\n",
		"third_party/lib/lib.go": "package lib\n\nfunc Ready() bool { return true }\n",
		"sample.go":              "package sample\n\nimport \"example.com/lib\"\n\nfunc Use() bool { return lib.Ready() }\n",
	})
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	var sample *core.GoPackageContext
	for _, pkg := range project.Packages {
		if pkg.Package.PkgPath == "example.com/sample" {
			sample = pkg
		}
	}
	require.NotNil(t, sample)
	sources := NewDependencySources(project)
	libPkg := sample.Package.Imports["example.com/lib"].Types
	ready := libPkg.Scope().Lookup("Ready").(*types.Func)
	require.NotNil(t, sources.FuncDecl(ready))

	copied := filepath.Join(t.TempDir(), "lib.go")
	require.NoError(t, os.WriteFile(copied, []byte("package lib\n\nfunc Ready() bool { return false }\n"), 0o600))
	sources = NewDependencySources(project)
	sources.packageFiles[libPkg]["lib.go"] = copied
	assert.Nil(t, sources.FuncDecl(ready))
}

// GOPATH mode (GO111MODULE=off over a go.mod) loads every package without a
// module: the standard library is told by its path there, and a dependency
// under a host path is not standard.
func TestDependencySourcesStandardInGOPATHMode(t *testing.T) {
	gopath := t.TempDir()
	t.Setenv("GO111MODULE", "off")
	t.Setenv("GOPATH", gopath)
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	guard := filepath.Join(gopath, "src", "example.com", "guard")
	require.NoError(t, os.MkdirAll(guard, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(guard, "guard.go"), []byte("package guard\n\nfunc Run(f func()) { f() }\n"), 0o600))
	root := filepath.Join(gopath, "src", "app")
	require.NoError(t, os.MkdirAll(root, 0o755))
	source := "package app\n\nimport (\n\t\"strings\"\n\n\t\"example.com/guard\"\n)\n\nfunc Use() { guard.Run(func() { _ = strings.ToUpper(\"x\") }) }\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module app\n\ngo 1.24\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app.go"), []byte(source), 0o600))
	contexts := []*core.FileContext{core.NewFileContext(filepath.Join(root, "app.go"), root, []byte(source), nil)}
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	require.Len(t, project.Packages, 1)
	imports := project.Packages[0].Package.Imports
	require.Nil(t, imports["example.com/guard"].Module)
	sources := NewDependencySources(project)
	assert.False(t, sources.Standard(imports["example.com/guard"].Types))
	assert.True(t, sources.Standard(imports["strings"].Types))
}
