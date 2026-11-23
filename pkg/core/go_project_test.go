package core

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

func writeNestedTrimpathProject(t *testing.T, files map[string]string) (string, []*FileContext) {
	t.Helper()
	root := t.TempDir()
	var contexts []*FileContext
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))
		if filepath.Ext(name) != ".go" {
			continue
		}
		file, err := NewFileContextChecked(path, root, []byte(content), DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, file)
	}
	return root, contexts
}

func loadNestedTrimpathProject(t *testing.T, root string, files []*FileContext) *GoProjectContext {
	t.Helper()
	project, err := LoadGoProject(root, files, GoProjectOptions{ListPackages: func(cfg *packages.Config, patterns ...string) ([]*packages.Package, error) {
		cfg.BuildFlags = []string{"-trimpath"}
		return packages.Load(cfg, patterns...)
	}})
	require.NoError(t, err)
	return project
}

func TestDeclarationForObjectTrimpathUsesSourcePosition(t *testing.T) {
	root, contexts := writeNestedTrimpathProject(t, map[string]string{
		"go.mod":        "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod": "module example.com/shared\n\ngo 1.24\n",
		"shared/types.go": `package shared

import "time"

type Status string
type Inner struct { Code int }
type Box[T any] struct { Val T }
type Values struct {
	At time.Time
	S Status
	Inner
	Cfg struct { Port int }
}
`,
		"shared/methods.go": `package shared

type ValueReceiver struct{}
func (ValueReceiver) Same() {}
func (ValueReceiver) ValueMethod() {}
func (ValueReceiver) OnLine() {}; func (*PointerReceiver) OnLine() {}

type PointerReceiver struct{}
func (*PointerReceiver) Same() {}
func (*PointerReceiver) PointerMethod() {}
`,
		"app.go": `package app

import "example.com/shared"

const LocalOnly = 1

func use(v shared.Values, box shared.Box[string], a shared.ValueReceiver, b *shared.PointerReceiver) {
	_ = v.At
	_ = v.S
	_ = v.Inner
	_ = v.Cfg.Port
	_ = box.Val
	a.Same()
	a.OnLine()
	b.Same()
	b.OnLine()
	a.ValueMethod()
	b.PointerMethod()
}
`,
	})
	project := loadNestedTrimpathProject(t, root, contexts)
	var app *packages.Package
	for _, pkg := range project.Packages {
		if pkg.Package.PkgPath == "example.com/app" {
			app = pkg.Package
		}
	}
	require.NotNil(t, app)
	local := app.TypesInfo.Defs[findIdent(app, "LocalOnly")]
	require.NotNil(t, local)
	assert.False(t, builtDeclarationIndex(project, "example.com/shared"), "loading a project must leave the declaration index unbuilt")
	localFile, localDeclaration, err := project.DeclarationForObject(local)
	require.NoError(t, err)
	assert.Equal(t, "app.go", localFile.RelPath)
	assert.Same(t, local, localDeclaration)
	assert.Empty(t, loadSharedKeys(project), "an object of the project syntax resolves by its own position")
	want := map[string]int{"At": 1, "S": 1, "Inner": 1, "Cfg": 1, "Port": 1, "Val": 1, "Same": 2, "ValueMethod": 1, "PointerMethod": 1, "OnLine": 2}
	got := make(map[string]int)
	for _, file := range app.Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			selection := app.TypesInfo.Selections[selector]
			if selection == nil || selection.Obj().Pkg() == nil || selection.Obj().Pkg().Path() != "example.com/shared" {
				return true
			}
			object := selection.Obj()
			file, declaration, err := project.DeclarationForObject(object)
			require.NoError(t, err, "resolve %s", object.Name())
			got[object.Name()]++
			wantFile := "shared/types.go"
			if object.Name() == "Same" || object.Name() == "ValueMethod" || object.Name() == "PointerMethod" || object.Name() == "OnLine" {
				wantFile = "shared/methods.go"
			}
			assert.Equal(t, wantFile, file.RelPath, object.Name())
			assert.Equal(t, object.Name(), declaration.Name())
			if method, ok := declaration.(*types.Func); ok && (method.Name() == "Same" || method.Name() == "OnLine") {
				wantReceiver := types.TypeString(object.Type().(*types.Signature).Recv().Type(), func(pkg *types.Package) string { return pkg.Name() })
				gotReceiver := types.TypeString(method.Type().(*types.Signature).Recv().Type(), func(pkg *types.Package) string { return pkg.Name() })
				assert.Equal(t, wantReceiver, gotReceiver)
			}
			return true
		})
	}
	assert.Equal(t, want, got)
	assert.True(t, builtDeclarationIndex(project, "example.com/shared"), "a trimmed position builds the index of its package on demand")
}

func findIdent(pkg *packages.Package, name string) *ast.Ident {
	for _, file := range pkg.Syntax {
		var found *ast.Ident
		ast.Inspect(file, func(node ast.Node) bool {
			ident, ok := node.(*ast.Ident)
			if ok && ident.Name == name {
				found = ident
				return false
			}
			return found == nil
		})
		if found != nil {
			return found
		}
	}
	return nil
}

func TestDeclarationForObjectTrimpathLookupScalesWithDeclarations(t *testing.T) {
	const fieldCount = 4800
	var source strings.Builder
	source.WriteString("package shared\n\ntype Many struct {\n")
	for i := range fieldCount {
		fmt.Fprintf(&source, "Field%04d int\n", i)
	}
	source.WriteString("}\n")
	root, contexts := writeNestedTrimpathProject(t, map[string]string{
		"go.mod":         "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod":  "module example.com/shared\n\ngo 1.24\n",
		"shared/many.go": source.String(),
		"app.go":         "package app\n\nimport \"example.com/shared\"\n\nfunc use(x shared.Many) { _ = x.Field4799 }\n",
	})
	project := loadNestedTrimpathProject(t, root, contexts)
	var field types.Object
	for _, pkg := range project.Packages {
		if pkg.Package.PkgPath != "example.com/app" {
			continue
		}
		for _, file := range pkg.Package.Syntax {
			ast.Inspect(file, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if ok && selector.Sel.Name == "Field4799" {
					field = pkg.Package.TypesInfo.Selections[selector].Obj()
				}
				return true
			})
		}
	}
	require.NotNil(t, field)
	started := time.Now()
	var resolvedFile *FileContext
	var resolved types.Object
	for range 1000 {
		var err error
		resolvedFile, resolved, err = project.DeclarationForObject(field)
		require.NoError(t, err)
	}
	elapsed := time.Since(started)
	t.Logf("%d declarations, 1000 lookups: %s", fieldCount, elapsed)
	assert.Equal(t, "shared/many.go", resolvedFile.RelPath)
	assert.Equal(t, "Field4799", resolved.Name())
	assert.Less(t, elapsed, time.Second)
}

func writeGoModule(t *testing.T, files map[string]string) (string, []*FileContext) {
	t.Helper()
	root := t.TempDir()
	files["go.mod"] = "module example.com/project\n\ngo 1.24\n"
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	}

	names := make([]string, 0, len(files))
	for name := range files {
		if strings.HasSuffix(name, ".go") {
			names = append(names, name)
		}
	}
	// Map iteration order is random; tests that pick contexts by index need a
	// stable one.
	sort.Strings(names)

	contexts := make([]*FileContext, 0, len(names))
	for _, name := range names {
		ctx, err := NewFileContextChecked(filepath.Join(root, name), root, []byte(files[name]), DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}
	return root, contexts
}

func TestLoadGoProjectBuildsCrossFileTypesAndSSAWithSingleParse(t *testing.T) {
	root, contexts := writeGoModule(t, map[string]string{
		"model.go": "package project\n\ntype User struct { Name string }\n",
		"use.go":   "package project\n\nfunc UserName(u User) string { return u.Name }\n",
		"use_test.go": "package project\n\n" +
			"func testHelper() User { return User{} }\n",
	})

	parseCounts := make(map[string]int)
	var mu sync.Mutex
	project, err := loadGoProjectWithOptions(root, contexts, GoProjectOptions{RequireSSA: true}, func(path string) {
		mu.Lock()
		parseCounts[path]++
		mu.Unlock()
	})
	require.NoError(t, err)
	require.Len(t, project.Packages, 1)
	require.NotNil(t, project.Program)
	pkg := project.Packages[0]
	require.Len(t, pkg.Files, 2, "Tests=false must keep test files outside the typed package")
	require.NotNil(t, pkg.Package.Types.Scope().Lookup("User"))
	require.NotNil(t, pkg.SSA)
	require.NotNil(t, pkg.SSA.Func("UserName"))
	require.NotEmpty(t, pkg.SSA.Func("UserName").Blocks)

	for _, ctx := range contexts {
		assert.Equal(t, 1, parseCounts[ctx.Path], "parse count for %s", ctx.Path)
		require.NotNil(t, ctx.GoAST)
		assert.Same(t, project.FileSet, ctx.GoFileSet)
	}
	for i, syntax := range pkg.Package.Syntax {
		ctx, mapErr := project.FileForPosition(syntax.Pos())
		require.NoError(t, mapErr)
		assert.Same(t, syntax, ctx.GoAST, "compiled AST %d must be shared with file rules", i)
	}
}

func TestLoadGoProjectReturnsTypeErrors(t *testing.T) {
	root, contexts := writeGoModule(t, map[string]string{
		"broken.go": "package project\n\nvar Number int = \"not an int\"\n",
	})

	_, err := LoadGoProject(root, contexts, GoProjectOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an int")
}

func TestLoadGoProjectTolerateBrokenPackagesKeepsHealthyOnes(t *testing.T) {
	root, contexts := writeGoModule(t, map[string]string{
		"healthy/value.go": "package healthy\n\nfunc Value() string { return \"ok\" }\n",
		"broken/broken.go": "package broken\n\nvar Number int = missingSymbol()\n",
	})

	project, err := LoadGoProject(root, contexts, GoProjectOptions{TolerateBrokenPackages: true})
	require.NoError(t, err)
	require.Len(t, project.Packages, 1, "only the healthy package stays typed")
	assert.Equal(t, "example.com/project/healthy", project.Packages[0].Package.PkgPath)

	require.Len(t, project.SkippedPackages, 1)
	assert.Equal(t, "example.com/project/broken", project.SkippedPackages[0].PkgPath)
	assert.Contains(t, project.SkippedPackages[0].Reason, "missingSymbol")
}

func TestLoadGoProjectTolerateBrokenPackagesStillParsesTheirFiles(t *testing.T) {
	root, contexts := writeGoModule(t, map[string]string{
		"broken/broken.go": "package broken\n\nvar Number int = missingSymbol()\n",
	})

	project, err := LoadGoProject(root, contexts, GoProjectOptions{TolerateBrokenPackages: true})
	require.NoError(t, err)
	assert.Empty(t, project.Packages, "a broken package carries no usable type information")
	require.Len(t, project.SkippedPackages, 1)

	fileCtx, err := project.File(filepath.Join(root, "broken", "broken.go"))
	require.NoError(t, err)
	require.NotNil(t, fileCtx.GoAST, "file rules must still see the syntax tree")
}

func TestLoadGoProjectTolerateBrokenPackagesKeepsFilesOutsideAnyModule(t *testing.T) {
	root := t.TempDir()
	moduleRoot := filepath.Join(root, "app")
	require.NoError(t, os.MkdirAll(moduleRoot, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(moduleRoot, "go.mod"), []byte("module example.com/app\n\ngo 1.24\n"), 0644))

	var contexts []*FileContext
	for path, source := range map[string]string{
		filepath.Join(moduleRoot, "value.go"):     "package app\n\nfunc Value() string { return \"ok\" }\n",
		filepath.Join(root, "tools", "helper.go"): "package main\n\nfunc main() {}\n",
	} {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, []byte(source), 0644))
		ctx, err := NewFileContextChecked(path, root, []byte(source), DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}

	project, err := LoadGoProject(root, contexts, GoProjectOptions{TolerateBrokenPackages: true})
	require.NoError(t, err)
	require.Len(t, project.Packages, 1)
	require.Len(t, project.SkippedPackages, 1)
	assert.Contains(t, project.SkippedPackages[0].Reason, "outside a Go module")

	fileCtx, err := project.File(filepath.Join(root, "tools", "helper.go"))
	require.NoError(t, err)
	require.NotNil(t, fileCtx.GoAST, "a file outside any module still gets parsed")
}

func TestLoadGoProjectTolerateBrokenPackagesReportsUnparsableFiles(t *testing.T) {
	root, contexts := writeGoModule(t, map[string]string{
		"value.go":   "package project\n\nfunc Value() string { return \"ok\" }\n",
		"scratch.go": "func main() {}\n",
	})

	project, err := LoadGoProject(root, contexts, GoProjectOptions{TolerateBrokenPackages: true})
	require.NoError(t, err)
	require.NotEmpty(t, project.SkippedPackages)
	var joined strings.Builder
	for _, pkg := range project.SkippedPackages {
		joined.WriteString(pkg.Reason)
	}
	assert.Contains(t, joined.String(), "scratch.go")

	fileCtx, err := project.File(filepath.Join(root, "scratch.go"))
	require.NoError(t, err)
	assert.Nil(t, fileCtx.GoAST, "an unparsable file carries no syntax tree")
}

// A //go:build ignore file is often a template or a generator script that is
// not valid Go; the toolchain never parses it, and neither may the load fail
// on it.
func TestLoadGoProjectSkipsUnparsableFileExcludedByBuild(t *testing.T) {
	root, contexts := writeGoModule(t, map[string]string{
		"value.go":    "package project\n\nfunc Value() string { return \"ok\" }\n",
		"template.go": "//go:build ignore\n\npackage main\n\nfunc main() { {{ .Body }} }\n",
	})

	project, err := LoadGoProject(root, contexts, GoProjectOptions{})
	require.NoError(t, err)
	assert.Empty(t, project.SkippedPackages, "a file outside every build is no broken package")
	fileCtx, err := project.File(filepath.Join(root, "template.go"))
	require.NoError(t, err)
	assert.Nil(t, fileCtx.GoAST)
}

func TestLoadGoProjectUsesExcludedCompiledFileForTypesWithoutAnalyzingIt(t *testing.T) {
	root, contexts := writeGoModule(t, map[string]string{
		"first.go":  "package project\n\nfunc First() Second { return Second{} }\n",
		"second.go": "package project\n\ntype Second struct{}\n",
	})
	contexts = contexts[:1]

	project, err := LoadGoProject(root, contexts, GoProjectOptions{RequireSSA: true})
	require.NoError(t, err)
	require.Len(t, project.Packages, 1)
	require.Len(t, project.Packages[0].Files, 1)
	require.NotNil(t, project.Packages[0].Package.Types.Scope().Lookup("Second"))
	require.NotNil(t, project.Packages[0].SSA.Func("First"))

	_, err = project.File(filepath.Join(root, "second.go"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no file context")
}

func TestLoadGoProjectLoadsModulesBelowProjectRoot(t *testing.T) {
	root := t.TempDir()
	var contexts []*FileContext
	for _, module := range []string{"first", "second"} {
		moduleRoot := filepath.Join(root, module)
		require.NoError(t, os.MkdirAll(moduleRoot, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(moduleRoot, "go.mod"), []byte("module example.com/"+module+"\n\ngo 1.24\n"), 0644))
		source := []byte("package " + module + "\n\nfunc Value() string { return \"" + module + "\" }\n")
		path := filepath.Join(moduleRoot, "value.go")
		require.NoError(t, os.WriteFile(path, source, 0644))
		ctx, err := NewFileContextChecked(path, root, source, DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}

	project, err := LoadGoProject(root, contexts, GoProjectOptions{RequireSSA: true})
	require.NoError(t, err)
	require.Len(t, project.Packages, 2)
	for _, pkg := range project.Packages {
		require.NotNil(t, pkg.SSA.Func("Value"))
	}
}

func TestLoadGoProjectRejectsAnalyzedFileOutsideGoModule(t *testing.T) {
	root := t.TempDir()
	source := []byte("package standalone\n")
	path := filepath.Join(root, "standalone.go")
	require.NoError(t, os.WriteFile(path, source, 0644))
	ctx, err := NewFileContextChecked(path, root, source, DefaultConfig())
	require.NoError(t, err)

	_, err = LoadGoProject(root, []*FileContext{ctx}, GoProjectOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside a Go module")
}

// Analyzing a subdirectory is the normal way to scope a run — `glint check
// ./internal ./cmd` in a Makefile. The module owning those packages lives above
// the analyzed directory, so the search for go.mod must not stop at the root of
// the run.
func TestLoadGoProjectFindsModuleAboveAnalyzedDirectory(t *testing.T) {
	moduleRoot := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(moduleRoot, "go.mod"), []byte("module example.com/app\n\ngo 1.24\n"), 0644))

	packageDir := filepath.Join(moduleRoot, "internal", "admin")
	require.NoError(t, os.MkdirAll(packageDir, 0755))
	source := []byte("package admin\n\nfunc Value() string { return \"ok\" }\n")
	path := filepath.Join(packageDir, "admin.go")
	require.NoError(t, os.WriteFile(path, source, 0644))

	analyzedRoot := filepath.Join(moduleRoot, "internal")
	ctx, err := NewFileContextChecked(path, analyzedRoot, source, DefaultConfig())
	require.NoError(t, err)

	project, err := LoadGoProject(analyzedRoot, []*FileContext{ctx}, GoProjectOptions{})
	require.NoError(t, err)
	require.Len(t, project.Packages, 1)
	assert.Equal(t, "example.com/app/internal/admin", project.Packages[0].Package.PkgPath)
}

func TestGoProjectFileForPositionRejectsUnknownPosition(t *testing.T) {
	project := &GoProjectContext{
		FileSet:     token.NewFileSet(),
		filesByPath: make(map[string]*FileContext),
	}

	_, err := project.FileForPosition(1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown position")
}

// Dependencies come from export data: only the project's own files are parsed
// and type-checked from source. An overlay of unchanged files would make
// go/packages distrust export data and check the whole standard library.
func TestLoadGoProjectParsesOnlyProjectFiles(t *testing.T) {
	root, contexts := writeGoModule(t, map[string]string{
		"client.go": "package project\n\nimport \"net/http\"\n\n" +
			"func Get(u string) (*http.Response, error) { return http.Get(u) }\n",
	})

	var parsed []string
	var mu sync.Mutex
	project, err := loadGoProjectWithOptions(root, contexts, GoProjectOptions{}, func(path string) {
		mu.Lock()
		parsed = append(parsed, path)
		mu.Unlock()
	})
	require.NoError(t, err)
	require.Len(t, project.Packages, 1)
	assert.Equal(t, []string{filepath.Join(root, "client.go")}, parsed)
	get := project.Packages[0].Package.Types.Scope().Lookup("Get")
	require.NotNil(t, get)
	assert.Contains(t, get.Type().String(), "*net/http.Response")
}

// A file context whose content differs from the disk is what the project is
// type-checked from.
func TestLoadGoProjectUsesContextContentThatDiffersFromDisk(t *testing.T) {
	root, contexts := writeGoModule(t, map[string]string{
		"model.go": "package project\n\ntype User struct{}\n",
	})
	edited, err := NewFileContextChecked(contexts[0].Path, root, []byte("package project\n\ntype Account struct{}\n"), DefaultConfig())
	require.NoError(t, err)

	project, err := LoadGoProject(root, []*FileContext{edited}, GoProjectOptions{})
	require.NoError(t, err)
	scope := project.Packages[0].Package.Types.Scope()
	assert.NotNil(t, scope.Lookup("Account"))
	assert.Nil(t, scope.Lookup("User"))
}

func TestSharedBuildsOncePerProject(t *testing.T) {
	type key struct{}
	type failingKey struct{}
	project := &GoProjectContext{}
	builds := 0
	build := func() (int, error) { builds++; return 42, nil }

	for range 3 {
		value, err := Shared(project, key{}, build)
		require.NoError(t, err)
		assert.Equal(t, 42, value)
	}
	assert.Equal(t, 1, builds)

	failures := 0
	for range 2 {
		_, err := Shared(project, failingKey{}, func() (string, error) {
			failures++
			return "", errors.New("scan failed")
		})
		require.EqualError(t, err, "scan failed")
	}
	assert.Equal(t, 1, failures, "a failed build is not retried")

	_, err := Shared(project, key{}, func() (string, error) { return "", nil })
	require.Error(t, err, "a key built with another type is an error")
}

// loadGoProjectWithOptions loads a project with a hook that sees every file
// the loader parses.
func loadGoProjectWithOptions(root string, contexts []*FileContext, opts GoProjectOptions, onParse func(string)) (*GoProjectContext, error) {
	loader := NewGoProjectLoader()
	loader.onParse = onParse
	return loader.Load(root, contexts, opts)
}

// Two roots of one module share one load: every file is parsed once, both
// projects see the whole module's packages and SSA, each attaches only its
// own files, and load-wide values are built once while per-root ones are not.
func TestGoProjectLoaderSharesModuleLoadAcrossRoots(t *testing.T) {
	root, _ := writeGoModule(t, map[string]string{
		"a/a.go": "package a\n\nfunc A() int { return 1 }\n",
		"b/b.go": "package b\n\nimport \"example.com/project/a\"\n\nfunc B() int { return a.A() }\n",
	})
	contextsOf := func(dir string) []*FileContext {
		name := filepath.Join(dir, dir+".go")
		content, err := os.ReadFile(filepath.Join(root, name))
		require.NoError(t, err)
		ctx, err := NewFileContextChecked(filepath.Join(root, name), filepath.Join(root, dir), content, DefaultConfig())
		require.NoError(t, err)
		return []*FileContext{ctx}
	}

	parses := make(map[string]int)
	var mu sync.Mutex
	loader := NewGoProjectLoader()
	loader.onParse = func(path string) {
		mu.Lock()
		parses[path]++
		mu.Unlock()
	}
	opts := GoProjectOptions{RequireSSA: true}
	projectA, err := loader.Load(filepath.Join(root, "a"), contextsOf("a"), opts)
	require.NoError(t, err)
	projectB, err := loader.Load(filepath.Join(root, "b"), contextsOf("b"), opts)
	require.NoError(t, err)

	for path, count := range parses {
		assert.Equal(t, 1, count, "parse count for %s", path)
	}
	assert.Same(t, projectA.Program, projectB.Program)
	require.Len(t, projectA.Packages, 2)
	require.Len(t, projectB.Packages, 2)
	assert.Equal(t, "a.go", projectA.Files[0].RelPath)
	assert.Equal(t, "b.go", projectB.Files[0].RelPath)
	for _, pkg := range projectB.Packages {
		for _, file := range pkg.Files {
			assert.Equal(t, "b.go", file.RelPath, "a root attaches only its own files")
		}
	}

	type loadKey struct{}
	type rootKey struct{}
	loadBuilds, rootBuilds := 0, 0
	for _, project := range []*GoProjectContext{projectA, projectB} {
		_, err := SharedLoad(project, loadKey{}, func() (int, error) { loadBuilds++; return 0, nil })
		require.NoError(t, err)
		_, err = Shared(project, rootKey{}, func() (int, error) { rootBuilds++; return 0, nil })
		require.NoError(t, err)
	}
	assert.Equal(t, 1, loadBuilds)
	assert.Equal(t, 2, rootBuilds)
}
