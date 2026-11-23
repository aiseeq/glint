package core

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

func loadSharedKeys(project *GoProjectContext) []any {
	project.loadShared.mu.Lock()
	defer project.loadShared.mu.Unlock()
	return slices.Collect(maps.Keys(project.loadShared.entries))
}

func builtDeclarationIndex(project *GoProjectContext, pkgPath string) bool {
	return slices.Contains(loadSharedKeys(project), any(packageDeclarationsKey{pkgPath: pkgPath}))
}

func projectPackage(t *testing.T, project *GoProjectContext, pkgPath string) *packages.Package {
	t.Helper()
	for _, pkg := range project.Packages {
		if pkg.Package.PkgPath == pkgPath {
			return pkg.Package
		}
	}
	require.FailNow(t, "no project package "+pkgPath)
	return nil
}

// usedObjects returns the objects of another package that pkg refers to by
// selector, keyed by the selector text, as "shared.Name" or "pair.Meta.Name".
func usedObjects(pkg *packages.Package) map[string][]types.Object {
	used := make(map[string][]types.Object)
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			object := pkg.TypesInfo.ObjectOf(selector.Sel)
			if object == nil || object.Pkg() == nil || object.Pkg() == pkg.Types {
				return true
			}
			key := types.ExprString(selector)
			used[key] = append(used[key], object)
			return true
		})
	}
	return used
}

// The project load lists packages with -trimpath, so a second copy of the
// project reuses the Go build cache entries of the first.
func TestLoadGoProjectListsWithTrimpath(t *testing.T) {
	root, contexts := writeNestedTrimpathProject(t, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.24\n",
		"app.go": "package app\n\nconst Limit = 1\n",
	})
	var flags [][]string
	_, err := LoadGoProject(root, contexts, GoProjectOptions{ListPackages: func(cfg *packages.Config, patterns ...string) ([]*packages.Package, error) {
		flags = append(flags, slices.Clone(cfg.BuildFlags))
		return packages.Load(cfg, patterns...)
	}})
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"-trimpath"}}, flags)
}

// An object of the standard library builds nothing: its package is not a
// project package. An object of a project package builds the declaration
// index of that package alone.
func TestDeclarationForObjectIndexesOnlyThePackageOfTheObject(t *testing.T) {
	root, contexts := writeNestedTrimpathProject(t, map[string]string{
		"go.mod":                "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod":         "module example.com/shared\n\ngo 1.24\n",
		"shared/lib/lib.go":     "package lib\n\nvar Codes []string\n",
		"shared/items/items.go": "package items\n\nvar Items []string\n",
		"app/app.go": `package app

import (
	"time"

	"example.com/shared/items"
	"example.com/shared/lib"
)

func Use(day time.Time) (time.Time, bool) {
	return day.AddDate(0, 0, int(time.Saturday)), lib.Codes == nil && items.Items == nil
}
`,
	})
	project, err := LoadGoProject(root, contexts, GoProjectOptions{})
	require.NoError(t, err)
	used := usedObjects(projectPackage(t, project, "example.com/app/app"))

	saturday := used["time.Saturday"][0]
	assert.Equal(t, "time/time.go", project.FileSet.PositionFor(saturday.Pos(), false).Filename)
	_, err = project.FileForObject(saturday)
	require.ErrorContains(t, err, "not loaded from project sources")
	require.ErrorIs(t, err, ErrObjectNotInRun, "a standard library object lies outside the project, which is no failure")
	_, _, err = project.DeclaredAt(saturday)
	require.ErrorIs(t, err, ErrObjectNotInRun)
	_, err = project.FileForObject(nil)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrObjectNotInRun, "a nil object is a failure of the caller")
	_, err = project.FileForObject(types.NewVar(token.NoPos, saturday.Pkg(), "Synthetic", saturday.Type()))
	require.ErrorIs(t, err, ErrObjectNotInRun, "an object without a position is declared in no project file")
	_, _, err = project.DeclarationForObject(saturday)
	require.Error(t, err)
	assert.Equal(t, []any{projectSyntaxPackagesKey{}}, loadSharedKeys(project), "a standard library object maps no directory and indexes no package")

	codes := used["lib.Codes"][0]
	assert.Equal(t, "example.com/shared@v0.0.0/lib/lib.go", project.FileSet.PositionFor(codes.Pos(), false).Filename)
	file, declaration, err := project.DeclarationForObject(codes)
	require.NoError(t, err)
	assert.Equal(t, "shared/lib/lib.go", file.RelPath)
	assert.Same(t, projectPackage(t, project, "example.com/shared/lib").Types.Scope().Lookup("Codes"), declaration)
	assert.True(t, builtDeclarationIndex(project, "example.com/shared/lib"))
	views, err := SharedLoad(project, projectPackageViewsKey{}, func() (map[*types.Package]*packages.Package, error) {
		return nil, errors.New("the package views must be built by the lookup")
	})
	require.NoError(t, err)
	var viewed []string
	for _, view := range views {
		viewed = append(viewed, view.PkgPath)
	}
	slices.Sort(viewed)
	assert.Equal(t, []string{"example.com/app/app", "example.com/shared/items", "example.com/shared/items", "example.com/shared/lib", "example.com/shared/lib"}, viewed, "the views hold project packages alone: their syntax and the export data of the importing module")
	assert.False(t, builtDeclarationIndex(project, "example.com/shared/items"), "the index is built for the package of the object only")

	// An object of a project package path whose package the load does not
	// hold resolves to no file.
	source := []byte("package lib\n\nvar Codes []string\n")
	trimmedFile := project.FileSet.AddFile("example.com/shared@v0.0.0/lib/lib.go", -1, len(source))
	trimmedFile.SetLinesForContent(source)
	stranger := types.NewVar(trimmedFile.Pos(strings.Index(string(source), "Codes")), types.NewPackage("example.com/shared/lib", "lib"), "Codes", codes.Type())
	_, err = project.FileForObject(stranger)
	require.ErrorContains(t, err, "not among the loaded packages")
	require.ErrorIs(t, err, ErrObjectNotInRun)
}

// A module nested under the path of the root module, taken by a replace, is
// trimmed as module@version: its files are found under its own directory, and
// a package of the root module whose path starts the same way, which comes
// from the same load with its syntax, under the root.
func TestFileForObjectModuleNestedUnderRootPath(t *testing.T) {
	root, contexts := writeNestedTrimpathProject(t, map[string]string{
		"go.mod":             "module example.com/app\n\ngo 1.24\n\nrequire example.com/app/sub v0.0.0\nreplace example.com/app/sub => ./sub\n",
		"sub/go.mod":         "module example.com/app/sub\n\ngo 1.24\n",
		"sub/sub.go":         "package sub\n\nconst Top = 1\n",
		"sub/inner/inner.go": "package inner\n\nconst Deep = 2\n",
		"subway/subway.go":   "package subway\n\nconst Near = 3\n",
		"app.go": `package app

import (
	"example.com/app/sub"
	"example.com/app/sub/inner"
	"example.com/app/subway"
)

var Sum = sub.Top + inner.Deep + subway.Near
`,
	})
	project, err := LoadGoProject(root, contexts, GoProjectOptions{})
	require.NoError(t, err)
	used := usedObjects(projectPackage(t, project, "example.com/app"))
	for selector, want := range map[string][2]string{
		"sub.Top":     {"example.com/app/sub@v0.0.0/sub.go", "sub/sub.go"},
		"inner.Deep":  {"example.com/app/sub@v0.0.0/inner/inner.go", "sub/inner/inner.go"},
		"subway.Near": {"subway/subway.go", "subway/subway.go"},
	} {
		object := used[selector][0]
		filename := project.FileSet.PositionFor(object.Pos(), false).Filename
		if rel, err := filepath.Rel(root, filename); err == nil && filepath.IsAbs(filename) {
			filename = filepath.ToSlash(rel)
		}
		assert.Equal(t, want[0], filename, selector)
		file, declaration, err := project.DeclarationForObject(object)
		require.NoError(t, err, selector)
		assert.Equal(t, want[1], file.RelPath, selector)
		assert.Equal(t, object.Name(), declaration.Name(), selector)
	}
}

// In a workspace the modules are main modules, without a version: an object
// of another module of the workspace is trimmed to its import path.
func TestFileForObjectWorkspaceModule(t *testing.T) {
	root, contexts := writeNestedTrimpathProject(t, map[string]string{
		"go.work":              "go 1.24\n\nuse (\n\t./app\n\t./shared\n)\n",
		"app/go.mod":           "module example.com/app\n\ngo 1.24\n",
		"app/app.go":           "package app\n\nimport \"example.com/shared/limits\"\n\nvar Days = limits.MaxDays\n",
		"shared/go.mod":        "module example.com/shared\n\ngo 1.24\n",
		"shared/limits/max.go": "package limits\n\nconst MaxDays = 5\n",
	})
	t.Setenv("GOWORK", filepath.Join(root, "go.work"))
	project, err := LoadGoProject(root, contexts, GoProjectOptions{})
	require.NoError(t, err)
	maxDays := usedObjects(projectPackage(t, project, "example.com/app"))["limits.MaxDays"][0]
	assert.Equal(t, "example.com/shared/limits/max.go", project.FileSet.PositionFor(maxDays.Pos(), false).Filename)
	file, declaration, err := project.DeclarationForObject(maxDays)
	require.NoError(t, err)
	assert.Equal(t, "shared/limits/max.go", file.RelPath)
	assert.Same(t, projectPackage(t, project, "example.com/shared/limits").Types.Scope().Lookup("MaxDays"), declaration)
}

// Namesakes on one line are told apart by type, by being a field, by the
// receiver of a method and through the generic origin; of two of one shape
// the first in the source is taken, the same on every load.
func TestDeclarationForObjectNamesakesOnOneLine(t *testing.T) {
	root, contexts := writeNestedTrimpathProject(t, map[string]string{
		"go.mod":        "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod": "module example.com/shared\n\ngo 1.24\n",
		"shared/names.go": `package shared

type Count struct{ Code int }; type Tally struct{ Code string }
func Local() { var Name string; _ = Name }; var Name string; type Pair struct{ Name string }
type Input struct { Meta struct{ Label string }; Label string }
type Box[T any] struct{ Val T }; func (b Box[T]) Get() T { return b.Val }; func (Pair) Get() string { return "" }
`,
		"app.go": `package app

import "example.com/shared"

func Use(count shared.Count, tally shared.Tally, pair shared.Pair, input shared.Input, box shared.Box[int]) {
	_, _, _, _ = count.Code, tally.Code, shared.Name, pair.Name
	_, _ = input.Label, input.Meta.Label
	_, _ = box.Get(), pair.Get()
}
`,
	})
	declaredIn := func(t *testing.T, project *GoProjectContext, typeName, field string) types.Object {
		t.Helper()
		named := projectPackage(t, project, "example.com/shared").Types.Scope().Lookup(typeName).Type().(*types.Named)
		object, _, _ := types.LookupFieldOrMethod(named, true, named.Obj().Pkg(), field)
		require.NotNil(t, object)
		return object
	}
	for range 4 {
		project, err := LoadGoProject(root, contexts, GoProjectOptions{})
		require.NoError(t, err)
		used := usedObjects(projectPackage(t, project, "example.com/app"))
		shared := projectPackage(t, project, "example.com/shared").Types.Scope()
		meta := declaredIn(t, project, "Input", "Meta")
		firstLabel := meta.Type().(*types.Struct).Field(0)
		for selector, want := range map[string]types.Object{
			"count.Code":       declaredIn(t, project, "Count", "Code"),
			"tally.Code":       declaredIn(t, project, "Tally", "Code"),
			"shared.Name":      shared.Lookup("Name"),
			"pair.Name":        declaredIn(t, project, "Pair", "Name"),
			"input.Label":      firstLabel,
			"input.Meta.Label": firstLabel,
			"box.Get":          declaredIn(t, project, "Box", "Get"),
			"pair.Get":         declaredIn(t, project, "Pair", "Get"),
		} {
			objects := used[selector]
			require.NotEmpty(t, objects, selector)
			file, declaration, err := project.DeclarationForObject(objects[0])
			require.NoError(t, err, selector)
			assert.Equal(t, "shared/names.go", file.RelPath, selector)
			assert.Same(t, want, declaration, selector)
		}
	}
}

func requireCgo(t *testing.T) {
	t.Helper()
	out, err := exec.Command("go", "env", "CGO_ENABLED").Output()
	require.NoError(t, err)
	if strings.TrimSpace(string(out)) != "1" {
		t.Skip("cgo is disabled")
	}
}

// A cgo package is type-checked from files the go command generated: the
// file of an object of it is still found by its trimmed path, its declaration
// is not, and that is an error rather than a wrong declaration.
func TestFileForObjectCgoNestedModule(t *testing.T) {
	requireCgo(t)
	root, contexts := writeNestedTrimpathProject(t, map[string]string{
		"go.mod":        "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod": "module example.com/shared\n\ngo 1.24\n",
		"shared/request.go": `package shared

/*
static int seven(void) { return 7; }
*/
import "C"

type Input struct {
	StrategyID string
}

func Seven() int { return int(C.seven()) }
`,
		"app.go": "package app\n\nimport \"example.com/shared\"\n\nfunc Use(input shared.Input) string { return input.StrategyID }\n",
	})
	project, err := LoadGoProject(root, contexts, GoProjectOptions{})
	require.NoError(t, err)
	field := usedObjects(projectPackage(t, project, "example.com/app"))["input.StrategyID"][0]
	assert.Equal(t, "example.com/shared@v0.0.0/request.go", project.FileSet.PositionFor(field.Pos(), false).Filename)
	file, err := project.FileForObject(field)
	require.NoError(t, err)
	assert.Equal(t, "shared/request.go", file.RelPath)
	_, _, err = project.DeclarationForObject(field)
	require.ErrorContains(t, err, "no declaration at that source position")
	require.ErrorIs(t, err, ErrObjectNotInRun, "a declaration missing from the syntax of the run is skipped as an object outside it")
}

// A //line directive tells another file and line for a declaration.
// FileForObject names the file that holds the declaration, as FileForPosition
// does; DeclaredAt names the file and the line of the directive, both from one
// position, and a directive to a file outside the project resolves to no file.
// Export data, as go/packages reads it, keeps the file of the directive and
// the line in the source file.
func TestDeclaredAtLineDirective(t *testing.T) {
	root := t.TempDir()
	generated := func(pkg string) string {
		return "package " + pkg + "\n\n//line limits.y:40\nconst MaxDays = 5\n\n//line /elsewhere/rules.y:7\nconst GraceDays = 3\n\n//line " +
			filepath.Join(root, pkg, "other.go") + ":3\nconst Spare = 2\n"
	}
	contexts := writeProjectIn(t, root, map[string]string{
		"go.mod":          "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"limits/gen.go":   generated("limits"),
		"limits/other.go": "package limits\n",
		"shared/go.mod":   "module example.com/shared\n\ngo 1.24\n",
		"shared/gen.go":   generated("shared"),
		"shared/other.go": "package shared\n",
		"app.go":          "package app\n\nimport (\"example.com/app/limits\"; \"example.com/shared\")\n\nvar Sum = shared.MaxDays + shared.GraceDays + shared.Spare + limits.Spare\n",
	})
	project, err := LoadGoProject(root, contexts, GoProjectOptions{})
	require.NoError(t, err)
	limits := projectPackage(t, project, "example.com/app/limits").Types.Scope()
	used := usedObjects(projectPackage(t, project, "example.com/app"))
	for name, want := range map[string]struct {
		object   types.Object
		file     string
		declared string
	}{
		"limits.MaxDays":   {limits.Lookup("MaxDays"), "limits/gen.go", ""},
		"limits.GraceDays": {limits.Lookup("GraceDays"), "limits/gen.go", ""},
		"limits.Spare":     {limits.Lookup("Spare"), "limits/gen.go", "limits/other.go:3"},
		"shared.MaxDays":   {used["shared.MaxDays"][0], "", ""},
		"shared.GraceDays": {used["shared.GraceDays"][0], "", ""},
		"shared.Spare":     {used["shared.Spare"][0], "shared/other.go", "shared/other.go:10"},
	} {
		file, err := project.FileForObject(want.object)
		if want.file == "" {
			require.Error(t, err, name)
		} else {
			require.NoError(t, err, name)
			assert.Equal(t, want.file, file.RelPath, name)
		}
		file, line, err := project.DeclaredAt(want.object)
		if want.declared == "" {
			require.Error(t, err, name)
			continue
		}
		require.NoError(t, err, name)
		assert.Equal(t, want.declared, fmt.Sprintf("%s:%d", file.RelPath, line), name)
	}
}

// Fields of one name on one line whose types differ only by the path of
// their package, two packages of one name, are two declarations.
func TestDeclarationForObjectNamesakesOfOnePackageName(t *testing.T) {
	root, contexts := writeNestedTrimpathProject(t, map[string]string{
		"go.mod":                 "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod":          "module example.com/shared\n\ngo 1.24\n",
		"shared/left/item/i.go":  "package item\n\ntype Item struct{}\n",
		"shared/right/item/i.go": "package item\n\ntype Item struct{}\n",
		"shared/names.go": `package shared

import (
	"example.com/shared/left/item"
	other "example.com/shared/right/item"
)

type Left struct{ Items []item.Item }; type Right struct{ Items []other.Item }
`,
		"app.go": "package app\n\nimport \"example.com/shared\"\n\nfunc Use(left shared.Left, right shared.Right) bool { return left.Items == nil && right.Items == nil }\n",
	})
	project, err := LoadGoProject(root, contexts, GoProjectOptions{})
	require.NoError(t, err)
	scope := projectPackage(t, project, "example.com/shared").Types.Scope()
	used := usedObjects(projectPackage(t, project, "example.com/app"))
	for selector, typeName := range map[string]string{"left.Items": "Left", "right.Items": "Right"} {
		_, declaration, err := project.DeclarationForObject(used[selector][0])
		require.NoError(t, err, selector)
		assert.Same(t, scope.Lookup(typeName).Type().Underlying().(*types.Struct).Field(0), declaration, selector)
	}
}
