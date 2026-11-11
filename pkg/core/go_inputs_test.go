package core

import (
	"go/ast"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeInputsFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// inputsModule is a module with the analyzed root in svc/ and a sibling
// package the root imports.
func inputsModule(t *testing.T) (module, root string) {
	t.Helper()
	module = t.TempDir()
	writeInputsFile(t, module, "go.mod", "module example.com/inputs\n\ngo 1.22\n")
	writeInputsFile(t, module, "svc/svc.go", "package svc\n\nimport \"example.com/inputs/lib\"\n\nvar V = lib.X\n")
	writeInputsFile(t, module, "lib/lib.go", "package lib\n\nvar X = 1\n")
	writeInputsFile(t, module, "web/app.ts", "export const a = 1\n")
	return module, filepath.Join(module, "svc")
}

func inputsOf(t *testing.T, root string) (string, bool) {
	t.Helper()
	contexts := []*FileContext{NewFileContext(filepath.Join(root, "svc.go"), root, mustRead(t, filepath.Join(root, "svc.go")), DefaultConfig())}
	hash, cacheable, err := NewGoProjectLoader().GoInputs(root, contexts, false)
	require.NoError(t, err)
	return hash, cacheable
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// The hash covers what the typed load reads — the module's Go sources outside
// the root and its module files — and nothing the load ignores.
func TestGoInputsChangeWithWhatTheLoadReads(t *testing.T) {
	module, root := inputsModule(t)
	base, cacheable := inputsOf(t, root)
	require.True(t, cacheable)
	again, _ := inputsOf(t, root)
	require.Equal(t, base, again, "same inputs, same hash")

	for name, edit := range map[string]func(){
		"frontend file": func() { writeInputsFile(t, module, "web/app.ts", "export const a = 2\n") },
		"testdata":      func() { writeInputsFile(t, module, "lib/testdata/x.go", "package x\n") },
		"hidden dir":    func() { writeInputsFile(t, module, ".cache/x.go", "package x\n") },
		"node_modules":  func() { writeInputsFile(t, module, "web/node_modules/x/x.go", "package x\n") },
		"nested module": func() {
			writeInputsFile(t, module, "tools/go.mod", "module example.com/tools\n")
			writeInputsFile(t, module, "tools/t.go", "package tools\n")
		},
	} {
		edit()
		got, _ := inputsOf(t, root)
		assert.Equal(t, base, got, "%s is not read by the load", name)
	}

	for name, edit := range map[string]func(){
		"sibling package": func() { writeInputsFile(t, module, "lib/lib.go", "package lib\n\nvar X = 2\n") },
		"new Go file":     func() { writeInputsFile(t, module, "lib/more.go", "package lib\n") },
		"go.sum":          func() { writeInputsFile(t, module, "go.sum", "example.com/x v1.0.0 h1:x=\n") },
		"cgo source":      func() { writeInputsFile(t, module, "lib/x.h", "int x;\n") },
	} {
		prev, _ := inputsOf(t, root)
		edit()
		got, _ := inputsOf(t, root)
		assert.NotEqual(t, prev, got, "%s changes the load", name)
	}
}

// Project rules check SQL against the schema the migrations leave: the SQL
// files under the root are inputs too, wherever the module is.
func TestGoInputsChangeWithSQLFiles(t *testing.T) {
	_, root := inputsModule(t)
	writeInputsFile(t, root, "migrations/001_init.up.sql", "CREATE TABLE a (id INT);\n")
	hashWith := func() string {
		contexts := []*FileContext{
			NewFileContext(filepath.Join(root, "svc.go"), root, mustRead(t, filepath.Join(root, "svc.go")), DefaultConfig()),
			NewFileContext(filepath.Join(root, "migrations/001_init.up.sql"), root, mustRead(t, filepath.Join(root, "migrations/001_init.up.sql")), DefaultConfig()),
		}
		hash, _, err := NewGoProjectLoader().GoInputs(root, contexts, false)
		require.NoError(t, err)
		return hash
	}
	base := hashWith()
	writeInputsFile(t, root, "migrations/001_init.up.sql", "CREATE TABLE a (id INT, name TEXT);\n")
	assert.NotEqual(t, base, hashWith(), "a changed migration changes the project findings")
}

// Project rules check templates against the Go types rendered into them: a
// changed template changes the project findings.
func TestGoInputsChangeWithTemplates(t *testing.T) {
	_, root := inputsModule(t)
	writeInputsFile(t, root, "templates/page.html", "{{.Title}}\n")
	hashWith := func() string {
		contexts := []*FileContext{
			NewFileContext(filepath.Join(root, "svc.go"), root, mustRead(t, filepath.Join(root, "svc.go")), DefaultConfig()),
			NewFileContext(filepath.Join(root, "templates/page.html"), root, mustRead(t, filepath.Join(root, "templates/page.html")), DefaultConfig()),
		}
		hash, _, err := NewGoProjectLoader().GoInputs(root, contexts, false)
		require.NoError(t, err)
		return hash
	}
	base := hashWith()
	writeInputsFile(t, root, "templates/page.html", "{{range .Rows}}{{.Title}}{{end}}\n")
	assert.NotEqual(t, base, hashWith(), "a changed template changes the project findings")
}

// A project rule keeps a Go type that hand-written TypeScript imports from
// generated TypeScript: a new import of a generated name changes the project
// findings, another edit of the frontend does not.
func TestGoInputsChangeWithGeneratedTSImports(t *testing.T) {
	_, root := inputsModule(t)
	writeInputsFile(t, root, "web/types.ts", "// Code generated by typegen. DO NOT EDIT.\n\nexport interface Item { id: string }\n")
	writeInputsFile(t, root, "web/app.ts", "export const a = 1\n")
	hashWith := func() string {
		var contexts []*FileContext
		for _, rel := range []string{"svc.go", "web/types.ts", "web/app.ts"} {
			contexts = append(contexts, NewFileContext(filepath.Join(root, rel), root, mustRead(t, filepath.Join(root, rel)), DefaultConfig()))
		}
		hash, _, err := NewGoProjectLoader().GoInputs(root, contexts, false)
		require.NoError(t, err)
		return hash
	}
	base := hashWith()
	writeInputsFile(t, root, "web/app.ts", "export const a = 2\n")
	assert.Equal(t, base, hashWith(), "an edit that imports nothing generated keeps the findings")
	writeInputsFile(t, root, "web/app.ts", "import type { Item } from './types'\n\nexport const a = (i: Item) => i.id\n")
	assert.NotEqual(t, base, hashWith(), "a new import of a generated name changes the project findings")
}

// A replace to a missing local directory is not cacheable.
func TestGoInputsNotCacheableWithMissingLocalReplaceTarget(t *testing.T) {
	module, root := inputsModule(t)
	writeInputsFile(t, module, "go.mod", "module example.com/inputs\n\ngo 1.22\n\nreplace example.com/dep => ../dep\n")
	_, cacheable := inputsOf(t, root)
	assert.False(t, cacheable)
}

func replaceInputs(t *testing.T, module string) (string, bool) {
	t.Helper()
	context := NewFileContext(filepath.Join(module, "svc.go"), module, mustRead(t, filepath.Join(module, "svc.go")), DefaultConfig())
	hash, cacheable, err := NewGoProjectLoader().GoInputs(module, []*FileContext{context}, false)
	require.NoError(t, err)
	return hash, cacheable
}

func replaceModule(t *testing.T, dir, name, source string) {
	t.Helper()
	writeInputsFile(t, dir, "go.mod", "module "+name+"\n\ngo 1.22\n")
	writeInputsFile(t, dir, "svc.go", source)
}

func TestGoInputsCacheableWithLocalReplaceModule(t *testing.T) {
	repo := t.TempDir()
	module := filepath.Join(repo, "b")
	target := filepath.Join(repo, "a")
	replaceModule(t, module, "example.com/repo/tools/b", "package b\n")
	replaceModule(t, target, "example.com/repo/tools/a", "package a\n")
	writeInputsFile(t, module, "go.mod", "module example.com/repo/tools/b\n\ngo 1.22\n\nrequire example.com/repo/tools/a v0.0.0\nreplace example.com/repo/tools/a => ../a\n")

	hash, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	writeInputsFile(t, target, "svc.go", "package a\nvar X = 1\n")
	changedSource, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, hash, changedSource, "a Go source in the replace target changes the hash")

	writeInputsFile(t, target, "go.mod", "module example.com/repo/tools/a\n\ngo 1.22\n\n// changed\n")
	changedModule, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, changedSource, changedModule, "the replace target go.mod changes the hash")
}

func TestGoInputsHashesChainedLocalReplaces(t *testing.T) {
	repo := t.TempDir()
	module := filepath.Join(repo, "b")
	target := filepath.Join(repo, "a")
	third := filepath.Join(repo, "c")
	replaceModule(t, module, "example.com/repo/b", "package b\n")
	replaceModule(t, target, "example.com/repo/a", "package a\n")
	replaceModule(t, third, "example.com/repo/c", "package c\n")
	writeInputsFile(t, module, "go.mod", "module example.com/repo/b\n\ngo 1.22\n\nreplace example.com/repo/a => ../a\n")
	writeInputsFile(t, target, "go.mod", "module example.com/repo/a\n\ngo 1.22\n\nreplace example.com/repo/c => ../c\n")

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	writeInputsFile(t, third, "svc.go", "package c\nvar X = 2\n")
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got)
}

func TestGoInputsLocalReplaceCycle(t *testing.T) {
	repo := t.TempDir()
	a := filepath.Join(repo, "a")
	b := filepath.Join(repo, "b")
	replaceModule(t, a, "example.com/repo/a", "package a\n")
	replaceModule(t, b, "example.com/repo/b", "package b\n")
	writeInputsFile(t, a, "go.mod", "module example.com/repo/a\n\ngo 1.22\n\nreplace example.com/repo/b => ../b\n")
	writeInputsFile(t, b, "go.mod", "module example.com/repo/b\n\ngo 1.22\n\nreplace example.com/repo/a => ../a\n")

	_, cacheable := replaceInputs(t, a)
	assert.True(t, cacheable, "a cycle of local replaces terminates and remains cacheable")
}

func TestGoInputsAbsoluteLocalReplace(t *testing.T) {
	repo := t.TempDir()
	module := filepath.Join(repo, "b")
	target := filepath.Join(repo, "a")
	replaceModule(t, module, "example.com/repo/b", "package b\n")
	replaceModule(t, target, "example.com/repo/a", "package a\n")
	writeInputsFile(t, module, "go.mod", "module example.com/repo/b\n\ngo 1.22\n\nreplace example.com/repo/a => "+target+"\n")

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	writeInputsFile(t, target, "svc.go", "package a\nvar X = 3\n")
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got, "an absolute replace target is hashed")
}

func TestGoInputsHashChangesWhenLocalReplaceTargetChanges(t *testing.T) {
	repo := t.TempDir()
	module := filepath.Join(repo, "b")
	first := filepath.Join(repo, "a")
	second := filepath.Join(repo, "other")
	replaceModule(t, module, "example.com/repo/b", "package b\n")
	replaceModule(t, first, "example.com/repo/a", "package a\n")
	replaceModule(t, second, "example.com/repo/a", "package a\n")
	writeInputsFile(t, module, "go.mod", "module example.com/repo/b\n\ngo 1.22\n\nreplace example.com/repo/a => ../a\n")

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	writeInputsFile(t, module, "go.mod", "module example.com/repo/b\n\ngo 1.22\n\nreplace example.com/repo/a => ../other\n")
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got, "the local replace target path is part of the hash")
}

func TestGoInputsLocalReplaceWithoutGoModIsNotCacheable(t *testing.T) {
	repo := t.TempDir()
	module := filepath.Join(repo, "b")
	target := filepath.Join(repo, "a")
	replaceModule(t, module, "example.com/repo/b", "package b\n")
	writeInputsFile(t, target, "a.go", "package a\n")
	writeInputsFile(t, module, "go.mod", "module example.com/repo/b\n\ngo 1.22\n\nreplace example.com/repo/a => ../a\n")

	_, cacheable := replaceInputs(t, module)
	assert.False(t, cacheable)
}

func TestGoInputsWorkspaceLocalReplace(t *testing.T) {
	repo := t.TempDir()
	module := filepath.Join(repo, "b")
	target := filepath.Join(repo, "a")
	replaceModule(t, module, "example.com/repo/b", "package b\n")
	replaceModule(t, target, "example.com/repo/a", "package a\n")
	writeInputsFile(t, repo, "go.work", "go 1.22\n\nuse (\n ./b\n)\n\nreplace example.com/repo/a => ./a\n")

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	writeInputsFile(t, target, "svc.go", "package a\nvar X = 2\n")
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got)
}

func TestGoInputsHashesSymlinkedOwnModuleRoot(t *testing.T) {
	parent := t.TempDir()
	module := filepath.Join(parent, "real")
	link := filepath.Join(parent, "module")
	replaceModule(t, module, "example.com/repo/a", "package a\n")
	require.NoError(t, os.Symlink(module, link))

	base, cacheable := replaceInputs(t, link)
	require.True(t, cacheable)
	writeInputsFile(t, module, "svc.go", "package a\nvar X = 1\n")
	got, cacheable := replaceInputs(t, link)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got)
}

func TestGoInputsHashesSymlinkedLocalReplaceTarget(t *testing.T) {
	repo := t.TempDir()
	module := filepath.Join(repo, "b")
	target := filepath.Join(repo, "real")
	link := filepath.Join(repo, "alink")
	replaceModule(t, module, "example.com/repo/b", "package b\n")
	replaceModule(t, target, "example.com/repo/a", "package a\n")
	require.NoError(t, os.Symlink(target, link))
	writeInputsFile(t, module, "go.mod", "module example.com/repo/b\n\ngo 1.22\n\nreplace example.com/repo/a => ../alink\n")

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	writeInputsFile(t, target, "svc.go", "package a\nvar X = 1\n")
	changedSource, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, changedSource, "a Go file under the resolved replace root changes the hash")

	writeInputsFile(t, target, "go.mod", "module example.com/repo/a\n\ngo 1.22\n\n// changed\n")
	changedModule, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, changedSource, changedModule, "go.mod under the resolved replace root changes the hash")
}

func TestGoInputsHashesSymlinkedWorkspaceReplaceTarget(t *testing.T) {
	repo := t.TempDir()
	module := filepath.Join(repo, "b")
	target := filepath.Join(repo, "real")
	link := filepath.Join(repo, "alink")
	replaceModule(t, module, "example.com/repo/b", "package b\n")
	replaceModule(t, target, "example.com/repo/a", "package a\n")
	require.NoError(t, os.Symlink(target, link))
	writeInputsFile(t, repo, "go.work", "go 1.22\n\nuse ./b\n\nreplace example.com/repo/a => ./alink\n")

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	writeInputsFile(t, target, "svc.go", "package a\nvar X = 1\n")
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got)
}

func TestGoInputsHashesSymlinkedGoSourceFiles(t *testing.T) {
	parent := t.TempDir()
	module := filepath.Join(parent, "module")
	replaceModule(t, module, "example.com/repo/a", "package a\n")
	real := filepath.Join(parent, "real.go")
	writeInputsFile(t, parent, "real.go", "package a\nvar X = 1\n")
	require.NoError(t, os.Symlink(real, filepath.Join(module, "alias.go")))
	require.NoError(t, os.Symlink(filepath.Join(parent, "missing.go"), filepath.Join(module, "dangling.go")))

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	writeInputsFile(t, module, "real.go", "package a\nvar X = 2\n")
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got)
}

func TestGoInputsHashChangesWhenSymlinkedFileTargetChanges(t *testing.T) {
	parent := t.TempDir()
	module := filepath.Join(parent, "module")
	replaceModule(t, module, "example.com/repo/module", "package module\n")
	writeInputsFile(t, parent, "first.data", "same contents\n")
	writeInputsFile(t, parent, "second.data", "same contents\n")
	require.NoError(t, os.Symlink(filepath.Join(parent, "first.data"), filepath.Join(module, "alias.data")))

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	require.NoError(t, os.Remove(filepath.Join(module, "alias.data")))
	require.NoError(t, os.Symlink(filepath.Join(parent, "second.data"), filepath.Join(module, "alias.data")))
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got, "the resolved target path of a file symlink is part of the hash")
}

func TestGoInputsHashChangesWhenDanglingSymlinkTargetAppears(t *testing.T) {
	parent := t.TempDir()
	module := filepath.Join(parent, "module")
	target := filepath.Join(parent, "target.data")
	replaceModule(t, module, "example.com/repo/module", "package module\n")
	require.NoError(t, os.Symlink(target, filepath.Join(module, "alias.data")))

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	writeInputsFile(t, parent, "target.data", "non-Go target\n")
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got, "a dangling symlink becoming live changes the hash")
}

func TestGoInputsWalksSymlinkedPackageDirectoriesOnce(t *testing.T) {
	parent := t.TempDir()
	module := filepath.Join(parent, "module")
	replaceModule(t, module, "example.com/repo/a", "package a\n")
	target := filepath.Join(parent, "realpkg")
	writeInputsFile(t, target, "pkg.go", "package realpkg\nvar X = 1\n")
	require.NoError(t, os.Symlink(target, filepath.Join(module, "aliaspkg")))
	require.NoError(t, os.Symlink(target, filepath.Join(module, "lib64")))

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	writeInputsFile(t, target, "pkg.go", "package realpkg\nvar X = 2\n")
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got)
}

func TestGoInputsWorkspaceReplaceWithoutModuleIsNotCacheable(t *testing.T) {
	for _, targetKind := range []string{"missing", "directory", "file"} {
		t.Run(targetKind, func(t *testing.T) {
			repo := t.TempDir()
			module := filepath.Join(repo, "b")
			replaceModule(t, module, "example.com/repo/b", "package b\n")
			switch targetKind {
			case "directory":
				require.NoError(t, os.MkdirAll(filepath.Join(repo, "target"), 0o755))
			case "file":
				writeInputsFile(t, repo, "target", "not a module")
			}
			writeInputsFile(t, repo, "go.work", "go 1.22\n\nuse ./b\n\nreplace example.com/repo/a => ./target\n")

			_, cacheable, err := NewGoProjectLoader().GoInputs(module, []*FileContext{
				NewFileContext(filepath.Join(module, "svc.go"), module, mustRead(t, filepath.Join(module, "svc.go")), DefaultConfig()),
			}, false)
			require.NoError(t, err)
			assert.False(t, cacheable)
		})
	}
}

func TestGoInputsHashChangesWhenSymlinkedPackageIsRenamed(t *testing.T) {
	parent := t.TempDir()
	module := filepath.Join(parent, "module")
	target := filepath.Join(parent, "package")
	replaceModule(t, module, "example.com/repo/module", "package module\n")
	writeInputsFile(t, target, "pkg.go", "package package\nvar X = 1\n")
	require.NoError(t, os.Symlink(target, filepath.Join(module, "lib")))

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	require.NoError(t, os.Rename(filepath.Join(module, "lib"), filepath.Join(module, "lib2")))
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got, "the symlink path defines the package path")
}

func TestGoInputsHashChangesWhenSecondSymlinkNamesPackage(t *testing.T) {
	parent := t.TempDir()
	module := filepath.Join(parent, "module")
	target := filepath.Join(parent, "package")
	replaceModule(t, module, "example.com/repo/module", "package module\n")
	writeInputsFile(t, target, "pkg.go", "package package\nvar X = 1\n")
	require.NoError(t, os.Symlink(target, filepath.Join(module, "lib")))

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	require.NoError(t, os.Symlink(target, filepath.Join(module, "lib2")))
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got, "a second symlink path changes the package paths")
}

func TestGoInputsHashChangesWhenReplaceSymlinkPackageIsRenamed(t *testing.T) {
	parent := t.TempDir()
	module := filepath.Join(parent, "b")
	target := filepath.Join(parent, "a")
	packageDir := filepath.Join(parent, "package")
	replaceModule(t, module, "example.com/repo/b", "package b\n")
	replaceModule(t, target, "example.com/repo/a", "package a\n")
	writeInputsFile(t, packageDir, "pkg.go", "package package\nvar X = 1\n")
	require.NoError(t, os.Symlink(packageDir, filepath.Join(target, "lib")))
	writeInputsFile(t, module, "go.mod", "module example.com/repo/b\n\ngo 1.22\n\nreplace example.com/repo/a => ../a\n")

	base, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	require.NoError(t, os.Rename(filepath.Join(target, "lib"), filepath.Join(target, "lib2")))
	got, cacheable := replaceInputs(t, module)
	require.True(t, cacheable)
	assert.NotEqual(t, base, got, "the replace module's symlink path changes the package paths")
}

func TestGoInputsUncacheableWithoutErrorForUnreadableSymlinkDirectory(t *testing.T) {
	parent := t.TempDir()
	module := filepath.Join(parent, "module")
	locked := filepath.Join(parent, "locked")
	replaceModule(t, module, "example.com/repo/module", "package module\n")
	writeInputsFile(t, locked, "nested/pkg.go", "package nested\n")
	require.NoError(t, os.Chmod(filepath.Join(locked, "nested"), 0))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(locked, "nested"), 0o755) })
	if _, err := os.ReadDir(filepath.Join(locked, "nested")); err == nil {
		t.Skip("the current user can read mode-000 directories")
	}
	require.NoError(t, os.Symlink(locked, filepath.Join(module, "external")))

	_, cacheable, err := NewGoProjectLoader().GoInputs(module, []*FileContext{
		NewFileContext(filepath.Join(module, "svc.go"), module, mustRead(t, filepath.Join(module, "svc.go")), DefaultConfig()),
	}, false)
	require.NoError(t, err)
	assert.False(t, cacheable)
}

func TestGoInputsVersionedReplaceRemainsCacheable(t *testing.T) {
	module := t.TempDir()
	replaceModule(t, module, "example.com/repo/b", "package b\n")
	writeInputsFile(t, module, "go.mod", "module example.com/repo/b\n\ngo 1.22\n\nreplace example.com/repo/a => example.com/fork/a v1.2.3\n")
	_, cacheable := replaceInputs(t, module)
	assert.True(t, cacheable)
}

// Trees parsed without a load match the load's: identifiers stay unresolved,
// and a file excluded by build constraints that does not parse has none.
func TestParseGoFilesMatchesTheLoad(t *testing.T) {
	root := t.TempDir()
	good := NewFileContext(filepath.Join(root, "a.go"), root, []byte("package a\n\nvar x = 1\nvar y = x\n"), DefaultConfig())
	ignored := NewFileContext(filepath.Join(root, "gen.go"), root, []byte("//go:build ignore\n\n{{template}}\n"), DefaultConfig())
	writeInputsFile(t, root, "gen.go", "//go:build ignore\n\n{{template}}\n")
	broken := NewFileContext(filepath.Join(root, "b.go"), root, []byte("package a\n\nfunc {\n"), DefaultConfig())
	writeInputsFile(t, root, "b.go", "package a\n\nfunc {\n")

	require.Error(t, ParseGoFiles(root, []*FileContext{good, ignored, broken}, false))
	require.NoError(t, ParseGoFiles(root, []*FileContext{good, ignored, broken}, true))

	require.NotNil(t, good.GoAST)
	assert.Nil(t, ignored.GoAST)
	assert.Nil(t, broken.GoAST)
	ast.Inspect(good.GoAST, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			assert.Nil(t, ident.Obj, "identifier %s is resolved; the load leaves it to go/types", ident.Name) //nolint:staticcheck // checking that the deprecated field stays empty
		}
		return true
	})
}

// Links that loop lead nowhere the go command reads, so they count as
// dangling: the module stays cacheable and the hash reports no error.
func TestGoInputsSymlinkLoopCountsAsDangling(t *testing.T) {
	module := filepath.Join(t.TempDir(), "module")
	replaceModule(t, module, "example.com/repo/module", "package module\n")
	require.NoError(t, os.Symlink("lb", filepath.Join(module, "la")))
	require.NoError(t, os.Symlink("la", filepath.Join(module, "lb")))

	_, cacheable := replaceInputs(t, module)
	assert.True(t, cacheable)
}
