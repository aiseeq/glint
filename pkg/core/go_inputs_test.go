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

// A replace to a local directory makes the load read a tree the hash does not
// walk: such a project is not cached.
func TestGoInputsNotCacheableWithLocalReplace(t *testing.T) {
	module, root := inputsModule(t)
	writeInputsFile(t, module, "go.mod", "module example.com/inputs\n\ngo 1.22\n\nreplace example.com/dep => ../dep\n")
	_, cacheable := inputsOf(t, root)
	assert.False(t, cacheable)
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
