// Package rulestest builds throwaway Go modules for rule tests, so that a test
// can state the source it cares about and get a loaded project back.
package rulestest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

const defaultGoMod = "module example.com/rulestest\n\ngo 1.24\n"

// Module writes the given files into a fresh temporary directory, adding a
// go.mod when the caller did not provide one, and returns the module root
// together with the file contexts of its Go files in path order.
func Module(t *testing.T, files map[string]string) (string, []*core.FileContext) {
	t.Helper()

	root := t.TempDir()
	names := make([]string, 0, len(files)+1)
	for name := range files {
		names = append(names, name)
	}
	if _, ok := files["go.mod"]; !ok {
		names = append(names, "go.mod")
	}
	sort.Strings(names)

	var contexts []*core.FileContext
	for _, name := range names {
		content, ok := files[name]
		if !ok {
			content = defaultGoMod
		}
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

		if !strings.HasSuffix(name, ".go") {
			continue
		}
		ctx, err := core.NewFileContextChecked(path, root, []byte(content), core.DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}

	return root, contexts
}

// Project loads the module written by Module as a typed Go project.
func Project(t *testing.T, files map[string]string) *core.GoProjectContext {
	t.Helper()
	return load(t, files, false)
}

// ProjectWithSSA loads the module and builds SSA for rules that need it.
func ProjectWithSSA(t *testing.T, files map[string]string) *core.GoProjectContext {
	t.Helper()
	return load(t, files, true)
}

func load(t *testing.T, files map[string]string, withSSA bool) *core.GoProjectContext {
	t.Helper()
	root, contexts := Module(t, files)
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{RequireSSA: withSSA})
	require.NoError(t, err)
	return project
}

// GoFile builds a file context with its Go syntax tree parsed, for rules that
// analyze one file at a time.
func GoFile(t *testing.T, path, source string) *core.FileContext {
	t.Helper()

	root := t.TempDir()
	full := filepath.Join(root, path)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(source), 0o644))

	ctx, err := core.NewFileContextChecked(full, root, []byte(source), core.DefaultConfig())
	require.NoError(t, err)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, full, source, parser.ParseComments)
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)

	return ctx
}

// TextFile builds a file context without parsing, for rules that work on lines
// — TypeScript, Markdown, SQL.
func TextFile(t *testing.T, path, source string) *core.FileContext {
	t.Helper()

	root := t.TempDir()
	full := filepath.Join(root, path)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(source), 0o644))

	ctx, err := core.NewFileContextChecked(full, root, []byte(source), core.DefaultConfig())
	require.NoError(t, err)
	return ctx
}
