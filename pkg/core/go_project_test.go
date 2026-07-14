package core

import (
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeGoModule(t *testing.T, files map[string]string) (string, []*FileContext) {
	t.Helper()
	root := t.TempDir()
	files["go.mod"] = "module example.com/project\n\ngo 1.24\n"
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	}

	var contexts []*FileContext
	for name, content := range files {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		ctx, err := NewFileContextChecked(filepath.Join(root, name), root, []byte(content), DefaultConfig())
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
	project, err := loadGoProject(root, contexts, true, func(path string) {
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

	_, err := LoadGoProject(root, contexts, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an int")
}

func TestLoadGoProjectUsesExcludedCompiledFileForTypesWithoutAnalyzingIt(t *testing.T) {
	root, contexts := writeGoModule(t, map[string]string{
		"first.go":  "package project\n\nfunc First() Second { return Second{} }\n",
		"second.go": "package project\n\ntype Second struct{}\n",
	})
	contexts = contexts[:1]

	project, err := LoadGoProject(root, contexts, true)
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

	project, err := LoadGoProject(root, contexts, true)
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

	_, err = LoadGoProject(root, []*FileContext{ctx}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside a Go module")
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
