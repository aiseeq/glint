package core

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFileContext(t *testing.T) {
	content := []byte("package main\n\nfunc main() {}")
	cfg := DefaultConfig()

	ctx := NewFileContext("/project/test.go", "/project", content, cfg)

	assert.Equal(t, "/project/test.go", ctx.Path)
	assert.Equal(t, "test.go", ctx.RelPath)
	assert.Equal(t, "/project", ctx.ProjectRoot)
	assert.Equal(t, content, ctx.Content)
	assert.Len(t, ctx.Lines, 3)
}

func TestNewFileContextChecked(t *testing.T) {
	ctx, err := NewFileContextChecked("/project/pkg/file.go", "/project", []byte("package pkg"), DefaultConfig())
	require.NoError(t, err)
	require.Equal(t, "pkg/file.go", ctx.RelPath)
}

func TestFileContextIsGoFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/project/main.go", true},
		{"/project/pkg/util.go", true},
		{"/project/main_test.go", true},
		{"/project/app.ts", false},
		{"/project/readme.md", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			ctx := &FileContext{Path: tt.path}
			assert.Equal(t, tt.expected, ctx.IsGoFile())
		})
	}
}

func TestFileContextIsTypeScriptFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/project/app.ts", true},
		{"/project/component.tsx", true},
		{"/project/main.go", false},
		{"/project/style.css", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			ctx := &FileContext{Path: tt.path}
			assert.Equal(t, tt.expected, ctx.IsTypeScriptFile())
		})
	}
}

func TestFileContextIsJavaScriptFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/project/app.js", true},
		{"/project/component.jsx", true},
		{"/project/main.go", false},
		{"/project/app.ts", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			ctx := &FileContext{Path: tt.path}
			assert.Equal(t, tt.expected, ctx.IsJavaScriptFile())
		})
	}
}

func TestFileContextIsTestFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"main_test.go", true},
		{"app.test.ts", true},
		{"app.spec.js", true},
		{"test/helper.go", true},
		{"internal/testdata/fixture.go", true},
		{"__tests__/app.ts", true},
		{"test_helper.go", false},
		{"main.go", false},
		{"app.ts", false},
		{"latest/app.ts", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			ctx := NewFileContext("/project/"+tt.path, "/project", nil, nil)
			assert.Equal(t, tt.expected, ctx.IsTestFile())
		})
	}
}

// Where the checkout lives says nothing about its files: a project cloned into
// a directory named test must not be test code as a whole.
func TestFileContextIsTestFileIgnoresDirectoriesAboveProjectRoot(t *testing.T) {
	ctx := NewFileContext("/builds/test/project/internal/app.go", "/builds/test/project", nil, nil)
	assert.False(t, ctx.IsTestFile())
}

// A Go test-helper package — the idiom of net/http/httptest and testing/fstest:
// its name ends in "test" and one of its files imports testing. A package
// named latest that never imports testing is not, nor is an ordinary package
// that imports testing; IsTestFile does not look at the directory.
func TestIsTestHelperDir(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) string {
		path := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
		return path
	}
	write("internal/storetest/scene.go", "package storetest\n\nimport \"testing\"\n\nfunc Scene(t *testing.T) { t.Helper() }\n")
	fixture := write("internal/storetest/fixture.go", "package storetest\n\nfunc Fixture() int { return 1 }\n")
	write("api/latest/handler.go", "package latest\n\nfunc Handle() int { return 2 }\n")
	write("internal/store/store.go", "package store\n\nimport \"testing\"\n\nvar _ = testing.Short\n")

	for dir, want := range map[string]bool{"internal/storetest": true, "api/latest": false, "internal/store": false} {
		got, err := IsTestHelperDir(filepath.Join(root, dir))
		require.NoError(t, err)
		assert.Equal(t, want, got, dir)
	}
	assert.False(t, NewFileContext(fixture, root, nil, nil).IsTestFile(), "IsTestFile is a property of the file alone")
}

func TestFileContextGetLine(t *testing.T) {
	ctx := &FileContext{
		Lines: []string{"line1", "line2", "line3"},
	}

	assert.Equal(t, "line1", ctx.GetLine(1))
	assert.Equal(t, "line2", ctx.GetLine(2))
	assert.Equal(t, "line3", ctx.GetLine(3))
	assert.Equal(t, "", ctx.GetLine(0))  // out of bounds
	assert.Equal(t, "", ctx.GetLine(4))  // out of bounds
	assert.Equal(t, "", ctx.GetLine(-1)) // negative
}

func TestFileContextGetLines(t *testing.T) {
	ctx := &FileContext{
		Lines: []string{"line1", "line2", "line3", "line4", "line5"},
	}

	lines := ctx.GetLines(2, 4)
	assert.Equal(t, []string{"line2", "line3", "line4"}, lines)

	// Out of bounds handling
	lines = ctx.GetLines(4, 10)
	assert.Equal(t, []string{"line4", "line5"}, lines)

	// Start less than 1
	lines = ctx.GetLines(-1, 2)
	assert.Equal(t, []string{"line1", "line2"}, lines)

	// Invalid range
	lines = ctx.GetLines(5, 2)
	assert.Nil(t, lines)
}

func TestFileContextGetContext(t *testing.T) {
	ctx := &FileContext{
		Lines: []string{"1", "2", "3", "4", "5", "6", "7"},
	}

	// Get context around line 4 with 2 lines context
	lines := ctx.GetContext(4, 2)
	assert.Equal(t, []string{"2", "3", "4", "5", "6"}, lines)
}

func TestFileContextHasGoAST(t *testing.T) {
	ctx := &FileContext{}
	assert.False(t, ctx.HasGoAST())

	ctx.GoAST = nil
	assert.False(t, ctx.HasGoAST())
}

func TestFileContextExtension(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/project/main.go", ".go"},
		{"/project/app.ts", ".ts"},
		{"/project/style.css", ".css"},
		{"/project/Makefile", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			ctx := &FileContext{Path: tt.path}
			assert.Equal(t, tt.expected, ctx.Extension())
		})
	}
}

func TestFileContextBaseName(t *testing.T) {
	ctx := &FileContext{Path: "/project/pkg/main.go"}
	assert.Equal(t, "main.go", ctx.BaseName())
}

func TestFileContextDir(t *testing.T) {
	ctx := &FileContext{Path: "/project/pkg/main.go"}
	assert.Equal(t, "/project/pkg", ctx.Dir())
}

func TestFileContextIsSuppressed(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		line     int
		rule     string
		expected bool
	}{
		{
			name:     "nolint on violation line",
			lines:    []string{`x := foo() //nolint:my-rule`},
			line:     1,
			rule:     "my-rule",
			expected: true,
		},
		{
			name:     "nolint with space",
			lines:    []string{`x := foo() // nolint:my-rule`},
			line:     1,
			rule:     "my-rule",
			expected: true,
		},
		{
			name:     "nolint comma separated list",
			lines:    []string{`x := foo() //nolint:first-rule,my-rule,third-rule`},
			line:     1,
			rule:     "my-rule",
			expected: true,
		},
		{
			name:     "nolint list with space after comma",
			lines:    []string{`x := foo() //nolint:first-rule, my-rule`},
			line:     1,
			rule:     "my-rule",
			expected: true,
		},
		{
			name:     "nolint list followed by prose does not read the prose as rules",
			lines:    []string{`x := foo() //nolint:first-rule, my-rule justified because reasons`},
			line:     1,
			rule:     "justified",
			expected: false,
		},
		{
			name:     "pointer dereference assignment is not a comment",
			lines:    []string{`*target = "my-rule: safe"`},
			line:     1,
			rule:     "my-rule",
			expected: false,
		},
		{
			name:     "rule-colon-safe on violation line",
			lines:    []string{`x := foo() // my-rule: safe — reason here`},
			line:     1,
			rule:     "my-rule",
			expected: true,
		},
		{
			name:     "rule-colon-safe without space",
			lines:    []string{`x := foo() // my-rule:safe`},
			line:     1,
			rule:     "my-rule",
			expected: true,
		},
		{
			name:     "suppression on line above",
			lines:    []string{`// nolint:my-rule — justified`, `x := foo()`},
			line:     2,
			rule:     "my-rule",
			expected: true,
		},
		{
			name:     "different rule not suppressed",
			lines:    []string{`x := foo() //nolint:other-rule`},
			line:     1,
			rule:     "my-rule",
			expected: false,
		},
		{
			name:     "rule name prefix must not match longer rule",
			lines:    []string{`x := foo() //nolint:my-rule-extended`},
			line:     1,
			rule:     "my-rule",
			expected: false,
		},
		{
			name:     "no comment no suppression",
			lines:    []string{`x := foo()`},
			line:     1,
			rule:     "my-rule",
			expected: false,
		},
		{
			name:     "marker outside comment is ignored",
			lines:    []string{`msg := "nolint:my-rule"`},
			line:     1,
			rule:     "my-rule",
			expected: false,
		},
		{
			name:     "line out of range",
			lines:    []string{`x := foo()`},
			line:     99,
			rule:     "my-rule",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &FileContext{Lines: tt.lines}
			assert.Equal(t, tt.expected, ctx.IsSuppressed(tt.line, tt.rule))
		})
	}
}

func TestFileContextIsGenerated(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		source   string
		expected bool
	}{
		{"go marker", "mocks/store.go", "// Code generated by MockGen. DO NOT EDIT.\n// Source: store.go\n\npackage mocks\n", true},
		{"go marker after license", "api.go", "/*\n * License\n */\n\n// Code generated by oapi-codegen. DO NOT EDIT.\npackage api\n", true},
		{"ts marker", "src/api.ts", "/* eslint-disable */\n// Code generated by openapi. DO NOT EDIT.\nexport type A = string\n", true},
		{"marker after code", "main.go", "package main\n\n// Code generated by hand. DO NOT EDIT.\n", false},
		{"no marker", "main.go", "// Package main does things.\npackage main\n", false},
		{"marker without period", "x.go", "// Code generated by x. DO NOT EDIT\npackage x\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewFileContext("/project/"+tt.path, "/project", []byte(tt.source), nil)
			assert.Equal(t, tt.expected, ctx.IsGenerated(), "line scan")
			if strings.HasSuffix(tt.path, ".go") {
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, tt.path, tt.source, parser.ParseComments)
				require.NoError(t, err)
				ctx.SetGoAST(fset, file)
				assert.Equal(t, tt.expected, ctx.IsGenerated(), "syntax tree")
			}
		})
	}
}

func TestFileSharedBuildsOncePerFile(t *testing.T) {
	type key struct{}
	file := &FileContext{Lines: []string{"a", "b"}}
	var builds atomic.Int32
	build := func() int { builds.Add(1); return len(file.Lines) }

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { assert.Equal(t, 2, FileShared(file, key{}, build)) })
	}
	wg.Wait()
	assert.Equal(t, int32(1), builds.Load())

	other := &FileContext{Lines: []string{"c"}}
	assert.Equal(t, 1, FileShared(other, key{}, func() int { return len(other.Lines) }), "each file has its own cache")
	assert.Panics(t, func() { FileShared(file, key{}, func() string { return "" }) }, "a key built with another type is a programming error")
}

func TestDeployFileNames(t *testing.T) {
	for name, want := range map[string]bool{
		"docker-compose.yml": true, "docker-compose.prod.yaml": true, "compose.yaml": true,
		"compose.override.yml": true, "docker-compose.md": false, "my-compose.yml": false,
	} {
		assert.Equal(t, want, IsComposeFileName(name), name)
	}
	for name, want := range map[string]bool{
		".env.example": true, "backend.env.example": true, ".env.sample": true, ".env.dist": true,
		".env": false, ".env.prod": false, "env.example.go": false,
	} {
		assert.Equal(t, want, isEnvTemplateName(name), name)
	}
	for path, want := range map[string]bool{
		"bitbucket-pipelines.yml": true, "ci/.gitlab-ci.yml": true, ".github/workflows/test.yaml": true,
		".github/dependabot.yml": false, "workflows/test.yml": false, "pipelines.yml": false,
	} {
		assert.Equal(t, want, isCIConfigPath(path), path)
	}
}

func TestShellTestScriptIsTestFile(t *testing.T) {
	assert.True(t, NewFileContext("scripts/loader_test.sh", ".", nil, nil).IsTestFile())
	assert.False(t, NewFileContext("scripts/loader.sh", ".", nil, nil).IsTestFile())
}
