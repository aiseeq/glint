package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		{"/project/main_test.go", true},
		{"/project/app.test.ts", true},
		{"/project/app.spec.js", true},
		{"/project/test/helper.go", true},
		{"/project/__tests__/app.ts", true},
		{"/project/main.go", false},
		{"/project/app.ts", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			ctx := &FileContext{Path: tt.path}
			assert.Equal(t, tt.expected, ctx.IsTestFile())
		})
	}
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
