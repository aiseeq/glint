package patternkit

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// TestSourceFile reports a Go test file or a TS/JS test or e2e file.
func TestSourceFile(ctx *core.FileContext) bool {
	path := "/" + strings.ToLower(ctx.RelPath)
	if strings.Contains(path, "/node_modules/") {
		return false
	}
	if ctx.IsGoFile() {
		return ctx.IsTestFile()
	}
	return (ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile()) && (ctx.IsTestFile() || strings.Contains(path, "/e2e/"))
}
