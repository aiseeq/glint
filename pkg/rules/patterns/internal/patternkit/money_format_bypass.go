package patternkit

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// FrontendSource reports a TS/JS source file of the product: not a test, not
// generated, not a dependency or a build output.
func FrontendSource(ctx *core.FileContext) bool {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() || ctx.IsTestFile() || IsE2EPath(ctx.RelPath) {
		return false
	}
	path := "/" + ctx.RelPath
	for _, dir := range []string{"/node_modules/", "/dist/", "/build/", "/.next/", "/out/"} {
		if strings.Contains(path, dir) {
			return false
		}
	}
	return !ctx.IsGenerated()
}
