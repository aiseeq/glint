package helpers

import "github.com/aiseeq/glint/pkg/core"

// AnalyzeGoAndFrontend dispatches a file to its language-specific analyzer.
func AnalyzeGoAndFrontend(
	ctx *core.FileContext,
	analyzeGo func(*core.FileContext) []*core.Violation,
	analyzeFrontend func(*core.FileContext) []*core.Violation,
) []*core.Violation {
	switch {
	case ctx.IsGoFile():
		return analyzeGo(ctx)
	case ctx.IsTypeScriptFile(), ctx.IsJavaScriptFile():
		return analyzeFrontend(ctx)
	default:
		return nil
	}
}
