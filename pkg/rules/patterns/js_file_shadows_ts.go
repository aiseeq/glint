package patterns

import (
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewJSFileShadowsTSModuleRule())
}

// JSFileShadowsTSModuleRule detects a .js or .jsx file next to a .ts or .tsx
// module of the same name:
//
//	e2e/utils/helpers.ts   // the maintained module
//	e2e/utils/helpers.js   // an old copy
//
// An import without an extension resolves to one of them by the resolver's
// order: the tests or the page run the stale copy, and a fix in the .ts has
// no effect. A .d.ts beside a .js describes it and is left out; so is build
// output.
type JSFileShadowsTSModuleRule struct {
	*rules.BaseRule
	// modules holds the extensionless paths of the root's TS modules.
	modules map[string]bool
}

// NewJSFileShadowsTSModuleRule creates the rule
func NewJSFileShadowsTSModuleRule() *JSFileShadowsTSModuleRule {
	return &JSFileShadowsTSModuleRule{BaseRule: rules.NewBaseRule(
		"js-file-shadows-ts-module",
		"patterns",
		"Detects a .js file next to a .ts module of the same name — an import without an extension may load the stale copy",
		core.SeverityHigh,
	)}
}

// UseProjectFiles collects the TS modules of the root.
func (r *JSFileShadowsTSModuleRule) UseProjectFiles(files []*core.FileContext) {
	r.modules = map[string]bool{}
	for _, ctx := range files {
		path := filepath.ToSlash(ctx.RelPath)
		if !ctx.IsTypeScriptFile() || strings.HasSuffix(path, ".d.ts") || jsBuildPath(path) {
			continue
		}
		r.modules[strings.TrimSuffix(path, filepath.Ext(path))] = true
	}
}

// ResetState drops the modules of the previous root.
func (r *JSFileShadowsTSModuleRule) ResetState() { r.modules = nil }

// AnalyzeFile reports a JS file that shadows a TS module.
func (r *JSFileShadowsTSModuleRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	path := filepath.ToSlash(ctx.RelPath)
	if !ctx.IsJavaScriptFile() || jsBuildPath(path) || !r.modules[strings.TrimSuffix(path, filepath.Ext(path))] {
		return nil
	}
	return jsReport(nil, r.BaseRule, ctx, 1,
		"JS file shadows the TS module of the same name — an import without an extension may load this copy",
		"Delete the copy, or rename it if it is a different module")
}

// jsBuildPath reports a path in installed dependencies or build output.
func jsBuildPath(path string) bool {
	path = "/" + path
	for _, dir := range []string{"/node_modules/", "/dist/", "/.next/", "/out/", "/build/", "/coverage/"} {
		if strings.Contains(path, dir) {
			return true
		}
	}
	return false
}
