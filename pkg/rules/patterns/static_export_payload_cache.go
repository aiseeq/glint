package patterns

import (
	"go/ast"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnhashedBuildDataServedCacheableRule())
}

// UnhashedBuildDataServedCacheableRule detects a Go static server that
// revalidates the pages of a Next.js static export and leaves their RSC
// payloads cacheable:
//
//	isEntryPoint := strings.HasSuffix(p, "/") || strings.HasSuffix(p, ".html")
//	if isEntryPoint { w.Header().Set("Cache-Control", "no-cache") }
//
// With output: 'export' every page has a payload next to it (page/index.txt)
// whose URL carries no build hash, like the HTML. After a deploy the browser
// serves the previous build's payload from its cache, the client rejects it
// by build id and navigates hard to the payload's URL.
type UnhashedBuildDataServedCacheableRule struct {
	*rules.BaseRule
	// exportsStatically marks a project with a Next.js static export.
	exportsStatically bool
}

// NewUnhashedBuildDataServedCacheableRule creates the rule
func NewUnhashedBuildDataServedCacheableRule() *UnhashedBuildDataServedCacheableRule {
	return &UnhashedBuildDataServedCacheableRule{BaseRule: rules.NewBaseRule(
		"unhashed-build-data-served-cacheable",
		"patterns",
		"Detects a static server revalidating .html but not the .txt RSC payloads of a Next.js static export (output: 'export') — after a deploy the browser serves the previous build's payload from cache",
		core.SeverityMedium,
	)}
}

var (
	nextStaticExport = regexp.MustCompile(`\boutput\s*:\s*['"]export['"]`)
	revalidating     = regexp.MustCompile(`(?i)no-cache|no-store|must-revalidate|max-age=0\b`)
)

// UseProjectFiles finds a Next.js configuration with a static export.
func (r *UnhashedBuildDataServedCacheableRule) UseProjectFiles(files []*core.FileContext) {
	r.exportsStatically = slices.ContainsFunc(files, func(ctx *core.FileContext) bool {
		return strings.HasPrefix(filepath.Base(ctx.RelPath), "next.config.") && nextStaticExport.Match(ctx.Content)
	})
}

// ResetState forgets the previous root.
func (r *UnhashedBuildDataServedCacheableRule) ResetState() { r.exportsStatically = false }

// AnalyzeFile reports the functions revalidating pages but not payloads.
func (r *UnhashedBuildDataServedCacheableRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !r.exportsStatically || !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !setsRevalidation(fn.Body) {
			continue
		}
		var htmlCheck ast.Node
		namesPayload := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok {
				return true
			}
			text, _ := goStringLiteral(lit)
			switch {
			case strings.HasSuffix(text, ".txt"):
				namesPayload = true
			case text == ".html" && htmlCheck == nil:
				htmlCheck = lit
			}
			return true
		})
		if htmlCheck == nil || namesPayload {
			continue
		}
		line := ctx.LineFor(htmlCheck)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line,
			"Pages (.html) are revalidated but the RSC payloads of the Next.js static export (.txt) are not — their URLs carry no build hash, and after a deploy the browser serves the previous build's payload")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Revalidate .txt like .html (Cache-Control: no-cache), or serve the payloads under hashed URLs")
		violations = append(violations, v)
	}
	return violations
}

// setsRevalidation reports a body setting a Cache-Control header that makes
// the browser ask again.
func setsRevalidation(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 || callName(call) != "Set" {
			return !found
		}
		header, ok1 := call.Args[0].(*ast.BasicLit)
		value, ok2 := call.Args[1].(*ast.BasicLit)
		if !ok1 || !ok2 {
			return !found
		}
		name, _ := goStringLiteral(header)
		text, _ := goStringLiteral(value)
		if strings.EqualFold(name, "Cache-Control") && revalidating.MatchString(text) {
			found = true
		}
		return !found
	})
	return found
}
