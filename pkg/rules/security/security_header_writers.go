package security

import (
	"fmt"
	"go/ast"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSecurityHeaderMultipleWritersRule())
}

// SecurityHeaderMultipleWritersRule detects a security header that two files
// of a project set:
//
//	// https_middleware.go
//	w.Header().Set("Content-Security-Policy", "upgrade-insecure-requests")
//	// security_headers_middleware.go
//	w.Header().Set("Content-Security-Policy", strictPolicy)
//
// Whichever middleware runs last decides, so the policy in force is not the
// one the reader of either file sees: a strict CSP is replaced by a weak one,
// a configured HSTS by a hardcoded one. One file owns each header; functions
// of that file that refine it for one kind of response (HTML) are its owner.
type SecurityHeaderMultipleWritersRule struct {
	*rules.BaseRule
	// writers maps a header to the files that set it.
	writers map[string][]string
}

// NewSecurityHeaderMultipleWritersRule creates the rule
func NewSecurityHeaderMultipleWritersRule() *SecurityHeaderMultipleWritersRule {
	return &SecurityHeaderMultipleWritersRule{BaseRule: rules.NewBaseRule(
		"security-header-multiple-writers",
		"security",
		"Detects a security header (CSP, HSTS, X-Frame-Options, ...) set in more than one file — the last middleware to run decides the policy",
		core.SeverityMedium,
	)}
}

var securityHeaders = map[string]bool{
	"content-security-policy": true, "strict-transport-security": true, "x-frame-options": true,
	"x-content-type-options": true, "referrer-policy": true, "permissions-policy": true,
	"cross-origin-opener-policy": true, "cross-origin-embedder-policy": true, "cross-origin-resource-policy": true,
}

// headerWrite is a call that sets a security header.
type headerWrite struct {
	header string
	call   *ast.CallExpr
	writer string
}

// UseProjectFiles indexes the functions that set each security header.
func (r *SecurityHeaderMultipleWritersRule) UseProjectFiles(files []*core.FileContext) {
	r.writers = make(map[string][]string)
	for _, ctx := range files {
		for _, write := range headerWrites(ctx) {
			key := strings.ToLower(write.header)
			if !slices.Contains(r.writers[key], write.writer) {
				r.writers[key] = append(r.writers[key], write.writer)
			}
		}
	}
}

// ResetState drops the writers of the previous root.
func (r *SecurityHeaderMultipleWritersRule) ResetState() { r.writers = nil }

// AnalyzeFile reports the first write of a header in the file when another
// file sets it too.
func (r *SecurityHeaderMultipleWritersRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	lr := newLineReporter(ctx, r.BaseRule)
	seen := make(map[string]bool)
	for _, write := range headerWrites(ctx) {
		header := strings.ToLower(write.header)
		if seen[write.writer+"|"+header] || len(r.writers[header]) < 2 {
			continue
		}
		seen[write.writer+"|"+header] = true
		var others []string
		for _, w := range r.writers[header] {
			if w != write.writer {
				others = append(others, w)
			}
		}
		lr.report(write.call, fmt.Sprintf("%s is also set by %s — whichever runs last decides the policy", write.header, strings.Join(others, ", ")),
			"Set each security header in one place and remove the other writes", "security_header_multiple_writers")
	}
	return lr.violations
}

// headerWrites returns the security-header Set and Add calls of a production
// Go file.
func headerWrites(ctx *core.FileContext) []headerWrite {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	var writes []headerWrite
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			if name := callName(call); name != "Set" && name != "Add" {
				return true
			}
			header := stringLiteral(call.Args[0])
			if securityHeaders[strings.ToLower(header)] {
				writes = append(writes, headerWrite{header: header, call: call, writer: ctx.RelPath})
			}
			return true
		})
	}
	return writes
}
