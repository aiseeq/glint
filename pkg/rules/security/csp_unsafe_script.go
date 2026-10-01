package security

import (
	"go/ast"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewCSPUnsafeScriptRule())
}

// CSPUnsafeScriptRule detects a Content-Security-Policy that lets scripts run
// inline or from strings:
//
//	ScriptSrc: []string{"'self'", "'unsafe-inline'", "https://www.googletagmanager.com"},
//	add_header Content-Security-Policy "script-src 'self' 'unsafe-inline'";
//
// 'unsafe-inline' in script-src runs any <script> an attacker manages to
// inject, which is the attack the policy exists to stop; 'unsafe-eval' runs
// strings as code. Nonces, hashes or 'strict-dynamic' keep the scripts the
// page needs. A policy built for development (a function or variable named
// Dev, Development, Local or Test) is left alone.
type CSPUnsafeScriptRule struct {
	*rules.BaseRule
}

// NewCSPUnsafeScriptRule creates the rule
func NewCSPUnsafeScriptRule() *CSPUnsafeScriptRule {
	return &CSPUnsafeScriptRule{BaseRule: rules.NewBaseRule(
		"csp-unsafe-script",
		"security",
		"Detects 'unsafe-inline' or 'unsafe-eval' in a Content-Security-Policy script-src — injected scripts run",
		core.SeverityHigh,
	)}
}

var (
	unsafeScriptSource = regexp.MustCompile(`'unsafe-(?:inline|eval)'`)
	scriptSrcDirective = regexp.MustCompile(`(?i)script-src(?:-elem)?\s[^;"]*'unsafe-(?:inline|eval)'`)
	developmentPolicy  = regexp.MustCompile(`(?:Dev|Development|Local|Test)(?:[A-Z_]|$)|^(?:dev|local|test)`)
)

const cspSuggestion = "Move inline scripts to files, or allow them by nonce or hash ('nonce-…', 'sha256-…', 'strict-dynamic')"

// AnalyzeFile reports unsafe script sources in Go policies and nginx configs.
func (r *CSPUnsafeScriptRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if strings.ToLower(filepath.Ext(ctx.Path)) == ".conf" {
		return r.analyzeConf(ctx)
	}
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	for _, decl := range ctx.GoAST.Decls {
		if developmentDecl(decl) {
			continue
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.KeyValueExpr:
				key, ok := node.Key.(*ast.Ident)
				if !ok || !strings.Contains(strings.ToLower(key.Name), "script") {
					return true
				}
				ast.Inspect(node.Value, func(m ast.Node) bool {
					if expr, ok := m.(ast.Expr); ok && unsafeScriptSource.MatchString(stringLiteral(expr)) {
						lr.report(m, "Content-Security-Policy script-src allows "+stringLiteral(expr)+" — an injected script runs", cspSuggestion, "csp_unsafe_script")
					}
					return true
				})
				return false
			case *ast.BasicLit:
				if scriptSrcDirective.MatchString(stringLiteral(node)) {
					lr.report(node, "Content-Security-Policy script-src allows inline or eval'd scripts — an injected script runs", cspSuggestion, "csp_unsafe_script")
				}
			}
			return true
		})
	}
	return lr.violations
}

// analyzeConf reports a CSP header of an nginx config with unsafe script
// sources.
func (r *CSPUnsafeScriptRule) analyzeConf(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	for i, line := range strings.Split(string(ctx.Content), "\n") {
		code, _, _ := strings.Cut(line, "#")
		if !strings.Contains(strings.ToLower(code), "content-security-policy") || !scriptSrcDirective.MatchString(code) {
			continue
		}
		if ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, "Content-Security-Policy script-src allows inline or eval'd scripts — an injected script runs")
		v.WithCode(strings.TrimSpace(line))
		v.WithSuggestion(cspSuggestion)
		violations = append(violations, v)
	}
	return violations
}

// developmentDecl reports a function or variable named for development.
func developmentDecl(decl ast.Decl) bool {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return developmentPolicy.MatchString(d.Name.Name)
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok {
				for _, name := range vs.Names {
					if developmentPolicy.MatchString(name.Name) {
						return true
					}
				}
			}
		}
	}
	return false
}
