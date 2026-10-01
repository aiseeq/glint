package security

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSignatureAlternateFormatsRule())
}

// SignatureAlternateFormatsRule detects a signature check that accepts any of
// several signed messages:
//
//	if sig := mac(body); hmac.Equal(sig, got) { return nil }
//	if sig := mac(ts + body); hmac.Equal(sig, got) { return nil }
//	if sig := mac(ts + window + path + body); hmac.Equal(sig, got) { return nil }
//
// Each format the receiver accepts is one a sender can choose, so the weakest
// decides: a signature over the body alone lets a captured request be replayed
// with any timestamp, and fields left out of a format can be changed freely.
// The protocol defines one message; the check computes that one.
type SignatureAlternateFormatsRule struct {
	*rules.BaseRule
}

// NewSignatureAlternateFormatsRule creates the rule
func NewSignatureAlternateFormatsRule() *SignatureAlternateFormatsRule {
	return &SignatureAlternateFormatsRule{BaseRule: rules.NewBaseRule(
		"signature-accepts-alternate-formats",
		"security",
		"Detects a signature verification that succeeds on any of several constant-time comparisons — the weakest signed message decides",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports the second and later accepting comparisons of a function.
func (r *SignatureAlternateFormatsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		accepted := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			stmt, ok := n.(*ast.IfStmt)
			if !ok || !constantTimeMatch(stmt.Cond) || !acceptsAndLeaves(stmt.Body) {
				return true
			}
			accepted++
			if accepted > 1 {
				lr.report(stmt.Cond, "Signature verification accepts another signed format — a sender picks the weakest one the receiver accepts",
					"Compute the one message the protocol signs and compare once; reject everything else", "signature_alternate_formats")
			}
			return true
		})
	}
	return lr.violations
}

// constantTimeMatch reports hmac.Equal(...) or subtle.ConstantTimeCompare(...)
// == 1 in a condition.
func constantTimeMatch(cond ast.Expr) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		pkg, ok := callPackage(call)
		name := callName(call)
		if ok && ((pkg == "hmac" && name == "Equal") || (pkg == "subtle" && name == "ConstantTimeCompare")) {
			found = true
		}
		return !found
	})
	return found
}

// acceptsAndLeaves reports a branch that returns success: nil, true, or a
// value with no error.
func acceptsAndLeaves(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) == 0 {
		return false
	}
	last, ok := ret.Results[len(ret.Results)-1].(*ast.Ident)
	return ok && (last.Name == "nil" || last.Name == "true")
}
