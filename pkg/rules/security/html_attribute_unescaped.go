package security

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewHTMLAttributeUnescapedRule())
}

// HTMLAttributeUnescapedRule detects a value concatenated into an HTML
// attribute without escaping:
//
//	img := baseURL + "/og/" + slug + ".png"     // baseURL from r.Host
//	meta := `<meta property="og:image" content="` + img + `">`
//
// A quote in the value closes the attribute and the rest becomes markup:
// content="https://x" onload="..." runs in every browser that opens the page.
// The Host header, a slug or a name all come from the client. html.EscapeString
// (or html/template) escapes; numbers from strconv cannot break out.
type HTMLAttributeUnescapedRule struct {
	*rules.BaseRule
}

// NewHTMLAttributeUnescapedRule creates the rule
func NewHTMLAttributeUnescapedRule() *HTMLAttributeUnescapedRule {
	return &HTMLAttributeUnescapedRule{BaseRule: rules.NewBaseRule(
		"html-attribute-unescaped",
		"security",
		"Detects a value concatenated into an HTML attribute (`content=\"` + v) without html.EscapeString — a quote in it breaks out into markup",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports unescaped values in HTML attributes built by
// concatenation.
func (r *HTMLAttributeUnescapedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		safe := escapedVariables(fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sum, ok := n.(*ast.BinaryExpr)
			if !ok || sum.Op != token.ADD {
				return true
			}
			operands := concatOperands(sum)
			if !markup(operands) {
				return true
			}
			for i := 1; i < len(operands); i++ {
				before := stringLiteral(operands[i-1])
				if (strings.HasSuffix(before, `="`) || strings.HasSuffix(before, `='`)) && !escapedValue(operands[i], safe) {
					lr.report(operands[i], "Value written into an HTML attribute without escaping — a quote in it closes the attribute and the rest becomes markup",
						"Escape it with html.EscapeString, or build the page with html/template", "html_attribute_unescaped")
				}
			}
			return false
		})
	}
	return lr.violations
}

// concatOperands flattens a + b + c into its operands.
func concatOperands(expr ast.Expr) []ast.Expr {
	sum, ok := ast.Unparen(expr).(*ast.BinaryExpr)
	if !ok || sum.Op != token.ADD {
		return []ast.Expr{expr}
	}
	return append(concatOperands(sum.X), concatOperands(sum.Y)...)
}

// markup reports operands with a string literal holding a tag.
func markup(operands []ast.Expr) bool {
	for _, operand := range operands {
		if strings.Contains(stringLiteral(operand), "<") {
			return true
		}
	}
	return false
}

// escapedVariables returns the variables a function assigns only escaped or
// numeric text.
func escapedVariables(body *ast.BlockStmt) map[string]bool {
	safe := make(map[string]bool)
	unsafe := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			if escapingCall(assign.Rhs[i]) {
				safe[ident.Name] = true
			} else {
				unsafe[ident.Name] = true
			}
		}
		return true
	})
	for name := range unsafe {
		delete(safe, name)
	}
	return safe
}

// escapedValue reports an operand that cannot break out of an attribute.
func escapedValue(expr ast.Expr, safe map[string]bool) bool {
	if ident, ok := ast.Unparen(expr).(*ast.Ident); ok {
		return safe[ident.Name]
	}
	return escapingCall(expr)
}

// escapingCall reports a call named for escaping (html.EscapeString, the
// project's escapeHTML), url.QueryEscape/PathEscape or a strconv formatting
// call.
func escapingCall(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	// The project's own escaper (escapeHTML, attrEscape) is trusted by name.
	if strings.Contains(strings.ToLower(callName(call)), "escape") {
		return true
	}
	pkg, ok := callPackage(call)
	if !ok {
		return false
	}
	switch pkg {
	case "strconv":
		return strings.HasPrefix(callName(call), "Format") || callName(call) == "Itoa"
	}
	return false
}
