package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewHTTPBodyCloseRule())
}

// HTTPBodyCloseRule detects HTTP response body not being closed
type HTTPBodyCloseRule struct {
	*rules.BaseRule
}

// NewHTTPBodyCloseRule creates the rule
func NewHTTPBodyCloseRule() *HTTPBodyCloseRule {
	return &HTTPBodyCloseRule{
		BaseRule: rules.NewBaseRule(
			"http-body-close",
			"patterns",
			"Detects HTTP response body not being closed (resource leak)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks for unclosed HTTP response bodies
func (r *HTTPBodyCloseRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Find http.Get, http.Post, client.Do, etc. calls
		r.checkFunction(ctx, fn.Body, &violations)

		return true
	})

	return violations
}

func (r *HTTPBodyCloseRule) checkFunction(ctx *core.FileContext, body *ast.BlockStmt, violations *[]*core.Violation) {
	// Track response variable names
	responseVars := make(map[string]int) // varName -> line

	ast.Inspect(body, func(n ast.Node) bool {
		// Skip nested function literals
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}

		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		// Check for http response assignments
		// resp, err := http.Get(...) or resp, err := client.Do(...)
		if len(assign.Lhs) >= 1 && len(assign.Rhs) == 1 {
			if r.isHTTPCall(assign.Rhs[0]) {
				if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name != "_" {
					responseVars[ident.Name] = r.getLineFromNode(ctx, assign)
				}
			}
		}

		return true
	})

	if len(responseVars) == 0 {
		return
	}

	// Check for defer resp.Body.Close() or resp.Body.Close()
	// Note: we DO need to check inside FuncLit because defer func() { resp.Body.Close() }() is common
	closedVars := make(map[string]bool)

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		if varName := r.getBodyCloseVar(call); varName != "" {
			closedVars[varName] = true
		}

		return true
	})

	// Report unclosed responses
	for varName, line := range responseVars {
		if !closedVars[varName] {
			v := r.CreateViolation(ctx.RelPath, line, "HTTP response body not closed - resource leak")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Add defer " + varName + ".Body.Close() after nil check")
			v.WithContext("pattern", "http_body_leak")
			v.WithContext("variable", varName)
			*violations = append(*violations, v)
		}
	}
}

func (r *HTTPBodyCloseRule) isHTTPCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	method := sel.Sel.Name

	// Check for http.Get, http.Post, http.Head, http.PostForm
	if ident, ok := sel.X.(*ast.Ident); ok {
		if ident.Name == "http" {
			return method == "Get" || method == "Post" || method == "Head" ||
				method == "PostForm" || method == "Do"
		}
		// Common HTTP client variable names
		clientNames := map[string]bool{
			"client":     true,
			"httpClient": true,
			"c":          true,
		}
		if clientNames[ident.Name] {
			return method == "Do" || method == "Get" || method == "Post" ||
				method == "Head" || method == "PostForm"
		}
	}

	// Only match Do method for client calls (most reliable indicator)
	return method == "Do"
}

func (r *HTTPBodyCloseRule) getBodyCloseVar(call *ast.CallExpr) string {
	// Looking for resp.Body.Close()
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Close" {
		return ""
	}

	// Check for .Body
	bodySel, ok := sel.X.(*ast.SelectorExpr)
	if !ok || bodySel.Sel.Name != "Body" {
		return ""
	}

	// Get the variable name
	if ident, ok := bodySel.X.(*ast.Ident); ok {
		return ident.Name
	}

	return ""
}

func (r *HTTPBodyCloseRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
	if node == nil {
		return 1
	}

	pos := node.Pos()
	if pos == 0 {
		return 1
	}

	offset := int(pos) - 1
	if offset < 0 || offset >= len(ctx.Content) {
		return 1
	}

	line := 1
	for i := 0; i < offset && i < len(ctx.Content); i++ {
		if ctx.Content[i] == '\n' {
			line++
		}
	}
	return line
}
