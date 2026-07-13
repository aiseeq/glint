package patterns

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
	return helpers.AnalyzeFuncBodies(ctx, r.checkFunction)
}

func (r *HTTPBodyCloseRule) checkFunction(ctx *core.FileContext, body *ast.BlockStmt, violations *[]*core.Violation) {
	// Track response variable names
	responseVars := make(map[string]int) // varName -> line
	httpAliases := httpImportAliases(ctx)

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
			if isHTTPResponseCall(assign.Rhs[0], httpAliases) {
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

func httpImportAliases(ctx *core.FileContext) map[string]struct{} {
	aliases := make(map[string]struct{})
	hasNetHTTP := false
	for _, path := range ctx.GoImports {
		if path == "net/http" {
			hasNetHTTP = true
			break
		}
	}
	if !hasNetHTTP || ctx.GoAST == nil {
		return aliases
	}

	for _, spec := range ctx.GoAST.Imports {
		if spec.Path.Value != `"net/http"` {
			continue
		}
		name := "http"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != "." && name != "_" {
			aliases[name] = struct{}{}
		}
	}
	return aliases
}

func isHTTPResponseCall(expr ast.Expr, httpAliases map[string]struct{}) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	method := sel.Sel.Name
	if ident, ok := sel.X.(*ast.Ident); ok {
		if _, isPackage := httpAliases[ident.Name]; isPackage {
			return isHTTPPackageResponseMethod(method)
		}
	}
	if !isHTTPClientResponseMethod(method) {
		return false
	}
	if isHTTPClientExpr(sel.X, httpAliases) {
		return true
	}
	return method == "Do" && len(call.Args) > 0 && isHTTPTypedExpr(call.Args[0], "Request", httpAliases)
}

func isHTTPPackageResponseMethod(method string) bool {
	return method == "Get" || method == "Post" || method == "Head" || method == "PostForm"
}

func isHTTPClientResponseMethod(method string) bool {
	return method == "Do" || isHTTPPackageResponseMethod(method)
}

func isHTTPClientExpr(expr ast.Expr, httpAliases map[string]struct{}) bool {
	if isHTTPTypedExpr(expr, "Client", httpAliases) {
		return true
	}
	return isHTTPDefaultClientExpr(expr, httpAliases)
}

func isHTTPDefaultClientExpr(expr ast.Expr, httpAliases map[string]struct{}) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "DefaultClient" {
		return false
	}
	packageName, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	_, ok = httpAliases[packageName.Name]
	return ok
}

func isHTTPTypedExpr(expr ast.Expr, typeName string, httpAliases map[string]struct{}) bool {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return expr.Obj != nil && declarationHasHTTPType(expr.Obj.Decl, expr.Name, typeName, httpAliases)
	case *ast.StarExpr:
		return isHTTPTypeSyntax(expr.X, typeName, httpAliases)
	case *ast.SelectorExpr:
		return isHTTPTypeSyntax(expr, typeName, httpAliases)
	case *ast.CompositeLit:
		return isHTTPTypeSyntax(expr.Type, typeName, httpAliases)
	case *ast.UnaryExpr:
		return expr.Op == token.AND && isHTTPTypedExpr(expr.X, typeName, httpAliases)
	default:
		return false
	}
}

func declarationHasHTTPType(decl any, name, typeName string, httpAliases map[string]struct{}) bool {
	switch decl := decl.(type) {
	case *ast.Field:
		return isHTTPTypeSyntax(decl.Type, typeName, httpAliases)
	case *ast.ValueSpec:
		if decl.Type != nil {
			return isHTTPTypeSyntax(decl.Type, typeName, httpAliases)
		}
		return valueSpecHasHTTPType(decl, name, typeName, httpAliases)
	case *ast.AssignStmt:
		return assignmentHasHTTPType(decl, name, typeName, httpAliases)
	default:
		return false
	}
}

func valueSpecHasHTTPType(spec *ast.ValueSpec, name, typeName string, httpAliases map[string]struct{}) bool {
	for i, declaredName := range spec.Names {
		if declaredName.Name != name || i >= len(spec.Values) {
			continue
		}
		return httpValueHasType(spec.Values[i], typeName, httpAliases)
	}
	return false
}

func assignmentHasHTTPType(assign *ast.AssignStmt, name, typeName string, httpAliases map[string]struct{}) bool {
	for i, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name != name {
			continue
		}
		if len(assign.Rhs) == len(assign.Lhs) {
			return httpValueHasType(assign.Rhs[i], typeName, httpAliases)
		}
		return i == 0 && len(assign.Rhs) == 1 && httpValueHasType(assign.Rhs[0], typeName, httpAliases)
	}
	return false
}

func httpValueHasType(expr ast.Expr, typeName string, httpAliases map[string]struct{}) bool {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.CompositeLit:
		return isHTTPTypeSyntax(expr.Type, typeName, httpAliases)
	case *ast.UnaryExpr:
		return expr.Op == token.AND && httpValueHasType(expr.X, typeName, httpAliases)
	case *ast.SelectorExpr:
		return typeName == "Client" && isHTTPDefaultClientExpr(expr, httpAliases)
	case *ast.CallExpr:
		return typeName == "Request" && isHTTPRequestConstructor(expr, httpAliases)
	default:
		return false
	}
}

func isHTTPRequestConstructor(call *ast.CallExpr, httpAliases map[string]struct{}) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "NewRequest" && sel.Sel.Name != "NewRequestWithContext") {
		return false
	}
	packageName, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	_, ok = httpAliases[packageName.Name]
	return ok
}

func isHTTPTypeSyntax(expr ast.Expr, typeName string, httpAliases map[string]struct{}) bool {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.StarExpr:
		return isHTTPTypeSyntax(expr.X, typeName, httpAliases)
	case *ast.SelectorExpr:
		packageName, ok := expr.X.(*ast.Ident)
		if !ok || expr.Sel.Name != typeName {
			return false
		}
		_, ok = httpAliases[packageName.Name]
		return ok
	default:
		return false
	}
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
