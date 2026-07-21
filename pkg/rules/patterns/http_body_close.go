package patterns

import (
	"go/ast"
	"go/token"
	"strconv"

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
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	httpAliases := httpImportAliases(ctx)
	var violations []*core.Violation
	for _, declaration := range ctx.GoAST.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		r.checkFunction(ctx, function.Body, httpAliases, &violations)
	}
	return violations
}

func (r *HTTPBodyCloseRule) checkFunction(
	ctx *core.FileContext,
	body *ast.BlockStmt,
	httpAliases map[string]struct{},
	violations *[]*core.Violation,
) {
	// Track response variable names
	responseVars := make(map[string]int) // varName -> line

	walkReachableHTTPBodyStatements(body.List, func(n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
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
	})

	if len(responseVars) == 0 {
		return
	}

	// Check for defer resp.Body.Close() or resp.Body.Close()
	// Note: we DO need to check inside FuncLit because defer func() { resp.Body.Close() }() is common
	closedVars := make(map[string]bool)

	walkReachableHTTPBodyStatements(body.List, func(n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			if varName := r.getBodyCloseVar(call); varName != "" {
				closedVars[varName] = true
			}

			return true
		})
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

type httpClientScope struct {
	parent   *httpClientScope
	bindings map[string]bool
}

func newHTTPClientScope(parent *httpClientScope) *httpClientScope {
	return &httpClientScope{parent: parent, bindings: make(map[string]bool)}
}

func (s *httpClientScope) declare(name string, isHTTPClient bool) {
	if name == "_" {
		return
	}
	if _, declared := s.bindings[name]; !declared {
		s.bindings[name] = isHTTPClient
	}
}

func (s *httpClientScope) isHTTPClient(name string) bool {
	for current := s; current != nil; current = current.parent {
		if isHTTPClient, declared := current.bindings[name]; declared {
			return isHTTPClient
		}
	}
	return false
}

type httpClientTypeCollector struct {
	httpAliases map[string]struct{}
	identifiers map[*ast.Ident]struct{}
}

func collectHTTPClientIdentifiers(function *ast.FuncDecl, httpAliases map[string]struct{}) map[*ast.Ident]struct{} {
	collector := httpClientTypeCollector{
		httpAliases: httpAliases,
		identifiers: make(map[*ast.Ident]struct{}),
	}
	scope := newHTTPClientScope(nil)
	collector.declareFields(scope, function.Recv)
	collector.declareFields(scope, function.Type.Params)
	collector.declareFields(scope, function.Type.Results)
	collector.collectBlock(function.Body.List, scope)
	return collector.identifiers
}

func (c *httpClientTypeCollector) declareFields(scope *httpClientScope, fields *ast.FieldList) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		isHTTPClient := isHTTPTypeSyntax(field.Type, "Client", c.httpAliases)
		for _, name := range field.Names {
			scope.declare(name.Name, isHTTPClient)
		}
	}
}

func (c *httpClientTypeCollector) collectBlock(statements []ast.Stmt, scope *httpClientScope) {
	for _, statement := range statements {
		c.collectStatement(statement, scope)
	}
}

func (c *httpClientTypeCollector) collectStatement(statement ast.Stmt, scope *httpClientScope) {
	switch node := statement.(type) {
	case *ast.AssignStmt:
		c.collectAssignment(node, scope)
	case *ast.DeclStmt:
		c.collectDeclaration(node.Decl, scope)
	case *ast.BlockStmt:
		c.collectBlock(node.List, newHTTPClientScope(scope))
	case *ast.IfStmt:
		c.collectIf(node, scope)
	case *ast.ForStmt:
		c.collectFor(node, scope)
	case *ast.RangeStmt:
		c.collectRange(node, scope)
	case *ast.SwitchStmt:
		c.collectSwitch(node, scope)
	case *ast.TypeSwitchStmt:
		c.collectTypeSwitch(node, scope)
	case *ast.SelectStmt:
		c.collectSelect(node, scope)
	case *ast.LabeledStmt:
		c.collectStatement(node.Stmt, scope)
	default:
		c.collectExpressionIdentifiers(node, scope)
	}
}

func (c *httpClientTypeCollector) collectAssignment(assign *ast.AssignStmt, scope *httpClientScope) {
	for _, expression := range assign.Rhs {
		c.collectExpressionIdentifiers(expression, scope)
	}
	for _, expression := range assign.Lhs {
		if _, isIdentifier := expression.(*ast.Ident); !isIdentifier {
			c.collectExpressionIdentifiers(expression, scope)
		}
	}
	if assign.Tok != token.DEFINE {
		return
	}
	for index, expression := range assign.Lhs {
		identifier, ok := expression.(*ast.Ident)
		if !ok || identifier.Name == "_" {
			continue
		}
		if _, declared := scope.bindings[identifier.Name]; declared {
			continue
		}
		scope.declare(identifier.Name, c.assignmentValueIsHTTPClient(assign, index, scope))
	}
}

func (c *httpClientTypeCollector) assignmentValueIsHTTPClient(assign *ast.AssignStmt, index int, scope *httpClientScope) bool {
	if len(assign.Rhs) == len(assign.Lhs) {
		return c.expressionIsHTTPClient(assign.Rhs[index], scope)
	}
	return index == 0 && len(assign.Rhs) == 1 && c.expressionIsHTTPClient(assign.Rhs[0], scope)
}

func (c *httpClientTypeCollector) collectDeclaration(declaration ast.Decl, scope *httpClientScope) {
	general, ok := declaration.(*ast.GenDecl)
	if !ok {
		c.collectExpressionIdentifiers(declaration, scope)
		return
	}
	for _, spec := range general.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, expression := range value.Values {
			c.collectExpressionIdentifiers(expression, scope)
		}
		for index, name := range value.Names {
			scope.declare(name.Name, c.valueSpecNameIsHTTPClient(value, index, scope))
		}
	}
}

func (c *httpClientTypeCollector) valueSpecNameIsHTTPClient(spec *ast.ValueSpec, index int, scope *httpClientScope) bool {
	if spec.Type != nil {
		return isHTTPTypeSyntax(spec.Type, "Client", c.httpAliases)
	}
	if index < len(spec.Values) {
		return c.expressionIsHTTPClient(spec.Values[index], scope)
	}
	return false
}

func (c *httpClientTypeCollector) expressionIsHTTPClient(expression ast.Expr, scope *httpClientScope) bool {
	if identifier, ok := ast.Unparen(expression).(*ast.Ident); ok {
		return scope.isHTTPClient(identifier.Name)
	}
	return httpValueHasType(expression, "Client", c.httpAliases)
}

func (c *httpClientTypeCollector) collectIf(statement *ast.IfStmt, parent *httpClientScope) {
	scope := newHTTPClientScope(parent)
	if statement.Init != nil {
		c.collectStatement(statement.Init, scope)
	}
	c.collectExpressionIdentifiers(statement.Cond, scope)
	c.collectBlock(statement.Body.List, newHTTPClientScope(scope))
	if statement.Else != nil {
		c.collectStatement(statement.Else, scope)
	}
}

func (c *httpClientTypeCollector) collectFor(statement *ast.ForStmt, parent *httpClientScope) {
	scope := newHTTPClientScope(parent)
	if statement.Init != nil {
		c.collectStatement(statement.Init, scope)
	}
	c.collectExpressionIdentifiers(statement.Cond, scope)
	c.collectBlock(statement.Body.List, newHTTPClientScope(scope))
	if statement.Post != nil {
		c.collectStatement(statement.Post, scope)
	}
}

func (c *httpClientTypeCollector) collectRange(statement *ast.RangeStmt, parent *httpClientScope) {
	c.collectExpressionIdentifiers(statement.X, parent)
	scope := newHTTPClientScope(parent)
	if statement.Tok == token.DEFINE {
		for _, expression := range []ast.Expr{statement.Key, statement.Value} {
			if identifier, ok := expression.(*ast.Ident); ok {
				scope.declare(identifier.Name, false)
			}
		}
	}
	c.collectBlock(statement.Body.List, scope)
}

func (c *httpClientTypeCollector) collectSwitch(statement *ast.SwitchStmt, parent *httpClientScope) {
	scope := newHTTPClientScope(parent)
	if statement.Init != nil {
		c.collectStatement(statement.Init, scope)
	}
	c.collectExpressionIdentifiers(statement.Tag, scope)
	c.collectCaseClauses(statement.Body.List, scope)
}

func (c *httpClientTypeCollector) collectTypeSwitch(statement *ast.TypeSwitchStmt, parent *httpClientScope) {
	scope := newHTTPClientScope(parent)
	if statement.Init != nil {
		c.collectStatement(statement.Init, scope)
	}
	c.collectStatement(statement.Assign, scope)
	c.collectCaseClauses(statement.Body.List, scope)
}

func (c *httpClientTypeCollector) collectCaseClauses(statements []ast.Stmt, parent *httpClientScope) {
	for _, item := range statements {
		clause, ok := item.(*ast.CaseClause)
		if !ok {
			continue
		}
		scope := newHTTPClientScope(parent)
		for _, expression := range clause.List {
			c.collectExpressionIdentifiers(expression, scope)
		}
		c.collectBlock(clause.Body, scope)
	}
}

func (c *httpClientTypeCollector) collectSelect(statement *ast.SelectStmt, parent *httpClientScope) {
	for _, item := range statement.Body.List {
		clause, ok := item.(*ast.CommClause)
		if !ok {
			continue
		}
		scope := newHTTPClientScope(parent)
		if clause.Comm != nil {
			c.collectStatement(clause.Comm, scope)
		}
		c.collectBlock(clause.Body, scope)
	}
}

func (c *httpClientTypeCollector) collectExpressionIdentifiers(node ast.Node, scope *httpClientScope) {
	if node == nil {
		return
	}
	ast.Inspect(node, func(current ast.Node) bool {
		if function, ok := current.(*ast.FuncLit); ok {
			functionScope := newHTTPClientScope(scope)
			c.declareFields(functionScope, function.Type.Params)
			c.declareFields(functionScope, function.Type.Results)
			c.collectBlock(function.Body.List, functionScope)
			return false
		}
		identifier, ok := current.(*ast.Ident)
		if !ok {
			return true
		}
		if scope.isHTTPClient(identifier.Name) {
			c.identifiers[identifier] = struct{}{}
		}
		return true
	})
}

type httpBodyReachability struct {
	next      bool
	breaks    bool
	continues bool
}

func walkReachableHTTPBodyStatements(statements []ast.Stmt, visit func(ast.Node)) httpBodyReachability {
	flow := httpBodyReachability{next: true}
	for _, statement := range statements {
		if !flow.next {
			break
		}
		statementFlow := walkReachableHTTPBodyStatement(statement, visit)
		flow.breaks = flow.breaks || statementFlow.breaks
		flow.continues = flow.continues || statementFlow.continues
		flow.next = statementFlow.next
	}
	return flow
}

func walkReachableHTTPBodyStatement(statement ast.Stmt, visit func(ast.Node)) httpBodyReachability {
	switch node := statement.(type) {
	case *ast.BlockStmt:
		return walkReachableHTTPBodyStatements(node.List, visit)
	case *ast.IfStmt:
		if node.Init != nil {
			walkReachableHTTPBodyStatement(node.Init, visit)
		}
		visit(node.Cond)
		body := walkReachableHTTPBodyStatements(node.Body.List, visit)
		otherwise := httpBodyReachability{next: true}
		if node.Else != nil {
			otherwise = walkReachableHTTPBodyStatement(node.Else, visit)
		}
		return mergeHTTPBodyReachability(body, otherwise)
	case *ast.ForStmt:
		if node.Init != nil {
			walkReachableHTTPBodyStatement(node.Init, visit)
		}
		if node.Cond != nil {
			visit(node.Cond)
		}
		body := walkReachableHTTPBodyStatements(node.Body.List, visit)
		if node.Post != nil && (body.next || body.continues) {
			walkReachableHTTPBodyStatement(node.Post, visit)
		}
		return httpBodyReachability{next: node.Cond != nil || body.breaks}
	case *ast.RangeStmt:
		visit(node.X)
		walkReachableHTTPBodyStatements(node.Body.List, visit)
		return httpBodyReachability{next: true}
	case *ast.SwitchStmt:
		if node.Init != nil {
			walkReachableHTTPBodyStatement(node.Init, visit)
		}
		if node.Tag != nil {
			visit(node.Tag)
		}
		return walkReachableHTTPBodyClauses(node.Body.List, visit)
	case *ast.TypeSwitchStmt:
		if node.Init != nil {
			walkReachableHTTPBodyStatement(node.Init, visit)
		}
		walkReachableHTTPBodyStatement(node.Assign, visit)
		return walkReachableHTTPBodyClauses(node.Body.List, visit)
	case *ast.SelectStmt:
		return walkReachableHTTPBodyComms(node.Body.List, visit)
	case *ast.LabeledStmt:
		return walkReachableHTTPBodyStatement(node.Stmt, visit)
	case *ast.ReturnStmt:
		visit(node)
		return httpBodyReachability{}
	case *ast.BranchStmt:
		if node.Label != nil {
			return httpBodyReachability{}
		}
		switch node.Tok {
		case token.BREAK:
			return httpBodyReachability{breaks: true}
		case token.CONTINUE:
			return httpBodyReachability{continues: true}
		default:
			return httpBodyReachability{}
		}
	default:
		visit(node)
		if isPanicStatement(node) {
			return httpBodyReachability{}
		}
		return httpBodyReachability{next: true}
	}
}

func walkReachableHTTPBodyClauses(statements []ast.Stmt, visit func(ast.Node)) httpBodyReachability {
	result := httpBodyReachability{}
	hasDefault := false
	for _, statement := range statements {
		clause, ok := statement.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, expression := range clause.List {
			visit(expression)
		}
		flow := walkReachableHTTPBodyStatements(clause.Body, visit)
		result.next = result.next || flow.next || flow.breaks
		result.continues = result.continues || flow.continues
		hasDefault = hasDefault || len(clause.List) == 0
	}
	result.next = result.next || !hasDefault
	return result
}

func walkReachableHTTPBodyComms(statements []ast.Stmt, visit func(ast.Node)) httpBodyReachability {
	result := httpBodyReachability{}
	for _, statement := range statements {
		clause, ok := statement.(*ast.CommClause)
		if !ok {
			continue
		}
		if clause.Comm != nil {
			walkReachableHTTPBodyStatement(clause.Comm, visit)
		}
		flow := walkReachableHTTPBodyStatements(clause.Body, visit)
		result.next = result.next || flow.next || flow.breaks
		result.continues = result.continues || flow.continues
	}
	return result
}

func mergeHTTPBodyReachability(left, right httpBodyReachability) httpBodyReachability {
	return httpBodyReachability{
		next:      left.next || right.next,
		breaks:    left.breaks || right.breaks,
		continues: left.continues || right.continues,
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
	for _, declaration := range ctx.GoAST.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		for identifier := range collectHTTPClientIdentifiers(function, aliases) {
			aliases[httpClientIdentifierKey(identifier)] = struct{}{}
		}
	}
	return aliases
}

func httpClientIdentifierKey(identifier *ast.Ident) string {
	return "\x00http-client:" + strconv.Itoa(int(identifier.Pos()))
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
	return false
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
		_, ok := httpAliases[httpClientIdentifierKey(expr)]
		return ok
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

func httpValueHasType(expr ast.Expr, typeName string, httpAliases map[string]struct{}) bool {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.CompositeLit:
		return isHTTPTypeSyntax(expr.Type, typeName, httpAliases)
	case *ast.UnaryExpr:
		return expr.Op == token.AND && httpValueHasType(expr.X, typeName, httpAliases)
	case *ast.SelectorExpr:
		return typeName == "Client" && isHTTPDefaultClientExpr(expr, httpAliases)
	default:
		return false
	}
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
	return ctx.LineFor(node)
}
