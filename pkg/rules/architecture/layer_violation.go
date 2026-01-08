package architecture

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewLayerViolationRule())
}

// LayerType represents an architectural layer
type LayerType int

const (
	UnknownLayer LayerType = iota
	HandlerLayer
	ServiceLayer
	RepositoryLayer
)

// LayerViolationRule detects architecture violations (Handler→Service→Repository)
type LayerViolationRule struct {
	*rules.BaseRule
}

// NewLayerViolationRule creates the rule
func NewLayerViolationRule() *LayerViolationRule {
	return &LayerViolationRule{
		BaseRule: rules.NewBaseRule(
			"layer-violation",
			"architecture",
			"Detects violations of layered architecture (Handler→Service→Repository)",
			core.SeverityCritical,
		),
	}
}

// AnalyzeFile checks for architecture violations
func (r *LayerViolationRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	layer := r.determineLayer(ctx.RelPath)
	if layer == UnknownLayer {
		return nil
	}

	var violations []*core.Violation

	// Check for layer-specific violations
	switch layer {
	case HandlerLayer:
		violations = append(violations, r.checkHandlerViolations(ctx)...)
	case ServiceLayer:
		violations = append(violations, r.checkServiceViolations(ctx)...)
	case RepositoryLayer:
		violations = append(violations, r.checkRepositoryViolations(ctx)...)
	}

	return violations
}

// determineLayer determines the architectural layer based on file path
func (r *LayerViolationRule) determineLayer(path string) LayerType {
	lowerPath := strings.ToLower(path)

	if strings.Contains(lowerPath, "handler") || strings.Contains(lowerPath, "/routing/") {
		return HandlerLayer
	}
	if strings.Contains(lowerPath, "service") {
		return ServiceLayer
	}
	if strings.Contains(lowerPath, "repository") || strings.Contains(lowerPath, "repo") {
		return RepositoryLayer
	}

	return UnknownLayer
}

// checkHandlerViolations checks for violations in handler layer
func (r *LayerViolationRule) checkHandlerViolations(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if v := r.checkDirectSQLCall(ctx, node, "Handler"); v != nil {
				violations = append(violations, v)
			}
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				if v := r.checkSQLString(ctx, node, "Handler"); v != nil {
					violations = append(violations, v)
				}
			}
		}
		return true
	})

	return violations
}

// checkServiceViolations checks for violations in service layer
func (r *LayerViolationRule) checkServiceViolations(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if v := r.checkDirectSQLCall(ctx, node, "Service"); v != nil {
				violations = append(violations, v)
			}
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				if v := r.checkSQLString(ctx, node, "Service"); v != nil {
					violations = append(violations, v)
				}
			}
		}
		return true
	})

	return violations
}

// checkRepositoryViolations checks for violations in repository layer
func (r *LayerViolationRule) checkRepositoryViolations(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if v := r.checkHTTPCall(ctx, call); v != nil {
				violations = append(violations, v)
			}
		}
		return true
	})

	return violations
}

// checkDirectSQLCall checks for direct SQL calls
func (r *LayerViolationRule) checkDirectSQLCall(ctx *core.FileContext, call *ast.CallExpr, layer string) *core.Violation {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil
	}

	// Check if receiver looks like a database connection
	if !r.isSQLReceiver(ident.Name) {
		return nil
	}

	// Check if method is a SQL method
	if !r.isSQLMethod(sel.Sel.Name) {
		return nil
	}

	pos := ctx.PositionFor(call)
	v := r.CreateViolation(ctx.RelPath, pos.Line,
		layer+" contains direct SQL call: "+ident.Name+"."+sel.Sel.Name)
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Move SQL operations to Repository layer")
	v.WithContext("layer", layer)
	v.WithContext("pattern", "direct_sql_call")

	return v
}

// checkSQLString checks for SQL strings in non-repository layers
func (r *LayerViolationRule) checkSQLString(ctx *core.FileContext, lit *ast.BasicLit, layer string) *core.Violation {
	value := strings.Trim(lit.Value, `"'`+"`")

	if !r.isSQLString(value) {
		return nil
	}

	pos := ctx.PositionFor(lit)
	truncated := value
	if len(truncated) > 50 {
		truncated = truncated[:50] + "..."
	}

	v := r.CreateViolation(ctx.RelPath, pos.Line,
		layer+" contains SQL query: "+truncated)
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Move SQL queries to Repository layer")
	v.WithContext("layer", layer)
	v.WithContext("pattern", "sql_string")

	return v
}

// checkHTTPCall checks for HTTP operations in repository layer
func (r *LayerViolationRule) checkHTTPCall(ctx *core.FileContext, call *ast.CallExpr) *core.Violation {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	methodName := sel.Sel.Name

	if !r.isHTTPOperation(methodName) {
		return nil
	}

	pos := ctx.PositionFor(call)
	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"Repository contains HTTP operation: "+methodName)
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Repository should only handle data access, move HTTP logic to Service/Handler")
	v.WithContext("layer", "Repository")
	v.WithContext("pattern", "http_in_repo")

	return v
}

// isSQLReceiver checks if the receiver name looks like a DB connection
func (r *LayerViolationRule) isSQLReceiver(name string) bool {
	sqlReceivers := []string{"db", "DB", "tx", "TX", "conn", "database", "pool"}
	for _, recv := range sqlReceivers {
		if name == recv {
			return true
		}
	}
	return false
}

// isSQLMethod checks if the method is a SQL operation
func (r *LayerViolationRule) isSQLMethod(name string) bool {
	sqlMethods := []string{
		"Query", "QueryRow", "QueryContext", "QueryRowContext",
		"Exec", "ExecContext", "Prepare", "PrepareContext",
		"Begin", "BeginTx",
	}
	for _, method := range sqlMethods {
		if name == method {
			return true
		}
	}
	return false
}

// SQL patterns for detection
var sqlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^SELECT\s+.+\s+FROM\s+\w+`),
	regexp.MustCompile(`(?i)^INSERT\s+INTO\s+\w+`),
	regexp.MustCompile(`(?i)^UPDATE\s+\w+\s+SET\s+`),
	regexp.MustCompile(`(?i)^DELETE\s+FROM\s+\w+`),
	regexp.MustCompile(`(?i)^CREATE\s+(TABLE|INDEX|DATABASE)`),
	regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+`),
	regexp.MustCompile(`(?i)^DROP\s+(TABLE|INDEX|DATABASE)`),
}

// isSQLString checks if a string looks like a SQL query
func (r *LayerViolationRule) isSQLString(value string) bool {
	if len(value) < 10 {
		return false
	}

	trimmed := strings.TrimSpace(value)

	// Exclude error messages and descriptions
	upper := strings.ToUpper(trimmed)
	excludePatterns := []string{
		"ERROR", "FAILED", "INVALID", "NOT FOUND",
		"UNAUTHORIZED", "FORBIDDEN", "TIMEOUT",
		"METHOD NOT", "NOT IMPLEMENTED",
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(upper, pattern) {
			return false
		}
	}

	// Check SQL patterns
	for _, pattern := range sqlPatterns {
		if pattern.MatchString(trimmed) {
			return true
		}
	}

	return false
}

// isHTTPOperation checks if a method name indicates HTTP operation
func (r *LayerViolationRule) isHTTPOperation(name string) bool {
	httpOps := []string{
		"WriteHeader", "ServeHTTP", "Redirect",
		"ParseForm", "Cookie", "SetCookie",
	}
	for _, op := range httpOps {
		if name == op {
			return true
		}
	}

	// HTTP methods in context of web frameworks
	if strings.HasPrefix(name, "HTTP") ||
		strings.Contains(name, "Response") && strings.Contains(name, "Writer") {
		return true
	}

	return false
}
