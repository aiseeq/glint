package patterns

import (
	"go/ast"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewContextFirstRule())
}

// ContextFirstRule detects public functions without context.Context as first parameter
type ContextFirstRule struct {
	*rules.BaseRule
}

// NewContextFirstRule creates the rule
func NewContextFirstRule() *ContextFirstRule {
	return &ContextFirstRule{
		BaseRule: rules.NewBaseRule(
			"context-first",
			"patterns",
			"Detects public functions without context.Context as first parameter",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for context.Context as first parameter in public functions
func (r *ContextFirstRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	// Skip main package and test helpers
	if r.shouldSkipFile(ctx.RelPath) {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			return true
		}

		// Only check public functions (capitalized)
		if !isPublic(fn.Name.Name) {
			return true
		}

		// Skip special functions
		if r.isSpecialFunction(fn) {
			return true
		}

		// Skip functions that return only error (like Close(), Flush())
		if r.isSimpleOperation(fn) {
			return true
		}

		// Skip constructors and factory functions
		if r.isConstructor(fn.Name.Name) {
			return true
		}

		// Check if first parameter is context.Context
		if !r.hasContextFirstParam(fn) {
			pos := ctx.PositionFor(fn)
			funcName := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				if typeName := getReceiverTypeName(fn.Recv.List[0].Type); typeName != "" {
					funcName = typeName + "." + funcName
				}
			}

			v := r.CreateViolation(ctx.RelPath, pos.Line,
				funcName+" should have context.Context as first parameter")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Add ctx context.Context as the first parameter for proper cancellation and deadline propagation")
			violations = append(violations, v)
		}

		return true
	})

	return violations
}

func (r *ContextFirstRule) shouldSkipFile(path string) bool {
	skipPatterns := []string{
		"_test.go",
		"/testdata/",
		"/testing/",
		"/test_",
		"_mock",
		"/mocks/",
		"/generated/",
		"main.go",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range skipPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

func (r *ContextFirstRule) isSpecialFunction(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	specialNames := []string{
		"init", "main",
		"String", "Error", "MarshalJSON", "UnmarshalJSON",
		"MarshalText", "UnmarshalText", "MarshalBinary", "UnmarshalBinary",
		"Scan", "Value", // sql.Scanner, driver.Valuer
		"ServeHTTP",     // http.Handler (context is in request)
		"Unwrap",        // error interface method for unwrapping errors
		"Commit",        // database transaction (context often stored in struct)
		"Rollback",      // database transaction
		"Ping",          // simple healthcheck operations
		"Stats",         // statistics retrieval (no side effects)
	}

	for _, special := range specialNames {
		if name == special {
			return true
		}
	}

	// Is* predicates - pure functions checking error/state types (no context needed)
	if strings.HasPrefix(name, "Is") && len(name) > 2 && unicode.IsUpper(rune(name[2])) {
		return true
	}

	// Set* setters for dependency injection (no context needed, just struct assignment)
	if strings.HasPrefix(name, "Set") && len(name) > 3 && unicode.IsUpper(rune(name[3])) {
		return true
	}

	// Get* simple getters that just return struct fields (no context needed)
	// Only if they have no parameters (pure accessors)
	if strings.HasPrefix(name, "Get") && len(name) > 3 && unicode.IsUpper(rune(name[3])) {
		if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
			return true
		}
	}

	// *Operations methods - delegation pattern returning interfaces
	if strings.HasSuffix(name, "Operations") {
		return true
	}

	// Valid* functions - return validation constants/lists
	if strings.HasPrefix(name, "Valid") {
		return true
	}

	// Wrap* error wrapping functions - add context to errors
	if strings.HasPrefix(name, "Wrap") {
		return true
	}

	return false
}

func (r *ContextFirstRule) isSimpleOperation(fn *ast.FuncDecl) bool {
	// Skip simple operations like Close(), Flush(), Reset()
	simpleOps := []string{"Close", "Flush", "Reset", "Clear", "Stop", "Start"}
	for _, op := range simpleOps {
		if fn.Name.Name == op {
			return true
		}
	}
	return false
}

func (r *ContextFirstRule) isConstructor(name string) bool {
	// New*, Make*, Create* without further params context expectation
	return strings.HasPrefix(name, "New") ||
		strings.HasPrefix(name, "Make") ||
		strings.HasPrefix(name, "Create") ||
		strings.HasPrefix(name, "Build") ||
		strings.HasPrefix(name, "Parse") ||
		strings.HasPrefix(name, "Load") ||
		strings.HasPrefix(name, "Must")
}

func (r *ContextFirstRule) hasContextFirstParam(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return false
	}

	firstParam := fn.Type.Params.List[0]
	return isContextType(firstParam.Type)
}

func isContextType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name == "context" && t.Sel.Name == "Context"
		}
	case *ast.Ident:
		// Handle aliased imports like `ctx context.Context`
		return t.Name == "Context"
	}
	return false
}

func isPublic(name string) bool {
	if len(name) == 0 {
		return false
	}
	return unicode.IsUpper(rune(name[0]))
}

func getReceiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}
