package deadcode

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNilReturnStubRule())
}

// NilReturnStubRule detects methods that only return nil without doing any work.
// These are typically interface compliance stubs that provide no functionality.
//
// Detects patterns like:
//
//	func (s *Service) GetData() (*Data, error) {
//	    return nil, nil
//	}
//
//	func (s *Service) Process() error {
//	    return nil // INTERFACE COMPLIANCE WRAPPER
//	}
type NilReturnStubRule struct {
	*rules.BaseRule
	compliancePatterns []string
}

// NewNilReturnStubRule creates the rule
func NewNilReturnStubRule() *NilReturnStubRule {
	return &NilReturnStubRule{
		BaseRule: rules.NewBaseRule(
			"nil-return-stub",
			"deadcode",
			"Detects methods that only return nil without functionality (interface compliance stubs)",
			core.SeverityLow,
		),
		compliancePatterns: []string{
			"interface compliance",
			"compliance wrapper",
			"stub",
			"placeholder",
			"not implemented yet",
			"todo: implement",
			"fixme: implement",
		},
	}
}

// AnalyzeFile checks for nil-return stub methods in Go files
func (r *NilReturnStubRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	// Skip test utility files
	pathLower := strings.ToLower(ctx.RelPath)
	if strings.Contains(pathLower, "/test") || strings.Contains(pathLower, "test_") {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Only check methods (functions with receivers)
		if fn.Recv == nil || len(fn.Recv.List) == 0 {
			return true
		}

		if v := r.checkForNilStub(ctx, fn); v != nil {
			violations = append(violations, v)
		}

		return true
	})

	return violations
}

// checkForNilStub checks if a method is a nil-returning stub
func (r *NilReturnStubRule) checkForNilStub(ctx *core.FileContext, fn *ast.FuncDecl) *core.Violation {
	// Must have exactly one statement (the return)
	if len(fn.Body.List) != 1 {
		return nil
	}

	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok {
		return nil
	}

	// Check if all return values are nil
	if !r.isAllNilReturn(ret) {
		return nil
	}

	// Check if there's a compliance-related comment
	hasComplianceComment := r.hasComplianceComment(fn)

	// Only report if it looks like a compliance stub (has comment or returns multiple nils)
	if !hasComplianceComment && len(ret.Results) < 2 {
		return nil
	}

	pos := ctx.PositionFor(fn.Name)
	funcName := r.getReceiverType(fn.Recv.List[0]) + "." + fn.Name.Name

	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"Method '"+funcName+"' only returns nil - likely an interface compliance stub")
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Either implement the method or remove it from the interface")
	return v
}

// isAllNilReturn checks if all return values are nil
func (r *NilReturnStubRule) isAllNilReturn(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false // Empty return is not a nil stub
	}

	for _, result := range ret.Results {
		if !r.isNilExpr(result) {
			return false
		}
	}
	return true
}

// isNilExpr checks if an expression is nil
func (r *NilReturnStubRule) isNilExpr(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}

// hasComplianceComment checks if the function has interface compliance related comments
func (r *NilReturnStubRule) hasComplianceComment(fn *ast.FuncDecl) bool {
	if fn.Doc == nil {
		return false
	}

	for _, comment := range fn.Doc.List {
		commentLower := strings.ToLower(comment.Text)
		for _, pattern := range r.compliancePatterns {
			if strings.Contains(commentLower, pattern) {
				return true
			}
		}
	}
	return false
}

// getReceiverType extracts the receiver type name
func (r *NilReturnStubRule) getReceiverType(field *ast.Field) string {
	switch t := field.Type.(type) {
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}
