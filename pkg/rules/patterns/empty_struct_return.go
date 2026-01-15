package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewEmptyStructReturnRule())
}

// EmptyStructReturnRule detects functions that return empty structs with nil error
// instead of returning explicit error. This violates "Fail explicitly, never degrade silently"
// Catches: return SafeDecimal{}, nil (in error context)
// Catches: return Config{} (without error, in error context)
type EmptyStructReturnRule struct {
	*rules.BaseRule
}

// NewEmptyStructReturnRule creates the rule
func NewEmptyStructReturnRule() *EmptyStructReturnRule {
	return &EmptyStructReturnRule{
		BaseRule: rules.NewBaseRule(
			"empty-struct-return",
			"patterns",
			"Detects empty struct returns that hide errors instead of propagating them",
			core.SeverityCritical,
		),
	}
}

// AnalyzeFile checks for empty struct returns in error contexts
func (r *EmptyStructReturnRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	// Skip test utility files
	pathLower := strings.ToLower(ctx.RelPath)
	if strings.Contains(pathLower, "/test") || strings.Contains(pathLower, "test_") ||
		strings.HasSuffix(pathLower, "/test.go") || strings.HasSuffix(pathLower, "/testing.go") {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Look for function declarations
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok || funcDecl.Body == nil {
			return true
		}

		// Check if function has error in return type
		if !r.hasErrorReturn(funcDecl) {
			return true
		}

		// Find return statements inside if blocks that check errors/nil
		for _, stmt := range funcDecl.Body.List {
			v := r.checkStatement(ctx, stmt, funcDecl)
			violations = append(violations, v...)
		}

		return true
	})

	return violations
}

// hasErrorReturn checks if function returns error type
func (r *EmptyStructReturnRule) hasErrorReturn(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, result := range fn.Type.Results.List {
		if ident, ok := result.Type.(*ast.Ident); ok && ident.Name == "error" {
			return true
		}
	}
	return false
}

// checkStatement recursively checks statements for problematic patterns
func (r *EmptyStructReturnRule) checkStatement(ctx *core.FileContext, stmt ast.Stmt, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation

	switch s := stmt.(type) {
	case *ast.IfStmt:
		// Check if this is an error/nil check
		if r.isErrorOrNilCheck(s.Cond) {
			// Check body for problematic returns
			for _, bodyStmt := range s.Body.List {
				if ret, ok := bodyStmt.(*ast.ReturnStmt); ok {
					if v := r.checkReturnForEmptyStructWithNilError(ctx, ret); v != nil {
						violations = append(violations, v)
					}
				}
			}
			// Also check else branch
			if s.Else != nil {
				violations = append(violations, r.checkStatement(ctx, s.Else, fn)...)
			}
		}
		// Recurse into body
		for _, bodyStmt := range s.Body.List {
			violations = append(violations, r.checkStatement(ctx, bodyStmt, fn)...)
		}

	case *ast.BlockStmt:
		for _, blockStmt := range s.List {
			violations = append(violations, r.checkStatement(ctx, blockStmt, fn)...)
		}
	}

	return violations
}

// isErrorOrNilCheck determines if condition checks for error or nil
func (r *EmptyStructReturnRule) isErrorOrNilCheck(cond ast.Expr) bool {
	switch c := cond.(type) {
	case *ast.BinaryExpr:
		// err != nil, x == nil, etc.
		if c.Op == token.NEQ || c.Op == token.EQL {
			if r.isNilIdent(c.Y) {
				return true
			}
			if r.isNilIdent(c.X) {
				return true
			}
			// Check for err variable
			if ident, ok := c.X.(*ast.Ident); ok {
				nameLower := strings.ToLower(ident.Name)
				if nameLower == "err" || strings.HasSuffix(nameLower, "err") {
					return true
				}
			}
		}
	case *ast.UnaryExpr:
		// !ok, !success, etc.
		if c.Op == token.NOT {
			return true
		}
	}
	return false
}

func (r *EmptyStructReturnRule) isNilIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}

// checkReturnForEmptyStructWithNilError checks if return has empty struct + nil error
func (r *EmptyStructReturnRule) checkReturnForEmptyStructWithNilError(ctx *core.FileContext, ret *ast.ReturnStmt) *core.Violation {
	if len(ret.Results) < 2 {
		return nil
	}

	// Check last result is nil (the error)
	lastResult := ret.Results[len(ret.Results)-1]
	if !r.isNilIdent(lastResult) {
		return nil
	}

	// Check if any prior result is an empty composite literal
	for i := 0; i < len(ret.Results)-1; i++ {
		if lit, ok := ret.Results[i].(*ast.CompositeLit); ok {
			// Empty struct: SomeType{} or SomeType{} with no elts
			if len(lit.Elts) == 0 {
				typeName := r.extractTypeName(lit.Type)
				if typeName != "" && !r.isAllowedEmptyStruct(typeName) {
					pos := ctx.PositionFor(ret)
					lineContent := ctx.GetLine(pos.Line)

					// Skip if has nolint
					if strings.Contains(lineContent, "nolint") {
						return nil
					}

					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Empty "+typeName+"{} returned with nil error hides failure")
					v.WithCode(lineContent)
					v.WithSuggestion("Return explicit error instead of nil to propagate failure")
					return v
				}
			}
		}
	}

	return nil
}

func (r *EmptyStructReturnRule) extractTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	}
	return ""
}

// isAllowedEmptyStruct returns true for structs that are OK to return empty
func (r *EmptyStructReturnRule) isAllowedEmptyStruct(typeName string) bool {
	// Common value objects that don't need error wrapping
	allowed := []string{
		"struct", // anonymous struct{}
		"Time",   // time.Time zero value is valid
	}

	for _, a := range allowed {
		if strings.HasSuffix(typeName, a) {
			return true
		}
	}
	return false
}
