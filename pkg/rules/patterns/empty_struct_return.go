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
// Catches: return Money{}, nil (in error context)
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
	return analyzeGoFunctions(ctx, func(funcDecl *ast.FuncDecl) []*core.Violation {
		if !r.hasErrorReturn(funcDecl) {
			return nil
		}
		// Error branches anywhere in the body — loops, switch and select cases
		// included; a closure returns through its own signature.
		var violations []*core.Violation
		forEachOwnStatement(funcDecl.Body, func(stmt ast.Stmt) {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok || !r.isErrorOrNilCheck(ifStmt.Cond) {
				return
			}
			for _, bodyStmt := range ifStmt.Body.List {
				if ret, ok := bodyStmt.(*ast.ReturnStmt); ok {
					if v := r.checkReturnForEmptyStructWithNilError(ctx, ret); v != nil {
						violations = append(violations, v)
					}
				}
			}
		})
		return violations
	})
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

// isErrorOrNilCheck determines if condition checks for error or nil
func (r *EmptyStructReturnRule) isErrorOrNilCheck(cond ast.Expr) bool {
	switch c := cond.(type) {
	case *ast.BinaryExpr:
		// err != nil, x == nil, etc.
		if c.Op == token.NEQ || c.Op == token.EQL {
			if isNilIdent(c.Y) {
				return true
			}
			if isNilIdent(c.X) {
				return true
			}
			// Check for err variable
			if ident, ok := c.X.(*ast.Ident); ok && isErrorVarName(ident.Name) {
				return true
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

// checkReturnForEmptyStructWithNilError checks if return has empty struct + nil error
func (r *EmptyStructReturnRule) checkReturnForEmptyStructWithNilError(ctx *core.FileContext, ret *ast.ReturnStmt) *core.Violation {
	if len(ret.Results) < 2 {
		return nil
	}

	// Check last result is nil (the error)
	lastResult := ret.Results[len(ret.Results)-1]
	if !isNilIdent(lastResult) {
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
	// time.Time: its zero value is a valid, checkable value (IsZero).
	return strings.HasSuffix(typeName, "Time")
}
