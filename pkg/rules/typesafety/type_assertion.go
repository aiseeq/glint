package typesafety

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTypeAssertionRule())
}

// TypeAssertionRule detects unsafe type assertions without comma-ok idiom
type TypeAssertionRule struct {
	*rules.BaseRule
}

// NewTypeAssertionRule creates the rule
func NewTypeAssertionRule() *TypeAssertionRule {
	return &TypeAssertionRule{
		BaseRule: rules.NewBaseRule(
			"type-assertion",
			"typesafety",
			"Detects unsafe type assertions without comma-ok check (may cause runtime failure)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks for unsafe type assertions
func (r *TypeAssertionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	fset := ctx.GoFileSet
	if fset == nil {
		fset = token.NewFileSet()
	}

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			// Check for v := x.(T) pattern (unsafe, no ok check)
			if len(stmt.Lhs) == 1 && len(stmt.Rhs) == 1 {
				if typeAssert, ok := stmt.Rhs[0].(*ast.TypeAssertExpr); ok {
					// This is v := x.(T) - unsafe single-value assertion
					if typeAssert.Type != nil { // Exclude type switch x.(type)
						v := r.createViolation(ctx, fset, stmt.Pos(), typeAssert)
						violations = append(violations, v)
					}
				}
			}
			// len(Lhs) == 2 is safe: v, ok := x.(T)

		case *ast.ExprStmt:
			// Check for standalone type assertions like _ = x.(T)
			if typeAssert, ok := stmt.X.(*ast.TypeAssertExpr); ok {
				if typeAssert.Type != nil {
					v := r.createViolation(ctx, fset, stmt.Pos(), typeAssert)
					violations = append(violations, v)
				}
			}

		case *ast.ValueSpec:
			// Check for var v = x.(T)
			if len(stmt.Names) == 1 && len(stmt.Values) == 1 {
				if typeAssert, ok := stmt.Values[0].(*ast.TypeAssertExpr); ok {
					if typeAssert.Type != nil {
						v := r.createViolation(ctx, fset, stmt.Pos(), typeAssert)
						violations = append(violations, v)
					}
				}
			}
		}
		return true
	})

	return violations
}

func (r *TypeAssertionRule) createViolation(ctx *core.FileContext, fset *token.FileSet, pos token.Pos, typeAssert *ast.TypeAssertExpr) *core.Violation {
	line := r.getLineFromPos(ctx, pos)

	v := r.CreateViolation(ctx.RelPath, line, "Unsafe type assertion without comma-ok check")
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Use 'v, ok := x.(T)' and handle the case when ok is false")
	v.WithContext("pattern", "unsafe_type_assertion")

	// Add target type if available
	if typeAssert.Type != nil {
		v.WithContext("target_type", formatType(typeAssert.Type))
	}

	return v
}

func (r *TypeAssertionRule) getLineFromPos(ctx *core.FileContext, pos token.Pos) int {
	// token.Pos is 1-based offset within file
	// We need to find the line number by counting newlines
	if pos == token.NoPos {
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

func formatType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + formatType(t.X)
	case *ast.SelectorExpr:
		return formatType(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + formatType(t.Elt)
		}
		return "[...]" + formatType(t.Elt)
	case *ast.MapType:
		return "map[" + formatType(t.Key) + "]" + formatType(t.Value)
	default:
		return "unknown"
	}
}
