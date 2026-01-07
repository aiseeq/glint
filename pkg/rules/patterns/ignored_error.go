package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewIgnoredErrorRule())
}

// IgnoredErrorRule detects ignored error returns
type IgnoredErrorRule struct {
	*rules.BaseRule
}

// NewIgnoredErrorRule creates a new ignored error detector
func NewIgnoredErrorRule() *IgnoredErrorRule {
	return &IgnoredErrorRule{
		BaseRule: rules.NewBaseRule(
			"ignored-error",
			"patterns",
			"Detects error values that are explicitly ignored with blank identifier",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for ignored errors
func (r *IgnoredErrorRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	visitor := core.NewGoASTVisitor(ctx)
	visitor.OnAssignStmt(func(stmt *ast.AssignStmt) {
		// Check for blank identifier assignments
		for i, lhs := range stmt.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || ident.Name != "_" {
				continue
			}

			// Check if the corresponding RHS might return an error
			if i < len(stmt.Rhs) {
				if call, ok := stmt.Rhs[i].(*ast.CallExpr); ok {
					funcName := core.ExtractFullFunctionName(call)
					// Common error-returning patterns
					if looksLikeErrorReturn(funcName) {
						pos := ctx.PositionFor(stmt)
						v := r.CreateViolation(ctx.RelPath, pos.Line,
							"Error from "+funcName+" is ignored")
						v.WithCode(ctx.GetLine(pos.Line))
						v.WithSuggestion("Handle the error or use a named blank identifier with comment")
						violations = append(violations, v)
					}
				}
			}
		}

		// Check for assignments like: result, _ := SomeFunc()
		// where _ is in the error position (typically last)
		if len(stmt.Lhs) >= 2 && len(stmt.Rhs) >= 1 {
			lastLhs := stmt.Lhs[len(stmt.Lhs)-1]
			if ident, ok := lastLhs.(*ast.Ident); ok && ident.Name == "_" {
				if call, ok := stmt.Rhs[0].(*ast.CallExpr); ok {
					funcName := core.ExtractFullFunctionName(call)
					if !isKnownSafeToIgnore(funcName) {
						pos := ctx.PositionFor(stmt)
						v := r.CreateViolation(ctx.RelPath, pos.Line,
							"Potential error ignored in multi-value assignment from "+funcName)
						v.WithCode(ctx.GetLine(pos.Line))
						v.WithSuggestion("Consider handling the error")
						violations = append(violations, v)
					}
				}
			}
		}
	})
	visitor.Visit()

	return violations
}

func looksLikeErrorReturn(funcName string) bool {
	// Functions that commonly return errors
	errorPatterns := []string{
		"Write", "Read", "Close", "Open", "Create",
		"Parse", "Marshal", "Unmarshal",
		"Scan", "Query", "Exec",
		"Send", "Receive", "Dial", "Connect",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}

	return false
}

func isKnownSafeToIgnore(funcName string) bool {
	// Functions where ignoring return value is often acceptable
	safePatterns := []string{
		"Printf", "Println", "Print",
		"Fprintf", "Fprintln", "Fprint",
		"Sprintf", "Sprint",
	}

	for _, pattern := range safePatterns {
		if strings.HasSuffix(funcName, pattern) {
			return true
		}
	}

	return false
}
