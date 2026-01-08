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
		violations = append(violations, r.checkBlankIdentifiers(ctx, stmt)...)
		violations = append(violations, r.checkMultiValueAssignment(ctx, stmt)...)
	})
	visitor.Visit()

	return violations
}

func (r *IgnoredErrorRule) checkBlankIdentifiers(ctx *core.FileContext, stmt *ast.AssignStmt) []*core.Violation {
	var violations []*core.Violation

	for i, lhs := range stmt.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name != "_" || i >= len(stmt.Rhs) {
			continue
		}

		call, ok := stmt.Rhs[i].(*ast.CallExpr)
		if !ok {
			continue
		}

		funcName := core.ExtractFullFunctionName(call)
		if looksLikeErrorReturn(funcName) {
			pos := ctx.PositionFor(stmt)
			v := r.CreateViolation(ctx.RelPath, pos.Line, "Error from "+funcName+" is ignored")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Handle the error or use a named blank identifier with comment")
			violations = append(violations, v)
		}
	}

	return violations
}

func (r *IgnoredErrorRule) checkMultiValueAssignment(ctx *core.FileContext, stmt *ast.AssignStmt) []*core.Violation {
	if len(stmt.Lhs) < 2 || len(stmt.Rhs) < 1 {
		return nil
	}

	lastLhs := stmt.Lhs[len(stmt.Lhs)-1]
	ident, ok := lastLhs.(*ast.Ident)
	if !ok || ident.Name != "_" {
		return nil
	}

	call, ok := stmt.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil
	}

	funcName := core.ExtractFullFunctionName(call)
	if isKnownSafeToIgnore(funcName) {
		return nil
	}

	pos := ctx.PositionFor(stmt)
	v := r.CreateViolation(ctx.RelPath, pos.Line, "Potential error ignored in multi-value assignment from "+funcName)
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Consider handling the error")
	return []*core.Violation{v}
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
