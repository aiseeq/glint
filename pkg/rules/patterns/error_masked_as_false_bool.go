package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorMaskedAsFalseBoolRule())
}

// ErrorMaskedAsFalseBoolRule detects `if err != nil { return false }` patterns
// inside non-predicate bool-returning functions.
//
// The existing `error-masking` rule requires the function to return `error`.
// That misses a class of security-sensitive bugs where a `(...) bool`
// function internally calls an error-returning API, then conflates "error"
// with "not allowed":
//
//	func ValidateUserPermission(user, perm string) bool {
//	    permissions, err := c.GetRolePermissions(user)
//	    if err != nil {
//	        return false  // ← user gets denied for reasons they can't debug;
//	                      //   ops can't see that lookup is broken
//	    }
//	    ...
//	}
//
// Pure predicates (IsEnabled, HasRole, CanWrite, ShouldRetry) are exempt —
// returning false on lookup miss is their whole contract.
//
// Detects:
//   - `if err != nil { ... return false ... }` without any logging call
//   - Function's return type contains `bool` (any position, not just last)
//   - Function name does NOT start with Is/Has/Can/Should
//
// Skips:
//   - Test files
//   - Pure predicate functions (Is/Has/Can/Should prefix)
//   - Blocks that log the error before returning false
type ErrorMaskedAsFalseBoolRule struct {
	*rules.BaseRule
}

// NewErrorMaskedAsFalseBoolRule creates the rule
func NewErrorMaskedAsFalseBoolRule() *ErrorMaskedAsFalseBoolRule {
	return &ErrorMaskedAsFalseBoolRule{
		BaseRule: rules.NewBaseRule(
			"error-masked-as-false-bool",
			"patterns",
			"Detects error conflated with 'false' return in non-predicate bool functions",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile runs the rule.
func (r *ErrorMaskedAsFalseBoolRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		if !r.returnsBool(fn) {
			return true
		}
		if r.isPurePredicate(fn.Name.Name) {
			return true
		}

		violations = append(violations, r.findViolations(ctx, fn)...)
		return true
	})

	return violations
}

// returnsBool checks if any of the function's return values is bool.
func (r *ErrorMaskedAsFalseBoolRule) returnsBool(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, field := range fn.Type.Results.List {
		if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "bool" {
			return true
		}
	}
	return false
}

// isPurePredicate exempts conventional bool-returning predicates. Returning
// false from these on "not found" or error is their contract.
func (r *ErrorMaskedAsFalseBoolRule) isPurePredicate(name string) bool {
	prefixes := []string{"Is", "Has", "Can", "Should", "Contains", "Matches", "Exists", "Supports"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			// Ensure next char is uppercase (IsFoo, not "Issue")
			if len(name) == len(p) {
				return true
			}
			next := name[len(p)]
			if next >= 'A' && next <= 'Z' {
				return true
			}
		}
	}
	return false
}

// findViolations scans a function body for `if err != nil { return false }`
// patterns without logging.
func (r *ErrorMaskedAsFalseBoolRule) findViolations(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if !r.isErrNilCheck(ifStmt.Cond) {
			return true
		}

		ret := r.findReturnFalse(ifStmt.Body)
		if ret == nil {
			return true
		}
		if r.hasLoggingCall(ifStmt.Body) {
			return true
		}

		pos := ctx.PositionFor(ret)
		lineContent := ctx.GetLine(pos.Line)
		if strings.Contains(lineContent, "nolint:error-masked-as-false-bool") {
			return true
		}

		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Error from subcall masked as 'false' in "+fn.Name.Name+
				" — caller can't distinguish failure from denial")
		v.WithCode(strings.TrimSpace(lineContent))
		v.WithSuggestion("Either log the error before returning false, or change the signature to " +
			"(bool, error) so the caller can handle lookup failure explicitly. CLAUDE.md: " +
			"'Every error must be explicit, never hidden'.")
		v.WithContext("function", fn.Name.Name)
		violations = append(violations, v)
		return true
	})

	return violations
}

// isErrNilCheck matches `err != nil`.
func (r *ErrorMaskedAsFalseBoolRule) isErrNilCheck(cond ast.Expr) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if bin.Op.String() != "!=" {
		return false
	}
	lhs, lhsOk := bin.X.(*ast.Ident)
	rhs, rhsOk := bin.Y.(*ast.Ident)
	if !lhsOk || !rhsOk {
		return false
	}
	return (lhs.Name == "err" || strings.HasSuffix(lhs.Name, "Err")) && rhs.Name == "nil"
}

// findReturnFalse returns the first `return false` (or `return false, ...`)
// inside the body, or nil.
func (r *ErrorMaskedAsFalseBoolRule) findReturnFalse(body *ast.BlockStmt) *ast.ReturnStmt {
	var found *ast.ReturnStmt
	ast.Inspect(body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		for _, res := range ret.Results {
			if ident, ok := res.(*ast.Ident); ok && ident.Name == "false" {
				found = ret
				return false
			}
		}
		return true
	})
	return found
}

// hasLoggingCall returns true if any statement in the block calls something
// that looks like a logger (log.*, slog.*, logger.*, Log*/Error*/Warn*).
func (r *ErrorMaskedAsFalseBoolRule) hasLoggingCall(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := core.ExtractFullFunctionName(call)
		lower := strings.ToLower(name)
		if strings.Contains(lower, "log") || strings.Contains(lower, "error") ||
			strings.Contains(lower, "warn") || strings.Contains(lower, "slog") {
			found = true
			return false
		}
		return true
	})
	return found
}
