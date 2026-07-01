package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMaskedErrorOrConditionRule())
}

// MaskedErrorOrConditionRule detects branches that conflate a real error with
// a legitimate "no data" case via ||, then swallow the error:
//
//	if err != nil || latest == nil {
//	    return SafeDecimal{}, nil   // DB failure masked as valid zero value
//	}
//
// The caller cannot distinguish a storage failure from an honest zero.
// CLAUDE.md: "Fail explicitly, never degrade silently".
//
// Not flagged: branches that propagate/wrap the error, branches that handle
// the error in a nested if, &&-narrowing (errors.Is style), and functions
// without an error result (see log-and-return-zero for those).
type MaskedErrorOrConditionRule struct {
	*rules.BaseRule
}

// NewMaskedErrorOrConditionRule creates the rule
func NewMaskedErrorOrConditionRule() *MaskedErrorOrConditionRule {
	return &MaskedErrorOrConditionRule{
		BaseRule: rules.NewBaseRule(
			"masked-error-in-or-condition",
			"patterns",
			"Detects err != nil conflated with no-data via || in a branch that returns nil error",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks Go functions for the masking pattern
func (r *MaskedErrorOrConditionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		body, results := functionParts(n)
		if body == nil || !lastResultIsErrorType(results) {
			return true
		}

		forEachOwnStatement(body, func(stmt ast.Stmt) {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				return
			}
			errNames := errCheckNamesInOrCondition(ifStmt.Cond)
			if len(errNames) == 0 {
				return
			}
			violations = append(violations, r.checkBranch(ctx, ifStmt, errNames)...)
		})

		return true
	})

	return violations
}

// checkBranch inspects the then-branch of an if whose ||-condition contains
// an err != nil operand, and reports returns that swallow the error.
func (r *MaskedErrorOrConditionRule) checkBranch(
	ctx *core.FileContext, ifStmt *ast.IfStmt, errNames map[string]bool,
) []*core.Violation {
	handled := false
	var maskingReturns []*ast.ReturnStmt

	forEachOwnStatement(ifStmt.Body, func(stmt ast.Stmt) {
		switch s := stmt.(type) {
		case *ast.IfStmt:
			// A nested check on the error variable means the branch
			// distinguishes the failure case — not masking.
			if exprMentionsAnyName(s.Cond, errNames) {
				handled = true
			}
		case *ast.ReturnStmt:
			if returnMentionsAnyName(s, errNames) {
				// The error is propagated or wrapped — not masking.
				handled = true
				return
			}
			if returnsNilError(s) {
				maskingReturns = append(maskingReturns, s)
			}
		}
	})

	if handled {
		return nil
	}

	var violations []*core.Violation
	for _, ret := range maskingReturns {
		pos := ctx.PositionFor(ret)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Branch guarded by 'err != nil || ...' returns nil error — a real failure is masked as a valid zero value")
		v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
		v.WithSuggestion("Split the condition: return the error when err != nil; keep the no-data case as a separate branch")
		violations = append(violations, v)
	}
	return violations
}

// functionParts extracts body and results from FuncDecl/FuncLit nodes.
func functionParts(n ast.Node) (*ast.BlockStmt, *ast.FieldList) {
	switch fn := n.(type) {
	case *ast.FuncDecl:
		if fn.Type == nil {
			return nil, nil
		}
		return fn.Body, fn.Type.Results
	case *ast.FuncLit:
		if fn.Type == nil {
			return nil, nil
		}
		return fn.Body, fn.Type.Results
	}
	return nil, nil
}

// lastResultIsErrorType reports whether the last result in the field list is
// the builtin error type.
func lastResultIsErrorType(results *ast.FieldList) bool {
	if results == nil || len(results.List) == 0 {
		return false
	}
	last := results.List[len(results.List)-1]
	ident, ok := last.Type.(*ast.Ident)
	return ok && ident.Name == "error"
}

// forEachOwnStatement walks all statements inside node, pruning nested
// function literals: their statements belong to the closure, not to the
// enclosing function.
func forEachOwnStatement(node ast.Node, visit func(ast.Stmt)) {
	ast.Inspect(node, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if stmt, ok := n.(ast.Stmt); ok {
			visit(stmt)
		}
		return true
	})
}

// errCheckNamesInOrCondition returns the names of error-like variables
// compared via `!= nil` inside ||-disjunctions of the condition. Empty map
// when the condition has no || with an error check (plain and &&-narrowed
// conditions are out of scope).
func errCheckNamesInOrCondition(cond ast.Expr) map[string]bool {
	names := make(map[string]bool)
	ast.Inspect(cond, func(n ast.Node) bool {
		be, ok := n.(*ast.BinaryExpr)
		if !ok || be.Op != token.LOR {
			return true
		}
		for _, operand := range flattenOr(be) {
			if name, ok := errNotNilName(operand); ok {
				names[name] = true
			}
		}
		return true
	})
	return names
}

// flattenOr flattens a ||-chain into its operands.
func flattenOr(expr ast.Expr) []ast.Expr {
	if be, ok := expr.(*ast.BinaryExpr); ok && be.Op == token.LOR {
		return append(flattenOr(be.X), flattenOr(be.Y)...)
	}
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return flattenOr(paren.X)
	}
	return []ast.Expr{expr}
}

// errNotNilName matches `<errVar> != nil` (or reversed) where the variable
// name looks like an error, returning the name.
func errNotNilName(expr ast.Expr) (string, bool) {
	be, ok := expr.(*ast.BinaryExpr)
	if !ok || be.Op != token.NEQ {
		return "", false
	}
	for _, pair := range [][2]ast.Expr{{be.X, be.Y}, {be.Y, be.X}} {
		if !isNilIdent(pair[1]) {
			continue
		}
		if name, ok := errLikeName(pair[0]); ok {
			return name, true
		}
	}
	return "", false
}

// errLikeName extracts the identifier name from an expression when it looks
// like an error variable (err, dbErr, loadError, resp.Err, ...).
func errLikeName(expr ast.Expr) (string, bool) {
	var name string
	switch e := expr.(type) {
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		name = e.Sel.Name
	default:
		return "", false
	}
	lower := strings.ToLower(name)
	if lower == "err" || strings.HasSuffix(name, "Err") || strings.HasSuffix(lower, "error") {
		return name, true
	}
	return "", false
}

// isNilIdent reports whether the expression is the nil identifier.
func isNilIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}

// returnsNilError reports whether the return statement's last value is the
// nil identifier (i.e. the error slot holds literal nil).
func returnsNilError(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false
	}
	return isNilIdent(ret.Results[len(ret.Results)-1])
}

// returnMentionsAnyName reports whether any of the given names appears in the
// return's expressions (direct propagation or wrapping like fmt.Errorf).
func returnMentionsAnyName(ret *ast.ReturnStmt, names map[string]bool) bool {
	for _, expr := range ret.Results {
		if exprMentionsAnyName(expr, names) {
			return true
		}
	}
	return false
}

// exprMentionsAnyName reports whether the expression references any of the
// given identifier names.
func exprMentionsAnyName(expr ast.Expr, names map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && names[ident.Name] {
			found = true
			return false
		}
		return true
	})
	return found
}
