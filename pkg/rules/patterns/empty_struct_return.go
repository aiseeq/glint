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
// Not flagged: an empty value under a nil or comma-ok guard when the function
// also returns that empty value as a regular answer outside such guards.
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
		type guardedReturn struct {
			ret        *ast.ReturnStmt
			errorGuard bool
		}
		var guarded []guardedReturn
		inGuard := map[*ast.ReturnStmt]bool{}
		forEachOwnStatement(funcDecl.Body, func(stmt ast.Stmt) {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok || !r.isErrorOrNilCheck(ifStmt.Cond) {
				return
			}
			for _, bodyStmt := range ifStmt.Body.List {
				if ret, ok := bodyStmt.(*ast.ReturnStmt); ok {
					guarded = append(guarded, guardedReturn{ret: ret, errorGuard: r.isErrorValueCheck(ifStmt.Cond)})
					inGuard[ret] = true
				}
			}
		})
		regular := r.regularEmptyAnswers(funcDecl.Body, inGuard)

		var violations []*core.Violation
		for _, g := range guarded {
			// Under a nil or comma-ok guard the empty value means "absent". When
			// the function hands out the same empty value as a regular answer
			// elsewhere ("no match", "nothing linked"), absent is that answer
			// too; under an error check it never is.
			if !g.errorGuard && regular[r.emptyStructTypeName(g.ret)] {
				continue
			}
			if v := r.checkReturnForEmptyStructWithNilError(ctx, g.ret); v != nil {
				violations = append(violations, v)
			}
		}
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

// isErrorValueCheck reports whether the condition looks at an error variable
// (err != nil, parseErr != errNone), as opposed to a nil or comma-ok guard.
func (r *EmptyStructReturnRule) isErrorValueCheck(cond ast.Expr) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	for _, side := range []ast.Expr{bin.X, bin.Y} {
		if ident, ok := side.(*ast.Ident); ok && isErrorVarName(ident.Name) {
			return true
		}
	}
	return false
}

// regularEmptyAnswers collects the types the function returns empty with a nil
// error outside the guarded branches: at the end of the body, under a length
// check, after a loop — the value is one of its ordinary answers.
func (r *EmptyStructReturnRule) regularEmptyAnswers(body *ast.BlockStmt, inGuard map[*ast.ReturnStmt]bool) map[string]bool {
	regular := map[string]bool{}
	forEachOwnStatement(body, func(stmt ast.Stmt) {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok || inGuard[ret] {
			return
		}
		if name := r.emptyStructTypeName(ret); name != "" {
			regular[name] = true
		}
	})
	return regular
}

// emptyStructTypeName returns the type of the first empty composite literal
// of a return whose last value is nil, or "".
func (r *EmptyStructReturnRule) emptyStructTypeName(ret *ast.ReturnStmt) string {
	if len(ret.Results) < 2 || !isNilIdent(ret.Results[len(ret.Results)-1]) {
		return ""
	}
	for _, result := range ret.Results[:len(ret.Results)-1] {
		if lit, ok := result.(*ast.CompositeLit); ok && len(lit.Elts) == 0 {
			return r.extractTypeName(lit.Type)
		}
	}
	return ""
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
