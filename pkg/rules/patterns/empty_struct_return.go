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
// Not flagged: an empty value under a nil or comma-ok guard when a function of
// the file returns that empty value as a regular answer outside such guards.
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

// guardedReturn is a return directly inside an error or nil check.
type guardedReturn struct {
	ret        *ast.ReturnStmt
	errorGuard bool
}

// guardedReturns lists the returns directly inside error and nil checks of
// the body — loops, switch and select cases included; a closure returns
// through its own signature.
func (r *EmptyStructReturnRule) guardedReturns(body *ast.BlockStmt) ([]guardedReturn, map[*ast.ReturnStmt]bool) {
	var guarded []guardedReturn
	inGuard := map[*ast.ReturnStmt]bool{}
	forEachOwnStatement(body, func(stmt ast.Stmt) {
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
	return guarded, inGuard
}

// AnalyzeFile checks for empty struct returns in error contexts
func (r *EmptyStructReturnRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	// The empty values the file's functions hand out as regular answers ("no
	// match", "nothing linked"): the meaning belongs to the type, so a sibling
	// function giving the same answer under a nil guard gives that answer too.
	regular := map[string]bool{}
	analyzeGoFunctions(ctx, func(funcDecl *ast.FuncDecl) []*core.Violation {
		if r.hasErrorReturn(funcDecl) {
			_, inGuard := r.guardedReturns(funcDecl.Body)
			for name := range r.regularEmptyAnswers(funcDecl.Body, inGuard) {
				regular[name] = true
			}
		}
		return nil
	})
	return analyzeGoFunctions(ctx, func(funcDecl *ast.FuncDecl) []*core.Violation {
		if !r.hasErrorReturn(funcDecl) {
			return nil
		}
		guarded, _ := r.guardedReturns(funcDecl.Body)

		var violations []*core.Violation
		if ret := cacheMissZeroAnswer(funcDecl.Body); ret != nil {
			line := ctx.LineFor(ret)
			v := r.CreateViolation(ctx.RelPath, line,
				"A cache that holds nothing is answered with a zero value and no error - the caller shows an empty result instead of \"not loaded yet\"")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Return an error (or a not-ready flag) when the cache has not been filled")
			violations = append(violations, v)
		}
		for _, g := range guarded {
			// Under a nil or comma-ok guard the empty value means "absent". When
			// the file hands out the same empty value as a regular answer
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
						ctx.RecordSuppression(r.Name(), pos.Line)
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

// cacheMissZeroAnswer returns the final return of a function that reads a
// cached value (data := s.cachedData), answers from it under len(data) > 0,
// and otherwise returns a literal of zero values with a nil error.
func cacheMissZeroAnswer(body *ast.BlockStmt) *ast.ReturnStmt {
	list := body.List
	if len(list) < 2 {
		return nil
	}
	ret, ok := list[len(list)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 2 || !isNilIdent(ret.Results[1]) || !isAllZeroLiteral(ret.Results[0]) {
		return nil
	}
	check, ok := list[len(list)-2].(*ast.IfStmt)
	if !ok || check.Else != nil {
		return nil
	}
	bin, ok := check.Cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.GTR || !isLenCall(bin.X) {
		return nil
	}
	cached, ok := lenArgument(bin.X).(*ast.Ident)
	if !ok {
		return nil
	}
	for _, stmt := range list[:len(list)-2] {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || !isIdentNamed(assign.Lhs[0], cached.Name) {
			continue
		}
		if sel, ok := assign.Rhs[0].(*ast.SelectorExpr); ok && strings.Contains(strings.ToLower(sel.Sel.Name), "cache") {
			return ret
		}
	}
	return nil
}

// isAllZeroLiteral reports a composite literal (or its address) whose fields
// are all zero values: 0, "", false, nil, an empty literal.
func isAllZeroLiteral(expr ast.Expr) bool {
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = unary.X
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, elt := range lit.Elts {
		value := elt
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			value = kv.Value
		}
		if !isZeroValueExpr(value) && !isIdentNamed(value, "false") {
			return false
		}
	}
	return true
}
