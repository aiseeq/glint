package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// idempotencyKeyName names an idempotency key, in a lookup's name or in its
// argument.
var idempotencyKeyName = regexp.MustCompile(`(?i)idempoten`)

// requestComparisonName names a helper that compares a stored record with
// the incoming request.
var requestComparisonName = regexp.MustCompile(`(?i)equal|match|same|compare|fingerprint|verify|validat|diff`)

// createCallName names a call that creates the record a replay stands in for.
var createCallName = regexp.MustCompile(`^(Create|Insert|Save|Add|Store|Put)`)

// replayGuards reports a repeat of an idempotency key answered with the
// stored record without comparing it with the incoming request:
//
//	stored, err := s.repo.GetByIdempotencyKey(ctx, order.IdempotencyKey)
//	if err != nil { ... }
//	*order = *stored
//	return true, nil
//
// The key promises the same answer to the same request; a different request
// that reuses the key (a client bug, a key derived from too few fields)
// silently gets the first request's result and its own is dropped. Compare a
// fingerprint of the request stored with the key, and refuse a mismatch.
func (r *IdempotencyCheckThenCreateRule) replayGuards(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation
	report := func(node ast.Node) {
		line := ctx.LineFor(node)
		if ctx.IsSuppressed(line, r.Name()) {
			return
		}
		v := r.CreateViolation(ctx.RelPath, line, "Idempotency key repeat answered with the stored record without comparing it with the incoming request — a different request reusing the key silently gets the first one's result")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Store a fingerprint of the request with the key and refuse a repeat whose fingerprint differs")
		violations = append(violations, v)
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List {
			if guard, ok := stmt.(*ast.IfStmt); ok && guard.Init != nil {
				if record, errName, ok := idempotencyLookup(guard.Init); ok && foundCondition(guard.Cond, record, errName) &&
					replaysWithoutComparing(fn, guard.Body.List, record) {
					report(guard)
				}
				continue
			}
			record, errName, ok := idempotencyLookup(stmt)
			if !ok || i+1 >= len(block.List) {
				continue
			}
			guard, ok := block.List[i+1].(*ast.IfStmt)
			if !ok || guard.Init != nil {
				continue
			}
			var found []ast.Stmt
			switch {
			case foundCondition(guard.Cond, record, errName):
				found = guard.Body.List
			case isComparisonWithNil(guard.Cond, errName, token.NEQ) && terminates(guard.Body):
				found = block.List[i+2:]
			}
			if replaysWithoutComparing(fn, found, record) {
				report(stmt)
			}
		}
		return true
	})
	return violations
}

// idempotencyLookup matches `record, err := x.Get...(key)` where the call or
// one of its arguments names an idempotency key.
func idempotencyLookup(stmt ast.Stmt) (record, errName string, ok bool) {
	assign, isAssign := stmt.(*ast.AssignStmt)
	if !isAssign || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return "", "", false
	}
	rec, recOK := assign.Lhs[0].(*ast.Ident)
	errIdent, errOK := assign.Lhs[1].(*ast.Ident)
	call, callOK := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !recOK || !errOK || !callOK || rec.Name == "_" || errIdent.Name == "_" {
		return "", "", false
	}
	named := idempotencyKeyName.MatchString(callName(call))
	for _, arg := range call.Args {
		switch a := ast.Unparen(arg).(type) {
		case *ast.Ident:
			named = named || idempotencyKeyName.MatchString(a.Name)
		case *ast.SelectorExpr:
			named = named || idempotencyKeyName.MatchString(a.Sel.Name)
		}
	}
	return rec.Name, errIdent.Name, named
}

// foundCondition matches `err == nil` and `record != nil`.
func foundCondition(cond ast.Expr, record, errName string) bool {
	return isComparisonWithNil(cond, errName, token.EQL) || isComparisonWithNil(cond, record, token.NEQ)
}

// isComparisonWithNil matches `name <op> nil`.
func isComparisonWithNil(cond ast.Expr, name string, op token.Token) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != op {
		return false
	}
	x, xOK := ast.Unparen(bin.X).(*ast.Ident)
	y, yOK := ast.Unparen(bin.Y).(*ast.Ident)
	return xOK && yOK && x.Name == name && y.Name == "nil"
}

// replaysWithoutComparing reports found-path statements that hand the
// stored record back as the answer (copy it into a pointer, or return it from
// a function that otherwise creates the record) before any comparison of the
// record with something other than nil.
func replaysWithoutComparing(fn *ast.FuncDecl, found []ast.Stmt, record string) bool {
	for _, stmt := range found {
		if comparesRecord(stmt, record) {
			return false
		}
		switch s := stmt.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) == 1 && len(s.Rhs) == 1 && isStar(s.Lhs[0]) && refersTo(s.Rhs[0], record) {
				return true
			}
		case *ast.ReturnStmt:
			for _, result := range s.Results {
				if refersTo(result, record) && createsAfter(fn, s.End()) {
					return true
				}
			}
			return false
		}
	}
	return false
}

// isStar matches *p.
func isStar(expr ast.Expr) bool {
	_, ok := ast.Unparen(expr).(*ast.StarExpr)
	return ok
}

// refersTo matches record and *record.
func refersTo(expr ast.Expr, record string) bool {
	expr = ast.Unparen(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = ast.Unparen(star.X)
	}
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == record
}

// comparesRecord reports a comparison inside stmt that mentions the record,
// other than with nil, or a comparison helper given the record.
func comparesRecord(stmt ast.Stmt, record string) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if (node.Op == token.EQL || node.Op == token.NEQ) && !isNilIdent(node.X) && !isNilIdent(node.Y) &&
				(mentions(node.X, record) || mentions(node.Y, record)) {
				found = true
			}
		case *ast.CallExpr:
			if requestComparisonName.MatchString(callName(node)) && mentions(node, record) {
				found = true
			}
		}
		return !found
	})
	return found
}

// createsAfter reports a create call in fn after pos.
func createsAfter(fn *ast.FuncDecl, pos token.Pos) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && call.Pos() > pos && createCallName.MatchString(callName(call)) {
			found = true
		}
		return !found
	})
	return found
}
