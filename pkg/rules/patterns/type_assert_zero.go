package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTypeAssertMismatchReturnsZeroRule())
}

// TypeAssertMismatchReturnsZeroRule detects a function that asserts a value
// to an interface or a type parameter and, when the assertion fails, returns
// the zero value of that type as its only result:
//
//	func safeCast[T any](value any) T {
//		if result, ok := value.(T); ok {
//			return result
//		}
//		var zero T
//		return zero
//	}
//
// The comma-ok form looks careful, but the mismatch - a service missing one
// method of the interface it is cast to - turns into a nil interface the
// caller cannot tell from a real value, and the program fails later, at the
// first call, far from the cause. Return an error or a bool with the value,
// or panic where a mismatch is a programming error.
type TypeAssertMismatchReturnsZeroRule struct {
	*rules.BaseRule
}

// NewTypeAssertMismatchReturnsZeroRule creates the rule
func NewTypeAssertMismatchReturnsZeroRule() *TypeAssertMismatchReturnsZeroRule {
	return &TypeAssertMismatchReturnsZeroRule{BaseRule: rules.NewBaseRule(
		"type-assert-mismatch-returns-zero",
		"patterns",
		"Detects a failed assertion to an interface or type parameter answered with the zero value as the only result — the mismatch becomes a nil the caller cannot see",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: whether the asserted type is an interface needs types.
func (r *TypeAssertMismatchReturnsZeroRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *TypeAssertMismatchReturnsZeroRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the zero returns that answer a failed assertion.
func (r *TypeAssertMismatchReturnsZeroRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, ret := range assertMismatchZeroReturns(fn, info) {
				line := file.LineFor(ret)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, "Failed type assertion answered with the zero value — a value of the wrong type becomes a nil the caller cannot tell from a real one")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Return an error (or a bool) with the value, or panic if a mismatch is a programming error")
				violations = append(violations, v)
			}
		}
		return violations
	})
}

// assertMismatchZeroReturns returns the returns of a single-result function
// that answer a failed comma-ok assertion to the result's own interface or
// type parameter with its zero value.
func assertMismatchZeroReturns(fn *ast.FuncDecl, info *types.Info) []*ast.ReturnStmt {
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return nil
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Results().Len() != 1 {
		return nil
	}
	result := sig.Results().At(0).Type()
	if !types.IsInterface(result) {
		return nil
	}
	zeros := zeroLocals(fn.Body, info)
	// isZero reports a return of nil, *new(T) or a local declared without a
	// value and assigned nowhere but in the assertion's success branch.
	isZero := func(ret *ast.ReturnStmt, success *ast.BlockStmt) bool {
		if len(ret.Results) != 1 {
			return false
		}
		switch e := ast.Unparen(ret.Results[0]).(type) {
		case *ast.Ident:
			if e.Name == "nil" {
				return true
			}
			obj := info.Uses[e]
			return zeros[obj] && !assignedOutside(fn.Body, success, obj, info)
		case *ast.StarExpr:
			call, ok := e.X.(*ast.CallExpr)
			return ok && isIdentNamed(call.Fun, "new")
		}
		return false
	}
	matches := func(assign ast.Stmt) (string, bool) {
		okName, asserted := commaOkAssertion(assign)
		return okName, asserted != nil && types.Identical(info.TypeOf(asserted.Type), result)
	}

	var found []*ast.ReturnStmt
	forEachStmtList(fn.Body, func(stmts []ast.Stmt) {
		for i, stmt := range stmts {
			switch s := stmt.(type) {
			case *ast.IfStmt:
				// if v, ok := x.(T); ok { return v } - what follows is the failure.
				okName, hit := matches(s.Init)
				if !hit || s.Else != nil || !isIdentNamed(s.Cond, okName) {
					continue
				}
				if ret := firstReturnAfterDecls(stmts[i+1:]); ret != nil && isZero(ret, s.Body) {
					found = append(found, ret)
				}
			case *ast.AssignStmt:
				// v, ok := x.(T); if !ok { return zero }
				okName, hit := matches(s)
				if !hit {
					continue
				}
				for _, next := range stmts[i+1:] {
					check, ok := next.(*ast.IfStmt)
					if !ok || !negates(check.Cond, okName) || len(check.Body.List) == 0 {
						continue
					}
					if ret, ok := check.Body.List[len(check.Body.List)-1].(*ast.ReturnStmt); ok && isZero(ret, nil) {
						found = append(found, ret)
					}
					break
				}
			}
		}
	})
	return found
}

// commaOkAssertion returns the ok name and the assertion of v, ok := x.(T).
func commaOkAssertion(stmt ast.Stmt) (string, *ast.TypeAssertExpr) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return "", nil
	}
	asserted, ok := ast.Unparen(assign.Rhs[0]).(*ast.TypeAssertExpr)
	if !ok || asserted.Type == nil {
		return "", nil
	}
	okName, ok := assign.Lhs[1].(*ast.Ident)
	if !ok || okName.Name == "_" {
		return "", nil
	}
	return okName.Name, asserted
}

func negates(cond ast.Expr, name string) bool {
	unary, ok := ast.Unparen(cond).(*ast.UnaryExpr)
	return ok && unary.Op == token.NOT && isIdentNamed(unary.X, name)
}

// firstReturnAfterDecls returns the return that follows only declarations
// (var zero T).
func firstReturnAfterDecls(stmts []ast.Stmt) *ast.ReturnStmt {
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.DeclStmt:
			continue
		case *ast.ReturnStmt:
			return s
		}
		return nil
	}
	return nil
}

// zeroLocals returns the locals declared without a value (var zero T).
func zeroLocals(body *ast.BlockStmt, info *types.Info) map[types.Object]bool {
	zeros := make(map[types.Object]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		if spec, ok := n.(*ast.ValueSpec); ok && len(spec.Values) == 0 {
			for _, name := range spec.Names {
				if obj := info.Defs[name]; obj != nil {
					zeros[obj] = true
				}
			}
		}
		return true
	})
	return zeros
}

// assignedOutside reports an assignment to obj anywhere in body but the
// skipped block.
func assignedOutside(body, skip *ast.BlockStmt, obj types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || (skip != nil && n == skip) {
			return false
		}
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && info.Uses[id] == obj {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// forEachStmtList calls visit with every statement list of a body, outside
// function literals.
func forEachStmtList(body *ast.BlockStmt, visit func([]ast.Stmt)) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.BlockStmt:
			visit(node.List)
		case *ast.CaseClause:
			visit(node.Body)
		case *ast.CommClause:
			visit(node.Body)
		}
		return true
	})
}
