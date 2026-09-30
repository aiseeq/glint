package deadcode

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewNilReturnStubRule())
}

// NilReturnStubRule detects methods that answer without doing the work they
// are named for. These are typically interface compliance stubs, or
// placeholders left in when the real call was not ready:
//
//	func (s *Service) GetData() (*Data, error) {
//	    return nil, nil
//	}
//
//	func (r *Repo) CountUsers() (int64, error) {
//	    // Simplified for the MVP: no users yet
//	    return 0, nil
//	}
//
//	func (a *Adapter) UpdateStatus(id, status string) error {
//	    return nil // the write is lost
//	}
//
//	return nil // m.cfg.Strategies()
//
// A body that answers with fixed values and whose comment calls it a stub; a
// write method whose whole body is return nil (a null object, named Nop, Noop,
// Null, Fake, Mock, Stub or Dummy, is one on purpose); a zero value returned
// beside the real call left in a comment; a handler answering with a success
// its own text calls a stub.
type NilReturnStubRule struct {
	*rules.BaseRule
	compliancePatterns []string
}

// NewNilReturnStubRule creates the rule
func NewNilReturnStubRule() *NilReturnStubRule {
	return &NilReturnStubRule{
		BaseRule: rules.NewBaseRule(
			"nil-return-stub",
			"deadcode",
			"Detects methods that only return nil without functionality (interface compliance stubs)",
			core.SeverityLow,
		),
		compliancePatterns: []string{
			"interface compliance",
			"compliance wrapper",
			"stub",
			"placeholder",
			"not implemented",
			"todo: implement",
			"fixme: implement",
			"temporary",
			"simplified",
			"mvp",
			"for compatibility",
			"development stage",
			"заглушк",
			"не реализ",
			"упрощен",
			"упрощён",
			"временн",
			"для совместимости",
			"development стадия",
		},
	}
}

// AnalyzeFile checks for nil-return stub methods in Go files
func (r *NilReturnStubRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Only check methods (functions with receivers)
		if fn.Recv == nil || len(fn.Recv.List) == 0 {
			return true
		}

		if v := r.checkForNilStub(ctx, fn); v != nil {
			violations = append(violations, v)
			return true
		}
		if v := r.checkForStubBody(ctx, fn); v != nil {
			violations = append(violations, v)
		}
		violations = append(violations, r.checkCommentedOutCalls(ctx, fn)...)
		violations = append(violations, r.checkStubResponses(ctx, fn)...)

		return true
	})

	return violations
}

// nullObjectWords name a type whose methods do nothing on purpose.
var nullObjectWords = []string{"nop", "noop", "null", "fake", "mock", "stub", "dummy", "discard", "empty"}

// checkForStubBody reports a body that answers with fixed values: when a
// comment in it or on it calls it a stub, or when a write method returns only
// nil. Blank assignments (_ = id) that silence unused parameters do not count
// as work.
func (r *NilReturnStubRule) checkForStubBody(ctx *core.FileContext, fn *ast.FuncDecl) *core.Violation {
	var ret *ast.ReturnStmt
	for _, stmt := range fn.Body.List {
		if isBlankAssign(stmt) {
			continue
		}
		if ret != nil {
			return nil
		}
		var ok bool
		if ret, ok = stmt.(*ast.ReturnStmt); !ok {
			return nil
		}
	}
	if ret == nil || len(ret.Results) == 0 {
		return nil
	}
	for _, result := range ret.Results {
		if !isStubValue(result) {
			return nil
		}
	}
	funcName := receiverTypeName(fn.Recv.List[0]) + "." + fn.Name.Name
	if r.hasComplianceComment(fn) || r.bodyCommentSaysStub(ctx, fn) {
		line := ctx.PositionFor(ret).Line
		v := r.CreateViolation(ctx.RelPath, line,
			"Method '"+funcName+"' answers with fixed values and its comment calls it a stub")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Implement the method, or return an error that says it is not available")
		return v
	}
	if len(ret.Results) == 1 && r.isNilExpr(ret.Results[0]) && helpers.IsWriteName(fn.Name.Name) &&
		fn.Type.Params != nil && fn.Type.Params.NumFields() > 0 && !isNullObject(receiverTypeName(fn.Recv.List[0])) {
		line := ctx.PositionFor(fn.Name).Line
		v := r.CreateViolation(ctx.RelPath, line,
			"Write method '"+funcName+"' only returns nil - the write is lost and the caller is told it succeeded")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Implement the write, or return an error that says it is not available")
		return v
	}
	return nil
}

// isBlankAssign reports _ = x.
func isBlankAssign(stmt ast.Stmt) bool {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN {
		return false
	}
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); !ok || ident.Name != "_" {
			return false
		}
	}
	return true
}

// isNullObject reports a type named as one that does nothing on purpose.
func isNullObject(typeName string) bool {
	lower := strings.ToLower(typeName)
	for _, word := range nullObjectWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// isStubValue reports a fixed value a stub answers with. A lone non-zero
// literal is a constant answer (a provider name, a version), not a stub.
func isStubValue(expr ast.Expr) bool {
	if lit, ok := ast.Unparen(expr).(*ast.BasicLit); ok {
		return lit.Value == "0" || lit.Value == `""` || lit.Value == "``" || lit.Value == "0.0"
	}
	return isFixedValue(expr)
}

// isFixedValue reports a value that does not depend on anything: nil, a
// literal, true or false, a package-level zero (decimal.Zero), an address of
// or a composite literal made of fixed values.
func isFixedValue(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return e.Name == "nil" || e.Name == "true" || e.Name == "false"
	case *ast.SelectorExpr:
		pkg, ok := e.X.(*ast.Ident)
		return ok && pkg.Obj == nil && strings.HasPrefix(e.Sel.Name, "Zero")
	case *ast.UnaryExpr:
		return (e.Op == token.AND || e.Op == token.SUB) && isFixedValue(e.X)
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				elt = kv.Value
			}
			if !isFixedValue(elt) {
				return false
			}
		}
		return true
	}
	return false
}

// bodyCommentSaysStub reports a comment inside the body that calls it a stub.
func (r *NilReturnStubRule) bodyCommentSaysStub(ctx *core.FileContext, fn *ast.FuncDecl) bool {
	for _, group := range ctx.GoAST.Comments {
		if group.Pos() < fn.Body.Lbrace || group.End() > fn.Body.Rbrace {
			continue
		}
		if r.saysStub(group.Text()) {
			return true
		}
	}
	return false
}

func (r *NilReturnStubRule) saysStub(text string) bool {
	lower := strings.ToLower(text)
	for _, pattern := range r.compliancePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// checkCommentedOutCalls reports a return of fixed values whose line comment
// is the call it replaced: return nil // m.cfg.Strategies().
func (r *NilReturnStubRule) checkCommentedOutCalls(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		for _, result := range ret.Results {
			if !isFixedValue(result) {
				return true
			}
		}
		line := ctx.PositionFor(ret).Line
		for _, group := range ctx.GoAST.Comments {
			if ctx.PositionFor(group).Line != line || group.Pos() < ret.End() {
				continue
			}
			// A comment that does not parse as an expression is prose.
			if expr, err := parser.ParseExpr(strings.TrimSpace(group.Text())); err == nil && isCallExpr(expr) {
				v := r.CreateViolation(ctx.RelPath, line,
					"Fixed value returned in place of the call left in the comment")
				v.WithCode(ctx.GetLine(line))
				v.WithSuggestion("Restore the call, or return an error that says it is not available")
				violations = append(violations, v)
			}
		}
		return true
	})
	return violations
}

func isCallExpr(expr ast.Expr) bool {
	_, ok := expr.(*ast.CallExpr)
	return ok
}

// checkStubResponses reports a success response whose own text calls it a stub.
func (r *NilReturnStubRule) checkStubResponses(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if !strings.Contains(strings.ToLower(name), "success") {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if ok && lit.Kind == token.STRING && r.saysStub(lit.Value) {
				line := ctx.PositionFor(call).Line
				v := r.CreateViolation(ctx.RelPath, line, "Success response that its own text calls a stub")
				v.WithCode(ctx.GetLine(line))
				v.WithSuggestion("Implement the handler, or answer 501 Not Implemented")
				violations = append(violations, v)
				break
			}
		}
		return true
	})
	return violations
}

// checkForNilStub checks if a method is a nil-returning stub
func (r *NilReturnStubRule) checkForNilStub(ctx *core.FileContext, fn *ast.FuncDecl) *core.Violation {
	// Must have exactly one statement (the return)
	if len(fn.Body.List) != 1 {
		return nil
	}

	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok {
		return nil
	}

	// Check if all return values are nil
	if !r.isAllNilReturn(ret) {
		return nil
	}

	// Check if there's a compliance-related comment
	hasComplianceComment := r.hasComplianceComment(fn)

	// Only report if it looks like a compliance stub (has comment or returns multiple nils)
	if !hasComplianceComment && len(ret.Results) < 2 {
		return nil
	}

	pos := ctx.PositionFor(fn.Name)
	funcName := receiverTypeName(fn.Recv.List[0]) + "." + fn.Name.Name

	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"Method '"+funcName+"' only returns nil - likely an interface compliance stub")
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Either implement the method or remove it from the interface")
	return v
}

// isAllNilReturn checks if all return values are nil
func (r *NilReturnStubRule) isAllNilReturn(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false // Empty return is not a nil stub
	}

	for _, result := range ret.Results {
		if !r.isNilExpr(result) {
			return false
		}
	}
	return true
}

// isNilExpr checks if an expression is nil
func (r *NilReturnStubRule) isNilExpr(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}

// hasComplianceComment checks if the function has interface compliance related comments
func (r *NilReturnStubRule) hasComplianceComment(fn *ast.FuncDecl) bool {
	if fn.Doc == nil {
		return false
	}

	for _, comment := range fn.Doc.List {
		commentLower := strings.ToLower(comment.Text)
		for _, pattern := range r.compliancePatterns {
			if strings.Contains(commentLower, pattern) {
				return true
			}
		}
	}
	return false
}
