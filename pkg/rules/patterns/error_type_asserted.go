package patterns

import (
	"errors"
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorTypeAssertedRule())
}

// ErrorTypeAssertedRule detects an error tested by a type assertion or a type
// switch to an error type instead of errors.As:
//
//	apiErr, ok := err.(*APIError)
//	if ne, ok := err.(net.Error); ok && ne.Timeout() { ... }
//	switch e := err.(type) { case *APIError: ... }
//
// The assertion sees only the outermost error. As soon as anything between
// the source and the check wraps it (fmt.Errorf with %w, a context added by a
// caller), the assertion fails and the branch for that error - a back-off on
// a rate limit, a 404 for a missing row - silently stops running.
//
// Only the error type is checked: an assertion to an interface that is not
// an error (a behaviour such as Temporary() bool) is left alone, and so are
// the Is and As methods of an error type, which errors.Is and errors.As call
// on one link of the chain at a time.
type ErrorTypeAssertedRule struct {
	*rules.BaseRule
}

// NewErrorTypeAssertedRule creates the rule
func NewErrorTypeAssertedRule() *ErrorTypeAssertedRule {
	return &ErrorTypeAssertedRule{BaseRule: rules.NewBaseRule(
		"error-type-asserted",
		"patterns",
		"Detects an error checked by a type assertion or type switch to an error type instead of errors.As — a wrapped error never matches",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: whether the value is an error is a question of type.
func (r *ErrorTypeAssertedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ErrorTypeAssertedRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the assertions of errors to error types.
func (r *ErrorTypeAssertedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("error type asserted: nil Go project context")
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || (fn.Recv != nil && (fn.Name.Name == "Is" || fn.Name.Name == "As")) {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				var assertion *ast.TypeAssertExpr
				switch node := n.(type) {
				case *ast.TypeAssertExpr:
					if node.Type != nil && isErrorTypeExpr(info, node.Type) {
						assertion = node
					}
				case *ast.TypeSwitchStmt:
					if switched := typeSwitchAssert(node); switched != nil && switchesToErrorType(info, node) {
						assertion = switched
					}
				}
				if assertion == nil || !isErrorInterface(info.TypeOf(assertion.X)) {
					return true
				}
				line := file.LineFor(assertion)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line,
					"The error is tested by a type assertion — once anything wraps it (fmt.Errorf with %w) the assertion fails and this branch no longer runs")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Use errors.As(err, &target), which looks through the whole chain of wrapped errors")
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

// typeSwitchAssert returns the x.(type) of a type switch.
func typeSwitchAssert(stmt *ast.TypeSwitchStmt) *ast.TypeAssertExpr {
	var expr ast.Expr
	switch assign := stmt.Assign.(type) {
	case *ast.AssignStmt:
		if len(assign.Rhs) == 1 {
			expr = assign.Rhs[0]
		}
	case *ast.ExprStmt:
		expr = assign.X
	}
	assertion, _ := ast.Unparen(expr).(*ast.TypeAssertExpr)
	return assertion
}

// switchesToErrorType reports a type switch with a case of an error type.
func switchesToErrorType(info *types.Info, stmt *ast.TypeSwitchStmt) bool {
	for _, clause := range stmt.Body.List {
		caseClause, ok := clause.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, expr := range caseClause.List {
			if isErrorTypeExpr(info, expr) {
				return true
			}
		}
	}
	return false
}

// isErrorTypeExpr reports a type expression of a type implementing error,
// other than error itself.
func isErrorTypeExpr(info *types.Info, expr ast.Expr) bool {
	tv, ok := info.Types[expr]
	if !ok || !tv.IsType() || tv.Type == nil || isErrorInterface(tv.Type) {
		return false
	}
	return implementsError(tv.Type)
}

// isErrorInterface reports the predeclared error interface.
func isErrorInterface(t types.Type) bool {
	return t != nil && types.Identical(t, types.Universe.Lookup("error").Type())
}
