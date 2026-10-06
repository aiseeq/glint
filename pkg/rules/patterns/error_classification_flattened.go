package patterns

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorClassificationFlattenedRule())
}

// ErrorClassificationFlattenedRule detects a function that tells the kinds
// of a failure apart and returns each as fresh text:
//
//	if err != nil {
//		if errors.As(err, &notFound) {
//			return fmt.Errorf("item not found")
//		}
//		return fmt.Errorf("failed to load item")
//	}
//
// The function knows a missing item from a failed read, yet its callers get
// two plain errors that differ only in text. They answer every error alike:
// an access check answered with a 403 refuses the operator when the database
// is down, and a not-found page shows for an outage. Return a sentinel or a
// typed error for the classified case (ErrNotFound) and wrap the cause of the
// other one with %w.
type ErrorClassificationFlattenedRule struct {
	*rules.BaseRule
}

// NewErrorClassificationFlattenedRule creates the rule
func NewErrorClassificationFlattenedRule() *ErrorClassificationFlattenedRule {
	return &ErrorClassificationFlattenedRule{BaseRule: rules.NewBaseRule(
		"error-classification-flattened",
		"patterns",
		"Detects a function that tells the kinds of an error apart (errors.Is/As) and returns each as a fresh text error — its callers can tell them apart only by the text and answer every error alike",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the classified fresh-text returns of a file's
// functions returning an error.
func (r *ErrorClassificationFlattenedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !returnsErrorLast(fn) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			outer, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			errName, isCheck := errNotNilName(outer.Cond)
			if !isCheck {
				return true
			}
			ret := flattenedClassification(outer.Body, errName)
			if ret == nil {
				return true
			}
			line := ctx.LineFor(ret)
			if ctx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(ctx.RelPath, line, "The error is told apart here, but this case and the rest both return fresh text — callers can tell them apart only by the message and answer every error alike")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Return a sentinel or a typed error for the classified case (ErrNotFound) and wrap the cause of the rest with %w, so callers can use errors.Is")
			violations = append(violations, v)
			return true
		})
	}
	return violations
}

// returnsErrorLast reports a function whose last result is an error.
func returnsErrorLast(fn *ast.FuncDecl) bool {
	results := fn.Type.Results
	if results == nil || len(results.List) == 0 {
		return false
	}
	return isIdentNamed(results.List[len(results.List)-1].Type, "error")
}

// flattenedClassification returns the fresh-text return of a classified case
// in an error branch whose other outcome is fresh text too: an if on
// errors.Is/As ending in such a return, and a later return of fresh text in
// the branch.
func flattenedClassification(body *ast.BlockStmt, errName string) *ast.ReturnStmt {
	for i, stmt := range body.List {
		inner, ok := stmt.(*ast.IfStmt)
		if !ok || inner.Else != nil || !classifiesErrorPart(inner.Cond, errName) || len(inner.Body.List) == 0 {
			continue
		}
		classified, ok := inner.Body.List[len(inner.Body.List)-1].(*ast.ReturnStmt)
		if !ok || !returnsFreshText(classified) {
			continue
		}
		for _, later := range body.List[i+1:] {
			if ret, ok := later.(*ast.ReturnStmt); ok && returnsFreshText(ret) {
				return classified
			}
		}
	}
	return nil
}

// classifiesErrorPart reports a condition that classifies the error, alone
// or as one operand of &&: errors.As(err, &coded) && coded.Code == "x".
func classifiesErrorPart(cond ast.Expr, errName string) bool {
	if and, ok := ast.Unparen(cond).(*ast.BinaryExpr); ok && and.Op == token.LAND {
		return classifiesErrorPart(and.X, errName) || classifiesErrorPart(and.Y, errName)
	}
	return classifiesError(cond, errName)
}

// returnsFreshText reports a return whose error is a new text error that
// carries no cause: errors.New("...") or fmt.Errorf without %w.
func returnsFreshText(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false
	}
	call, ok := ast.Unparen(ret.Results[len(ret.Results)-1]).(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	switch {
	case isSelectorCall(call, "errors", "New"):
		return true
	case isSelectorCall(call, "fmt", "Errorf"):
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return false
		}
		format, err := strconv.Unquote(lit.Value)
		return err == nil && !strings.Contains(format, "%w")
	}
	return false
}
