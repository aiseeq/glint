package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorTextAsResultRule())
}

// ErrorTextAsResultRule detects an error branch that writes the error's text
// into the value it returns instead of returning the error:
//
//	if err != nil {
//		return &Result{Success: false, Message: fmt.Sprintf("failed: %v", err)}, nil
//	}
//
//	"toJSON": func(v any) string {
//		...
//		if err != nil {
//			return fmt.Sprintf("null /* JSON error: %v */", err)
//		}
//
// The caller receives a nil error, or the template no error at all, and
// goes on with a value that only looks like data: a config file with a
// comment where JSON should be, a simulation reported as done. Return the
// error; a template function can have one in its signature.
//
// A loop that appends each failure's text to a list field of the result
// (agg.Errors = append(agg.Errors, err.Error()); continue) and ends with
// return agg, nil folds the failures the same way.
//
// Judged are the functions of a template.FuncMap and the functions with an
// error result that return a result literal marked unsuccessful (a field set
// to false) next to a nil error. Elsewhere a value with the error's text is
// built to carry it (a validation result, a check's finding, a skip reason,
// a text for a message), which is the function's contract. Not reported
// either: String, Error and GoString, a value computed from the error
// (errors.Is), and test files.
type ErrorTextAsResultRule struct {
	*rules.BaseRule
}

// NewErrorTextAsResultRule creates the rule
func NewErrorTextAsResultRule() *ErrorTextAsResultRule {
	return &ErrorTextAsResultRule{BaseRule: rules.NewBaseRule(
		"error-text-as-result",
		"patterns",
		"Detects an error branch that returns the error's text inside a value with a nil error, or as a template function's output — the caller takes the failure for data",
		core.SeverityHigh,
	)}
}

// fixedStringMethods are the methods whose string result is their contract.
var fixedStringMethods = map[string]bool{"String": true, "Error": true, "GoString": true}

// AnalyzeFile reports the returns that fold an error into a value.
func (r *ErrorTextAsResultRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	templateFuncs := templateFuncTypes(ctx.GoAST)
	var violations []*core.Violation
	forEachFunction(ctx.GoAST, func(name string, ftype *ast.FuncType, body *ast.BlockStmt) {
		if fixedStringMethods[name] || ftype.Results == nil || len(ftype.Results.List) == 0 {
			return
		}
		returnsError := lastResultIsErrorType(ftype.Results)
		if !returnsError && !templateFuncs[ftype] {
			return
		}
		folded := returnedNilErrorHolders(body)
		forEachOwnStatement(body, func(stmt ast.Stmt) {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				return
			}
			errName := errNilCheckName(ifStmt.Cond)
			if errName == "" {
				return
			}
			if returnsError {
				if assign := foldedIntoResultList(ifStmt, errName, folded); assign != nil {
					line := ctx.LineFor(assign)
					if !ctx.IsSuppressed(line, r.Name()) {
						v := r.CreateViolation(ctx.RelPath, line, "The error's text is added to the result's list and the loop goes on — the function then returns the result with a nil error, and the caller takes the run as clean")
						v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
						v.WithSuggestion("Collect the errors and return errors.Join of them next to the partial result")
						violations = append(violations, v)
					}
				}
			}
			forEachOwnStatement(ifStmt.Body, func(inner ast.Stmt) {
				ret, ok := inner.(*ast.ReturnStmt)
				if !ok || !foldsErrorText(ret, errName, returnsError) {
					return
				}
				line := ctx.PositionFor(ret).Line
				if ctx.IsSuppressed(line, r.Name()) {
					return
				}
				v := r.CreateViolation(ctx.RelPath, line, "The error's text is returned inside a value with no error — the caller takes the failure for data and goes on")
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Return the error (wrap it with %w); give the function an error result if it has none")
				violations = append(violations, v)
			})
		})
	})
	return violations
}

// returnedNilErrorHolders returns the variables the function's last
// statement returns next to a nil error (return agg, nil).
func returnedNilErrorHolders(body *ast.BlockStmt) map[string]bool {
	holders := make(map[string]bool)
	if len(body.List) == 0 {
		return holders
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) < 2 || !isNilIdent(ret.Results[len(ret.Results)-1]) {
		return holders
	}
	for _, value := range ret.Results[:len(ret.Results)-1] {
		if id, ok := value.(*ast.Ident); ok {
			holders[id.Name] = true
		}
	}
	return holders
}

// foldedIntoResultList returns the assignment of an error branch that ends
// with continue and appends the error's text to a list field of a returned
// holder: agg.Errors = append(agg.Errors, err.Error()).
func foldedIntoResultList(ifStmt *ast.IfStmt, errName string, holders map[string]bool) *ast.AssignStmt {
	list := ifStmt.Body.List
	if len(holders) == 0 || len(list) < 2 {
		return nil
	}
	if branch, ok := list[len(list)-1].(*ast.BranchStmt); !ok || branch.Tok.String() != "continue" {
		return nil
	}
	for _, stmt := range list[:len(list)-1] {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		sel, ok := assign.Lhs[0].(*ast.SelectorExpr)
		if !ok {
			continue
		}
		holder, ok := sel.X.(*ast.Ident)
		if !ok || !holders[holder.Name] || !isAppendExprTo(assign.Rhs[0], holder.Name) || !namesFailures(sel.Sel.Name) {
			continue
		}
		if carriesErrorText(assign.Rhs[0], errName) && !errUsedBesides(list, assign, errName) {
			return assign
		}
	}
	return nil
}

// namesFailures reports a list field named for failures (Errors, Failures);
// a list of skip reasons is a report of what the input lacked.
func namesFailures(field string) bool {
	lower := strings.ToLower(field)
	return strings.Contains(lower, "err") || strings.Contains(lower, "fail")
}

// errUsedBesides reports a branch that hands the error to something other
// than the folded text and a logger: failed = append(failed, err).
func errUsedBesides(list []ast.Stmt, fold *ast.AssignStmt, errName string) bool {
	for _, stmt := range list {
		if stmt != ast.Stmt(fold) && readsIdentOutsideLoggers(stmt, errName) {
			return true
		}
	}
	return false
}

// templateFuncTypes returns the function literals of template.FuncMap
// literals: their result goes straight into the rendered output.
func templateFuncTypes(file *ast.File) map[*ast.FuncType]bool {
	found := map[*ast.FuncType]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || lit.Type == nil || !strings.HasSuffix(types.ExprString(lit.Type), "FuncMap") {
			return true
		}
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if fn, ok := kv.Value.(*ast.FuncLit); ok {
					found[fn.Type] = true
				}
			}
		}
		return true
	})
	return found
}

// foldsErrorText reports a return that carries the error's text (err.Error()
// or err formatted by fmt.Sprint*): a template function's output, or, with a
// nil error, a result literal marked unsuccessful.
func foldsErrorText(ret *ast.ReturnStmt, errName string, returnsError bool) bool {
	values := ret.Results
	if !returnsError {
		return len(values) == 1 && carriesErrorText(values[0], errName)
	}
	if len(values) < 2 || !isNilIdent(values[len(values)-1]) {
		return false
	}
	for _, value := range values[:len(values)-1] {
		if marksFailure(value) && carriesErrorText(value, errName) {
			return true
		}
	}
	return false
}

// marksFailure reports a result literal with a field set to false, such as
// Success: false: the value says the call failed while the error says it
// did not. A finding or a skip reason without such a mark is the function's
// answer, not a failure of its own.
func marksFailure(expr ast.Expr) bool {
	if unary, ok := expr.(*ast.UnaryExpr); ok {
		expr = unary.X
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok && isIdentNamed(kv.Value, "false") {
			return true
		}
	}
	return false
}

// carriesErrorText reports err.Error() or fmt.Sprint*(..., err, ...) inside expr.
func carriesErrorText(expr ast.Expr, errName string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "Error" && len(call.Args) == 0 && isIdentNamed(sel.X, errName) {
			found = true
			return false
		}
		if isIdentNamed(sel.X, "fmt") && strings.HasPrefix(sel.Sel.Name, "Sprint") {
			for _, arg := range call.Args {
				if isIdentNamed(arg, errName) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}
