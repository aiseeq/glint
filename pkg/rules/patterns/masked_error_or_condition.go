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
//	    return Money{}, nil   // DB failure masked as valid zero value
//	}
//
// The caller cannot distinguish a storage failure from an honest zero.
// CLAUDE.md: "Fail explicitly, never degrade silently".
//
// Functions WITHOUT an error result are covered too, and there any return from
// such a branch masks the failure — the error cannot even be handed back:
//
//	func (s *S) dayYield(id string) Decimal {
//	    share, err := s.share(id)
//	    if err != nil || share.LessThanOrEqual(zero) {
//	        return s.cumulative        // DB failure silently yields "no growth"
//	    }
//
// In a loop the same branch ending in continue drops the failure with the
// item: `if err != nil || active > 0 { continue }` reports a failed check as
// "did not qualify". A branch that logs the error or hands it on keeps it on
// record and is left alone.
//
// Not flagged: branches that propagate/wrap the error, branches that handle
// the error in a nested if, branches that panic, &&-narrowing (errors.Is
// style), and branches without a return.
//
// For functions WITHOUT an error result the log IS the only error channel, so
// a branch that mentions the error variable anywhere (logs it, hands it to a
// collector) or calls an Error/Warn/Fatal-level logger is treated as handled.
// Functions taking http.ResponseWriter are skipped entirely: an HTTP handler
// reports failures through the response, not through return values. Functions
// WITH an error result get no such exemption — logging and then returning nil
// error still hides the failure from the caller.
type MaskedErrorOrConditionRule struct {
	*rules.BaseRule
}

// NewMaskedErrorOrConditionRule creates the rule
func NewMaskedErrorOrConditionRule() *MaskedErrorOrConditionRule {
	return &MaskedErrorOrConditionRule{
		BaseRule: rules.NewBaseRule(
			"masked-error-in-or-condition",
			"patterns",
			"Detects err != nil conflated with no-data via || in a branch that returns nil error or skips the item with continue",
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
		body, params, results := functionParts(n)
		if body == nil {
			return true
		}
		// Функция без error в результатах не «возвращает nil в error-слоте» —
		// там маскировкой является любой возврат значения из такой ветки.
		returnsError := lastResultIsErrorType(results)
		// Единственный bool-результат — зона error-masked-as-false-bool: там
		// false может честно означать «не подходит», и предикаты уже разобраны.
		if !returnsError && isSingleBoolResult(results) {
			return true
		}
		// HTTP-хендлер отчитывается об ошибке ответом клиенту, не возвратом.
		if !returnsError && hasResponseWriterParam(params) {
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
			violations = append(violations, r.checkBranch(ctx, body, ifStmt, errNames, returnsError)...)
		})

		return true
	})

	return violations
}

// checkBranch inspects the then-branch of an if whose ||-condition contains
// an err != nil operand, and reports returns that swallow the error.
func (r *MaskedErrorOrConditionRule) checkBranch(
	ctx *core.FileContext, body *ast.BlockStmt, ifStmt *ast.IfStmt, errNames map[string]bool, returnsError bool,
) []*core.Violation {
	handled := false
	// recorded: the branch logs the error or hands it on — a skipped item is
	// then on record, whatever the function returns.
	recorded := false
	var maskingReturns []*ast.ReturnStmt
	var skips []*ast.BranchStmt

	forEachOwnStatement(ifStmt.Body, func(stmt ast.Stmt) {
		switch s := stmt.(type) {
		case *ast.IfStmt:
			// A nested check on the error variable means the branch
			// distinguishes the failure case — not masking.
			if exprMentionsAnyName(s.Cond, errNames) {
				handled = true
			}
		case *ast.ExprStmt:
			// panic() aborts instead of returning a plausible value — explicit,
			// not masking.
			if call, ok := s.X.(*ast.CallExpr); ok {
				if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "panic" {
					handled = true
				}
			}
			// Для функции без error-результата лог — единственный канал ошибки:
			// ветка, которая передаёт err куда-то (логгеру, коллектору) или зовёт
			// Error/Warn/Fatal-логгер, ошибку обработала — это зона
			// log-and-return-zero, не маскировка. С error в сигнатуре лог не
			// оправдывает return nil — caller всё равно не отличит сбой от нуля.
			if exprMentionsAnyName(s.X, errNames) || isErrorLevelLogExpr(s.X) {
				recorded = true
				if !returnsError {
					handled = true
				}
			}
		case *ast.BranchStmt:
			// continue skips the item: the failure goes with it unless the
			// branch put it on record.
			if s.Tok == token.CONTINUE {
				skips = append(skips, s)
			}
		case *ast.ReturnStmt:
			if returnMentionsAnyName(s, errNames) {
				// The error is propagated or wrapped — not masking.
				handled = true
				return
			}
			// С error в сигнатуре маскировка — только явный nil в error-слоте.
			// Без error в сигнатуре деть ошибку некуда: маскирует любой возврат
			// ЗНАЧЕНИЯ. Голый `return` (void-функция, обработчик) — ранний выход
			// после обработки, а не подмена результата.
			if returnsError {
				if returnsNilError(s) {
					maskingReturns = append(maskingReturns, s)
				}
			} else if len(s.Results) > 0 {
				maskingReturns = append(maskingReturns, s)
			}
		}
	})

	if handled {
		return nil
	}

	var violations []*core.Violation
	if !recorded && !skipsUnparsed(body, ifStmt, errNames) {
		for _, skip := range skips {
			pos := ctx.PositionFor(skip)
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Branch guarded by 'err != nil || ...' skips the item with continue — a failure is dropped as if the item simply did not qualify")
			v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
			v.WithSuggestion("Split the condition: return or log the error when err != nil; keep the skip for the condition alone")
			violations = append(violations, v)
		}
	}

	message := "Branch guarded by 'err != nil || ...' returns nil error — a real failure is masked as a valid zero value"
	suggestion := "Split the condition: return the error when err != nil; keep the no-data case as a separate branch"
	if !returnsError {
		message = "Branch guarded by 'err != nil || ...' returns a value from a function without an error result — the failure is lost entirely"
		suggestion = "Give the function an (T, error) signature and return the error when err != nil; keep the no-data case as a separate branch"
	}

	for _, ret := range maskingReturns {
		pos := ctx.PositionFor(ret)
		v := r.CreateViolation(ctx.RelPath, pos.Line, message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
		v.WithSuggestion(suggestion)
		violations = append(violations, v)
	}
	return violations
}

// skipsUnparsed reports a skip whose error comes from a parse of the item:
// an item that does not parse is not one of those looked for, and skipping
// it is the filter itself.
func skipsUnparsed(body *ast.BlockStmt, ifStmt *ast.IfStmt, errNames map[string]bool) bool {
	for name := range errNames {
		if call := errSourceExpr(body, ifStmt, name); isParseCall(call) && !parsesRequestInput(body, call) {
			return true
		}
	}
	return false
}

// isErrorLevelLogExpr reports whether the expression is an Error/Warn/Fatal
// level logger call.
func isErrorLevelLogExpr(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	return ok && isErrorLevelLogCall(call)
}

// functionParts extracts body, params and results from FuncDecl/FuncLit nodes.
func functionParts(n ast.Node) (body *ast.BlockStmt, params, results *ast.FieldList) {
	switch fn := n.(type) {
	case *ast.FuncDecl:
		if fn.Type == nil {
			return nil, nil, nil
		}
		return fn.Body, fn.Type.Params, fn.Type.Results
	case *ast.FuncLit:
		if fn.Type == nil {
			return nil, nil, nil
		}
		return fn.Body, fn.Type.Params, fn.Type.Results
	}
	return nil, nil, nil
}

// hasResponseWriterParam (HTTP-хендлер отчитывается ответом, а не возвратом)
// объявлена в log_and_return_zero.go — второй копии здесь не нужно.

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

// isSingleBoolResult reports whether the function returns exactly one bool.
func isSingleBoolResult(results *ast.FieldList) bool {
	if results == nil || len(results.List) != 1 || len(results.List[0].Names) > 1 {
		return false
	}
	ident, ok := results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == "bool"
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
	if isErrorVarName(name) {
		return name, true
	}
	return "", false
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
