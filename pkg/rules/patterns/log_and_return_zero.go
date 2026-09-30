package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewLogAndReturnZeroRule())
}

// LogAndReturnZeroRule detects functions without an error result that log at
// Error/Warn level and immediately return a zero value:
//
//	func (m *TokenManager) getJWTIssuer() string {
//	    if m.config == nil {
//	        m.logger.Error("Configuration not available")
//	        return "" // empty issuer breaks validation much later
//	    }
//	    ...
//	}
//
// The log acknowledges a failure, but the caller receives a sentinel ("" / 0
// / nil) indistinguishable from a valid value. CLAUDE.md: a function that can
// fail must return (T, error).
//
// Not flagged: Info/Debug logs, `return false` (see
// error-masked-as-false-bool), computed recovery values, and HTTP handlers
// (they report the failure via ResponseWriter).
type LogAndReturnZeroRule struct {
	*rules.BaseRule
}

// NewLogAndReturnZeroRule creates the rule
func NewLogAndReturnZeroRule() *LogAndReturnZeroRule {
	return &LogAndReturnZeroRule{
		BaseRule: rules.NewBaseRule(
			"log-and-return-zero",
			"patterns",
			"Detects Error/Warn log followed by a zero-value return in functions without an error result",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks Go functions for the log-then-zero pattern
func (r *LogAndReturnZeroRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil || hasResponseWriterParam(fn.Type.Params) {
			return true
		}
		if fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
			if isCommandName(fn.Name.Name) {
				violations = append(violations, r.checkSwallowedWrites(ctx, fn.Body)...)
			}
			return true
		}
		if !hasNonErrorResults(fn.Type.Results) {
			return true
		}

		forEachOwnStatementList(fn.Body, func(list []ast.Stmt) {
			for i := 0; i+1 < len(list); i++ {
				if !isErrorOrWarnLogStmt(list[i]) {
					continue
				}
				ret, ok := list[i+1].(*ast.ReturnStmt)
				if !ok || !allResultsAreZeroValues(ret) {
					continue
				}
				pos := ctx.PositionFor(ret)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Error/Warn log followed by a zero-value return — the caller cannot distinguish this failure from a valid value")
				v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
				v.WithSuggestion("Change the signature to (T, error) and return an explicit error instead of the zero sentinel")
				violations = append(violations, v)
			}
		})

		return true
	})

	return violations
}

// hasNonErrorResults reports whether the function returns at least one value
// and none of the results is the builtin error type.
func hasNonErrorResults(results *ast.FieldList) bool {
	if results == nil || len(results.List) == 0 {
		return false
	}
	for _, field := range results.List {
		if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "error" {
			return false
		}
	}
	return true
}

// hasResponseWriterParam reports whether any parameter is an
// http.ResponseWriter — such functions report failures via the response.
func hasResponseWriterParam(params *ast.FieldList) bool {
	if params == nil {
		return false
	}
	for _, field := range params.List {
		if sel, ok := field.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "ResponseWriter" {
			return true
		}
	}
	return false
}

// forEachOwnStatementList visits every statement list (blocks, case bodies)
// of the function body, pruning nested function literals.
func forEachOwnStatementList(body *ast.BlockStmt, visit func([]ast.Stmt)) {
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

// isErrorOrWarnLogStmt reports whether the statement is a bare Error/Warn
// logger call, or an unleveled print (log.Printf, fmt.Printf) whose message
// says it reports an error.
func isErrorOrWarnLogStmt(stmt ast.Stmt) bool {
	exprStmt, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	return ok && isErrorReport(call)
}

// isErrorReport reports an Error/Warn log call or a print of an error.
func isErrorReport(call *ast.CallExpr) bool {
	return isErrorLevelLogCall(call) || isPrintedError(call)
}

// errorMessageWords mark the text of an unleveled print as an error report.
var errorMessageWords = []string{"error", "fail", "critical", "fatal", "cannot", "unable", "ошибк", "не удалось", "❌"}

// isPrintedError reports log.Print*, fmt.Print* or fmt.Fprint*(os.Stderr)
// whose message literal names an error.
func isPrintedError(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(sel.Sel.Name, "Print") && !strings.HasPrefix(sel.Sel.Name, "Fprint") {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || (pkg.Name != "log" && pkg.Name != "fmt") {
		return false
	}
	args := call.Args
	if strings.HasPrefix(sel.Sel.Name, "Fprint") {
		if !helpers.IsStderrPrint(sel, call) {
			return false
		}
		args = args[1:]
	}
	for _, arg := range args {
		lit, ok := ast.Unparen(arg).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		text := strings.ToLower(lit.Value)
		for _, word := range errorMessageWords {
			if strings.Contains(text, word) {
				return true
			}
		}
	}
	return false
}

// commandVerbs start the names of functions that carry out a business
// action. Their caller takes the action as done; a helper that records an
// audit entry, a metric or a history row after the action is not one of them.
var commandVerbs = []string{"Create", "Insert", "Update", "Delete", "Remove", "Save", "Upsert", "Store", "Persist",
	"Process", "Apply", "Complete", "Commit", "Settle", "Credit", "Debit", "Transfer", "Withdraw", "Deposit"}

// isCommandName reports a function named by a command verb.
func isCommandName(name string) bool {
	for _, verb := range commandVerbs {
		if helpers.HasLeadingWord(name, verb) {
			return true
		}
	}
	return false
}

// writeVerbs start the names of calls that change stored state.

// checkSwallowedWrites reports, in a command function without results, a
// write whose error is logged and dropped as the function ends: the caller has no result
// to check and goes on as if the state had changed. A branch that goes on
// with a loop (continue) is left out: the loop decides.
func (r *LogAndReturnZeroRule) checkSwallowedWrites(ctx *core.FileContext, body *ast.BlockStmt) []*core.Violation {
	var violations []*core.Violation
	report := func(ifStmt *ast.IfStmt, call *ast.CallExpr, rest []ast.Stmt) {
		if !isWriteCall(call) || !branchLogsAndEnds(ifStmt.Body, rest) {
			return
		}
		pos := ctx.PositionFor(ifStmt)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"A failed write is logged and dropped in a function without an error result - the caller goes on as if it had succeeded")
		v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
		v.WithSuggestion("Return the error and let the caller stop, or make the write part of the caller's transaction")
		violations = append(violations, v)
	}
	forEachOwnStatementList(body, func(list []ast.Stmt) {
		for i, stmt := range list {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				continue
			}
			errName := errNilCheckName(ifStmt.Cond)
			if errName == "" {
				continue
			}
			if call := errorSourceCall(nil, nil, ifStmt, list[:i], errName); call != nil {
				report(ifStmt, call, list[i+1:])
			}
		}
	})
	return violations
}

// isWriteCall reports a method call whose name starts with a write verb.
func isWriteCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return helpers.IsWriteName(sel.Sel.Name)
}

// branchLogsAndEnds reports an error branch that logs the error, hands it to
// nothing else, and ends the function: it returns, or nothing but logging
// follows the if.
func branchLogsAndEnds(body *ast.BlockStmt, rest []ast.Stmt) bool {
	logs := false
	for _, stmt := range body.List {
		switch s := stmt.(type) {
		case *ast.ExprStmt:
			call, ok := s.X.(*ast.CallExpr)
			if !ok || !isErrorReport(call) {
				return false
			}
			logs = true
		case *ast.ReturnStmt:
		default:
			return false
		}
	}
	if !logs {
		return false
	}
	if last := body.List[len(body.List)-1]; isReturnStmt(last) {
		return true
	}
	for _, stmt := range rest {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return false
		}
		if call, ok := exprStmt.X.(*ast.CallExpr); !ok || !helpers.IsLoggerCall(call) {
			return false
		}
	}
	return true
}

func isReturnStmt(stmt ast.Stmt) bool {
	_, ok := stmt.(*ast.ReturnStmt)
	return ok
}

// allResultsAreZeroValues reports whether every returned expression is a zero
// sentinel: "", 0, nil, or an empty composite literal. A lone `false` is left
// to the error-masked-as-false-bool rule.
func allResultsAreZeroValues(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false
	}
	for _, expr := range ret.Results {
		if !isZeroValueExpr(expr) {
			return false
		}
	}
	return true
}

// isZeroValueExpr matches "", 0, 0.0, nil and empty composite literals.
func isZeroValueExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Value == `""` || e.Value == "0" || e.Value == "0.0" || e.Value == "``"
	case *ast.Ident:
		return e.Name == "nil"
	case *ast.CompositeLit:
		return len(e.Elts) == 0
	}
	return false
}
