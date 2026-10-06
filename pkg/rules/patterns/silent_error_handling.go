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
	rules.Register(NewSilentErrorHandlingRule())
}

// SilentErrorHandlingRule detects error checks that don't log or propagate the error
// This implements CLAUDE.md principle: "Log all errors, never ignore silently"
// Catches: if err != nil { return X } without logging or returning the error
type SilentErrorHandlingRule struct {
	*rules.BaseRule
}

// NewSilentErrorHandlingRule creates the rule
func NewSilentErrorHandlingRule() *SilentErrorHandlingRule {
	return &SilentErrorHandlingRule{
		BaseRule: rules.NewBaseRule(
			"silent-error-handling",
			"patterns",
			"Detects error checks that neither log nor propagate the error",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for silent error handling
func (r *SilentErrorHandlingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() {
		return nil
	}

	if ctx.IsTestFile() {
		return nil
	}

	// Build a set of if statements that are inside defer function literals
	ifStmtsInDefer := r.findIfStmtsInDefers(ctx.GoAST)

	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			name := ""
			if fn.Name != nil {
				name = fn.Name.Name
			}
			violations = append(violations, r.analyzeFuncBody(ctx, fn.Type, name, fn.Body, nil, ifStmtsInDefer)...)
			return false
		case *ast.FuncLit:
			// Функциональный литерал вне FuncDecl (var handler = func() {...}).
			violations = append(violations, r.analyzeFuncBody(ctx, fn.Type, "", fn.Body, nil, ifStmtsInDefer)...)
			return false
		}
		return true
	})

	return violations
}

// analyzeFuncBody проверяет `if err != nil` внутри тела одной функции. Вложенные
// замыкания разбираются рекурсивно со своей сигнатурой: исключения для
// (T, bool)-функций и bool-предикатов не наследуются от объемлющей функции.
func (r *SilentErrorHandlingRule) analyzeFuncBody(ctx *core.FileContext, ftype *ast.FuncType, name string, body *ast.BlockStmt, outerWriters map[string]bool, ifStmtsInDefer map[*ast.IfStmt]bool) []*core.Violation {
	if body == nil {
		return nil
	}

	funcReturnsValueBool := r.funcTypeReturnsValueBool(ftype)
	// A declared function answering with one bool: its branches that return
	// true/false are error-masking's (true) and error-masked-as-false-bool's
	// (false) — one branch is reported by one rule. Closures have no such
	// owner and stay here.
	boolAnswerFunc := name != "" && ftype != nil && isSingleBoolResult(ftype.Results)
	// The http.ResponseWriter parameters in scope: the function's own and the
	// ones a closure captures from the function around it.
	writers := responseWriterParamNames(ftype)
	for writer := range outerWriters {
		writers[writer] = true
	}

	var violations []*core.Violation
	ast.Inspect(body, func(n ast.Node) bool {
		// Тело замыкания живёт со своей сигнатурой — рекурсия вместо спуска.
		if lit, ok := n.(*ast.FuncLit); ok {
			violations = append(violations, r.analyzeFuncBody(ctx, lit.Type, "", lit.Body, writers, ifStmtsInDefer)...)
			return false
		}

		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}

		// Check if this is err != nil, alone or narrowed by a test that does
		// not look at the error: err != nil && optional { continue } takes
		// every failure of an optional source for its absence.
		if errNilCheckName(ifStmt.Cond) == "" && !narrowedErrCheck(ifStmt.Cond) {
			return true
		}

		// Skip error checks inside defer - they typically check named return values for cleanup
		if ifStmtsInDefer[ifStmt] {
			return true
		}

		// Check if the if body handles the error properly
		// For (T, bool) functions, returning false is acceptable error handling
		if !debugOnlyLostValue(body, ifStmt) && r.bodyHandlesError(ifStmt.Body, writers) {
			return true
		}

		pos := ctx.PositionFor(ifStmt)
		lineContent := ctx.GetLine(pos.Line)

		// Skip if has nolint
		if strings.Contains(lineContent, "nolint") {
			return true
		}

		// Skip if we're in a function returning (T, bool) and return includes false
		if funcReturnsValueBool && r.bodyReturnsFalse(ifStmt.Body) {
			return true
		}

		if boolAnswerFunc && r.bodyReturnsBool(ifStmt.Body) {
			return true
		}

		// Skip if body has comment indicating error is handled elsewhere
		// Common patterns: "error already sent", "error handled", "response sent"
		if r.bodyHasErrorHandledComment(ctx, ifStmt.Body) {
			return true
		}

		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Error check without logging or error propagation")
		v.WithCode(lineContent)
		v.WithSuggestion("Add logging or return the error to make failure visible")
		violations = append(violations, v)

		return true
	})

	return violations
}

// bodyHandlesError checks if the if body logs or propagates error
func (r *SilentErrorHandlingRule) bodyHandlesError(body *ast.BlockStmt, writers map[string]bool) bool {
	if body == nil {
		return false
	}

	for _, stmt := range body.List {
		if r.stmtHandlesError(stmt, writers) {
			return true
		}
	}

	return false
}

// funcTypeReturnsValueBool checks if function returns (T, bool) pattern
// Handles both (string, bool) and (value, exists bool) syntaxes
func (r *SilentErrorHandlingRule) funcTypeReturnsValueBool(ftype *ast.FuncType) bool {
	if ftype == nil || ftype.Results == nil {
		return false
	}

	results := ftype.Results.List

	// Count total return values (a field can have multiple names)
	totalReturns := 0
	for _, field := range results {
		if len(field.Names) == 0 {
			totalReturns++ // unnamed return value
		} else {
			totalReturns += len(field.Names) // named return values
		}
	}

	if totalReturns < 2 {
		return false
	}

	// Check if last return type is bool
	lastResult := results[len(results)-1]
	if ident, ok := lastResult.Type.(*ast.Ident); ok {
		return ident.Name == "bool"
	}

	return false
}

// bodyReturnsFalse checks if the body contains return with false
func (r *SilentErrorHandlingRule) bodyReturnsFalse(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}

	for _, stmt := range body.List {
		if retStmt, ok := stmt.(*ast.ReturnStmt); ok {
			for _, result := range retStmt.Results {
				if ident, ok := result.(*ast.Ident); ok {
					if ident.Name == "false" {
						return true
					}
				}
			}
		}
	}

	return false
}

// bodyReturnsBool checks if the body contains return with true or false
func (r *SilentErrorHandlingRule) bodyReturnsBool(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}

	for _, stmt := range body.List {
		if retStmt, ok := stmt.(*ast.ReturnStmt); ok {
			for _, result := range retStmt.Results {
				if ident, ok := result.(*ast.Ident); ok {
					if ident.Name == "true" || ident.Name == "false" {
						return true
					}
				}
			}
		}
	}

	return false
}

// bodyHasErrorHandledComment checks if the if body has a comment indicating error is handled elsewhere
func (r *SilentErrorHandlingRule) bodyHasErrorHandledComment(ctx *core.FileContext, body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}

	// Get line numbers covered by the body
	startLine := ctx.PositionFor(body).Line
	endLine := startLine + 5 // Check a few lines within the body

	// Patterns indicating error is handled elsewhere or intentionally acceptable
	handledPatterns := []string{
		// Error handled elsewhere
		"already sent", "already handled", "response sent", "error sent",
		"handled by", "logged by", "reported by", "error response",
		"already logged", "handled above", "handled in",
		// Intentionally acceptable error (optional operations)
		"allow empty", "optional", "permitted", "expected", "ok to fail",
		"non-critical", "best effort", "acceptable", "can fail",
		// Russian equivalents (Cyrillic)
		"разрешаем", "опционально", "допускается", "ожидаемо",
	}

	for lineNum := startLine; lineNum <= endLine && lineNum <= len(ctx.Lines); lineNum++ {
		lineLower := strings.ToLower(ctx.GetLine(lineNum))
		if !strings.Contains(lineLower, "//") {
			continue
		}

		for _, pattern := range handledPatterns {
			if strings.Contains(lineLower, pattern) {
				return true
			}
		}
	}

	return false
}

// stmtHandlesError checks if a statement handles error
func (r *SilentErrorHandlingRule) stmtHandlesError(stmt ast.Stmt, writers map[string]bool) bool {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		// Check if return includes error or uses error value
		for _, result := range s.Results {
			if r.exprReferencesError(result) {
				return true
			}
			// Also check if error is used in return value (e.g., struct with error in field)
			if r.exprUsesErrorValue(result) {
				return true
			}
			if r.exprReturnsUserVisibleError(result) {
				return true
			}
		}

	case *ast.ExprStmt:
		// Check for logging calls
		if call, ok := s.X.(*ast.CallExpr); ok {
			// A Debug or Trace line is off in production: the failure it
			// records is as silent as one never logged.
			if helpers.IsLoggerCall(call) {
				return true
			}
			if r.isResponseCall(call) || callWritesResponse(call, writers) {
				return true
			}
			if writesToStderr(call) {
				return true
			}
			// Check for panic
			if r.isPanicCall(call) {
				return true
			}
			// Handing the error to another function is not swallowing it: the
			// callee is what reports it. Project code routinely funnels a branch
			// into writePreflightFailure(msg, report, err) or
			// handleReconcileFailure(ctx, item, err) instead of logging inline.
			if callTakesErrorArgument(call) {
				return true
			}
		}

	case *ast.IfStmt:
		// Nested if might handle error
		if r.bodyHandlesError(s.Body, writers) {
			return true
		}

	case *ast.BlockStmt:
		for _, inner := range s.List {
			if r.stmtHandlesError(inner, writers) {
				return true
			}
		}

	case *ast.AssignStmt:
		// Check for error collection pattern: errors = append(errors, err)
		if r.isErrorCollectionAppend(s) {
			return true
		}
		// Check for explicit error acknowledgment: _ = err
		if r.isExplicitErrorAcknowledge(s) {
			return true
		}
		// Check for error usage in RHS (e.g., response["details"] = err.Error())
		if r.rhsUsesError(s) {
			return true
		}

	case *ast.SendStmt:
		return r.exprReferencesError(s.Value) || r.exprUsesErrorValue(s.Value)
	}

	return false
}

func (r *SilentErrorHandlingRule) exprReturnsUserVisibleError(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.UnaryExpr:
		return r.exprReturnsUserVisibleError(e.X)
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if ok && strings.EqualFold(key.Name, "error") {
				return true
			}
		}
	}
	return false
}

func (r *SilentErrorHandlingRule) isResponseCall(call *ast.CallExpr) bool {
	funcName := strings.ToLower(core.ExtractFullFunctionName(call))
	patterns := []string{
		"http.error", "writejson", "render", "redirect", "respond", "response", "senderror", "errorjson",
	}
	for _, pattern := range patterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}
	return false
}

// isErrorCollectionAppend checks if statement is appending error to a collection
// Pattern: errors = append(errors, err) or errs = append(errs, err)
func (r *SilentErrorHandlingRule) isErrorCollectionAppend(stmt *ast.AssignStmt) bool {
	// Must have RHS
	if len(stmt.Rhs) != 1 {
		return false
	}

	// Check RHS is append call
	call, ok := stmt.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}

	// Check it's append function
	fnIdent, ok := call.Fun.(*ast.Ident)
	if !ok || fnIdent.Name != "append" {
		return false
	}

	// Need at least 2 args: slice and element(s)
	if len(call.Args) < 2 {
		return false
	}

	// Check if first arg (slice) is named like an error collection
	sliceIdent, ok := call.Args[0].(*ast.Ident)
	if !ok {
		return false
	}
	sliceNameLower := strings.ToLower(sliceIdent.Name)
	isErrorSlice := sliceNameLower == "errors" || sliceNameLower == "errs" ||
		strings.HasSuffix(sliceNameLower, "errors") || strings.HasSuffix(sliceNameLower, "errs")

	if !isErrorSlice {
		return false
	}

	// Check if any appended element references error
	for i := 1; i < len(call.Args); i++ {
		if r.exprReferencesError(call.Args[i]) {
			return true
		}
	}

	return false
}

// isExplicitErrorAcknowledge checks if statement is an explicit error acknowledgment
// Pattern: _ = err (explicitly assigns error to blank identifier to silence linter)
func (r *SilentErrorHandlingRule) isExplicitErrorAcknowledge(stmt *ast.AssignStmt) bool {
	// Must be simple assignment (=)
	if stmt.Tok != token.ASSIGN {
		return false
	}

	// Must have exactly one LHS and one RHS
	if len(stmt.Lhs) != 1 || len(stmt.Rhs) != 1 {
		return false
	}

	// LHS must be blank identifier (_)
	lhsIdent, ok := stmt.Lhs[0].(*ast.Ident)
	if !ok || lhsIdent.Name != "_" {
		return false
	}

	// RHS must reference error variable
	return r.exprReferencesError(stmt.Rhs[0])
}

// rhsUsesError checks if any RHS expression uses an error (e.g., err.Error())
// Pattern: response["details"] = err.Error() or similar
func (r *SilentErrorHandlingRule) rhsUsesError(stmt *ast.AssignStmt) bool {
	for _, rhs := range stmt.Rhs {
		if r.exprUsesErrorValue(rhs) {
			return true
		}
	}
	return false
}

// exprUsesErrorValue checks if expression uses an error value (e.g., err.Error(), err.String())
func (r *SilentErrorHandlingRule) exprUsesErrorValue(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		// Check for err.Error() pattern
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			// Check if X is an error variable
			if ident, ok := sel.X.(*ast.Ident); ok && isErrorVarName(ident.Name) {
				return true
			}
			// Check for fmt.Errorf(..., err).Error() pattern
			// The X is a CallExpr (fmt.Errorf) and its args contain error
			if innerCall, ok := sel.X.(*ast.CallExpr); ok {
				for _, arg := range innerCall.Args {
					if r.exprReferencesError(arg) {
						return true
					}
				}
			}
		}
		// Also check function arguments for error references
		for _, arg := range e.Args {
			if r.exprUsesErrorValue(arg) {
				return true
			}
		}
	case *ast.SelectorExpr:
		// err.someField
		if ident, ok := e.X.(*ast.Ident); ok && isErrorVarName(ident.Name) {
			return true
		}
	case *ast.CompositeLit:
		// Check struct literals for error usage in field values
		// e.g., ValidationError{Message: fmt.Sprintf("...: %v", err)}
		for _, elt := range e.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if r.exprUsesErrorValue(kv.Value) {
					return true
				}
			} else if r.exprUsesErrorValue(elt) {
				return true
			}
		}
	case *ast.UnaryExpr:
		// Handle &struct{} pattern
		return r.exprUsesErrorValue(e.X)
	case *ast.BinaryExpr:
		return r.exprUsesErrorValue(e.X) || r.exprUsesErrorValue(e.Y)
	case *ast.Ident:
		// Direct error variable reference
		return isErrorVarName(e.Name)
	}
	return false
}

// exprReferencesError checks if expression references err variable or creates an error
func (r *SilentErrorHandlingRule) exprReferencesError(expr ast.Expr) bool {
	return exprCarriesError(expr)
}

// callCreatesError распознаёт вызовы, создающие ошибку: errors.New, fmt.Errorf
// и функции с суффиксом Error/Errorf (NewError, newValidationError, x.Errorf).
// Произвольные подстроки ("new", "fail") не считаются: NewClient() в ветке
// err != nil — это fallback-значение, а не создание ошибки.
func callCreatesError(call *ast.CallExpr) bool {
	funcName := core.ExtractFullFunctionName(call)
	if funcName == "errors.New" || funcName == "fmt.Errorf" {
		return true
	}

	base := funcName
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		base = base[idx+1:]
	}
	baseLower := strings.ToLower(base)
	return strings.HasSuffix(baseLower, "error") || strings.HasSuffix(baseLower, "errorf")
}

// isPanicCall checks if call is panic
func (r *SilentErrorHandlingRule) isPanicCall(call *ast.CallExpr) bool {
	if ident, ok := call.Fun.(*ast.Ident); ok {
		return ident.Name == "panic"
	}
	return false
}

// findIfStmtsInDefers finds all if statements that are inside defer function literals
func (r *SilentErrorHandlingRule) findIfStmtsInDefers(file *ast.File) map[*ast.IfStmt]bool {
	result := make(map[*ast.IfStmt]bool)

	ast.Inspect(file, func(n ast.Node) bool {
		deferStmt, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}

		// Check if defer has a function literal (defer func() { ... }())
		callExpr, ok := deferStmt.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}

		// Find all if statements in the function literal's body
		ast.Inspect(callExpr.Body, func(inner ast.Node) bool {
			if ifStmt, ok := inner.(*ast.IfStmt); ok {
				result[ifStmt] = true
			}
			return true
		})

		return true
	})

	return result
}

// callTakesErrorArgument reports whether the error value itself is one of the
// call's arguments — either the value, or its text via err.Error(). Only those
// shapes count, so a call that merely mentions "error" in its name does not
// silence the rule.
func callTakesErrorArgument(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if argumentIsError(arg) {
			return true
		}
	}
	return false
}

func argumentIsError(arg ast.Expr) bool {
	switch a := arg.(type) {
	case *ast.Ident:
		return isErrorVarName(a.Name)
	case *ast.SelectorExpr:
		// r.lastErr, or queryErr.message: a field of the error value is its text.
		if x, ok := a.X.(*ast.Ident); ok && isErrorVarName(x.Name) {
			return true
		}
		return isErrorVarName(a.Sel.Name)
	case *ast.BinaryExpr:
		// "invalid 'from': " + parseErr.Error() — the cause travels in the message.
		return argumentIsError(a.X) || argumentIsError(a.Y)
	case *ast.ParenExpr:
		return argumentIsError(a.X)
	case *ast.CallExpr:
		// err.Error() — the message travels even though the value does not.
		if sel, ok := a.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" {
			return argumentIsError(sel.X)
		}
		// fmt.Errorf("...: %w", err), errors.Join(err, ...) — the error travels
		// wrapped, as when an iterator hands it to the consumer through yield.
		return callTakesErrorArgument(a)
	}
	return false
}

// writesToStderr recognises a write to os.Stderr — fmt.Fprintln(os.Stderr, …):
// a command-line tool reports its failure to the operator there, next to the
// exit code it returns.
func writesToStderr(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		sel, ok := arg.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Stderr" {
			continue
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" {
			return true
		}
	}
	return false
}

// debugOnlyLostValue reports a branch holding only Debug or Trace lines for
// the error of a call that produced a value (data, err := fetch()): the
// function goes on without the data as if nothing failed, and the line is off
// in production. A failed Close or drain produces nothing to lose.
func debugOnlyLostValue(body *ast.BlockStmt, ifStmt *ast.IfStmt) bool {
	if !onlyDebugLogs(ifStmt.Body.List) {
		return false
	}
	errName := errNilCheckName(ifStmt.Cond)
	var source *ast.AssignStmt
	if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok {
		source = assign
	} else {
		ast.Inspect(body, func(n ast.Node) bool {
			if assign, ok := n.(*ast.AssignStmt); ok && assign.Pos() < ifStmt.Pos() && assignsName(assign, errName) {
				source = assign
			}
			return true
		})
	}
	if source == nil || len(source.Rhs) != 1 || !assignsName(source, errName) {
		return false
	}
	for _, lhs := range source.Lhs {
		if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" && id.Name != errName {
			return true
		}
	}
	return false
}

func onlyDebugLogs(list []ast.Stmt) bool {
	if len(list) == 0 {
		return false
	}
	for _, stmt := range list {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok || !helpers.IsLoggerCall(call) || !isDebugLogCall(call) {
			return false
		}
	}
	return true
}

// isDebugLogCall reports a log call at Debug or Trace level.
func isDebugLogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	verb := helpers.LogVerb(sel)
	return strings.HasPrefix(verb, "debug") || strings.HasPrefix(verb, "trace")
}

// narrowedErrCheck reports err != nil && cond where cond does not read the
// error: the branch fires for every error of the call, whatever its cause.
func narrowedErrCheck(cond ast.Expr) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.LAND {
		return false
	}
	name := errNilCheckName(ast.Unparen(bin.X))
	return name != "" && !mentions(bin.Y, name)
}
