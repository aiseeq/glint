package errrules

import (
	"go/ast"
	"go/token"
	"path"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
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

	// Build sets shared by the function-body checks.
	ifStmtsInDefer := r.findIfStmtsInDefers(ctx.GoAST)
	imports := standardImportAliases(ctx.GoAST)

	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			name := ""
			if fn.Name != nil {
				name = fn.Name.Name
			}
			violations = append(violations, r.analyzeFuncBody(ctx, fn.Type, name, fn.Body, nil, ifStmtsInDefer, imports)...)
			return false
		case *ast.FuncLit:
			// Функциональный литерал вне FuncDecl (var handler = func() {...}).
			violations = append(violations, r.analyzeFuncBody(ctx, fn.Type, "", fn.Body, nil, ifStmtsInDefer, imports)...)
			return false
		}
		return true
	})

	return violations
}

// analyzeFuncBody проверяет `if err != nil` внутри тела одной функции. Вложенные
// замыкания разбираются рекурсивно со своей сигнатурой: исключения для
// (T, bool)-функций и bool-предикатов не наследуются от объемлющей функции.
func (r *SilentErrorHandlingRule) analyzeFuncBody(ctx *core.FileContext, ftype *ast.FuncType, name string, body *ast.BlockStmt, outerWriters map[string]bool, ifStmtsInDefer map[*ast.IfStmt]bool, imports map[string]string) []*core.Violation {
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
			violations = append(violations, r.analyzeFuncBody(ctx, lit.Type, "", lit.Body, writers, ifStmtsInDefer, imports)...)
			return false
		}

		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}

		// Check if this is err != nil, alone or narrowed by a test that does
		// not look at the error: err != nil && optional { continue } takes
		// every failure of an optional source for its absence.
		if patternkit.ErrNilCheckName(ifStmt.Cond) == "" && !narrowedErrCheck(ifStmt.Cond) {
			return true
		}

		// Skip error checks inside defer - they typically check named return values for cleanup
		if ifStmtsInDefer[ifStmt] {
			return true
		}

		// An assigned replacement error that reaches a later return is propagated.
		if assignedErrorReturnedAfterIf(body, ifStmt) {
			return true
		}

		// Check if the if body handles the error properly
		// For (T, bool) functions, returning false is acceptable error handling
		if !debugOnlyLostValue(body, ifStmt) && r.bodyHandlesError(ifStmt.Body, writers, imports) {
			return true
		}

		pos := ctx.PositionFor(ifStmt)
		lineContent := ctx.GetLine(pos.Line)

		if ctx.IsSuppressed(pos.Line, r.Name()) {
			return true
		}

		// Skip if we're in a function returning (T, bool) and return includes false
		if funcReturnsValueBool && r.bodyReturnsFalse(ifStmt.Body) {
			return true
		}

		if boolAnswerFunc && r.bodyReturnsBool(ifStmt.Body) {
			return true
		}

		if bodyReturnsErrorText(ifStmt.Body, errorTextResult(ftype)) {
			return true
		}

		// Skip if body has comment indicating error is handled elsewhere
		// Common patterns: "error already sent", "error handled", "response sent"
		if r.bodyHasErrorHandledComment(ctx, ifStmt.Body) {
			return true
		}

		if numericNameFilter(body, ifStmt) {
			return true
		}

		if countsIntoResult(ftype, body, ifStmt.Body) || appendsIntoResult(ftype, body, ifStmt) {
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
func (r *SilentErrorHandlingRule) bodyHandlesError(body *ast.BlockStmt, writers map[string]bool, imports map[string]string) bool {
	if body == nil {
		return false
	}

	for _, stmt := range body.List {
		if r.stmtHandlesError(stmt, writers, imports) {
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
func (r *SilentErrorHandlingRule) stmtHandlesError(stmt ast.Stmt, writers map[string]bool, imports map[string]string) bool {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		return r.returnHandlesError(s)

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
			// into writeSetupFailure(msg, report, err) or
			// handleRefreshFailure(ctx, item, err) instead of logging inline.
			if callTakesErrorArgument(call) {
				return true
			}
		}

	case *ast.IfStmt:
		// A nested condition evaluates its calls on the error path too.
		if conditionTakesError(s.Cond, imports) || r.bodyHandlesError(s.Body, writers, imports) {
			return true
		}

	case *ast.SwitchStmt:
		return r.switchHandlesError(s, writers, imports)

	case *ast.BlockStmt:
		for _, inner := range s.List {
			if r.stmtHandlesError(inner, writers, imports) {
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

	case *ast.ForStmt, *ast.RangeStmt:
		return r.loopHandlesError(stmt, writers, imports)

	case *ast.SendStmt:
		return r.exprReferencesError(s.Value) || r.exprUsesErrorValue(s.Value)
	}

	return false
}

func (r *SilentErrorHandlingRule) returnHandlesError(stmt *ast.ReturnStmt) bool {
	for _, result := range stmt.Results {
		if r.exprReferencesError(result) || r.exprUsesErrorValue(result) || r.exprReturnsUserVisibleError(result) {
			return true
		}
	}
	return false
}

func (r *SilentErrorHandlingRule) switchHandlesError(stmt *ast.SwitchStmt, writers map[string]bool, imports map[string]string) bool {
	for _, clause := range stmt.Body.List {
		if cc, ok := clause.(*ast.CaseClause); ok && slices.ContainsFunc(cc.Body, func(inner ast.Stmt) bool { return r.stmtHandlesError(inner, writers, imports) }) {
			return true
		}
	}
	return false
}

func (r *SilentErrorHandlingRule) loopHandlesError(stmt ast.Stmt, writers map[string]bool, imports map[string]string) bool {
	switch loop := stmt.(type) {
	case *ast.ForStmt:
		return r.bodyHandlesError(loop.Body, writers, imports)
	case *ast.RangeStmt:
		return r.bodyHandlesError(loop.Body, writers, imports)
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
	return slices.ContainsFunc(stmt.Rhs, r.exprUsesErrorValue)
}

// exprUsesErrorValue checks if expression uses an error value (e.g., err.Error(), err.String())
func (r *SilentErrorHandlingRule) exprUsesErrorValue(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		// Check for err.Error() pattern
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			// Check if X is an error variable
			if ident, ok := sel.X.(*ast.Ident); ok && patternkit.IsErrorVarName(ident.Name) {
				return true
			}
			// Check for fmt.Errorf(..., err).Error() pattern
			// The X is a CallExpr (fmt.Errorf) and its args contain error
			if innerCall, ok := sel.X.(*ast.CallExpr); ok {
				if slices.ContainsFunc(innerCall.Args, r.exprReferencesError) {
					return true
				}
			}
		}
		// Also check function arguments for error references
		if slices.ContainsFunc(e.Args, r.exprUsesErrorValue) {
			return true
		}
	case *ast.SelectorExpr:
		// err.someField
		if ident, ok := e.X.(*ast.Ident); ok && patternkit.IsErrorVarName(ident.Name) {
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
		return patternkit.IsErrorVarName(e.Name)
	}
	return false
}

// exprReferencesError checks if expression references err variable or creates an error
func (r *SilentErrorHandlingRule) exprReferencesError(expr ast.Expr) bool {
	return patternkit.ExprCarriesError(expr)
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
	return slices.ContainsFunc(call.Args, argumentIsError)
}

func argumentIsError(arg ast.Expr) bool {
	switch a := arg.(type) {
	case *ast.Ident:
		return patternkit.IsErrorVarName(a.Name)
	case *ast.SelectorExpr:
		// r.lastErr, or queryErr.message: a field of the error value is its text.
		if x, ok := a.X.(*ast.Ident); ok && patternkit.IsErrorVarName(x.Name) {
			return true
		}
		return patternkit.IsErrorVarName(a.Sel.Name)
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
	errName := patternkit.ErrNilCheckName(ifStmt.Cond)
	source := errSource(body, ifStmt, errName)
	if source == nil {
		return false
	}
	for _, lhs := range source.Lhs {
		if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" && id.Name != errName {
			return true
		}
	}
	return false
}

// errorTextResult returns the index of a string result named as an error
// (errKey, errMsg): the function answers its failures there, -1 for none.
func errorTextResult(ftype *ast.FuncType) int {
	if ftype == nil || ftype.Results == nil {
		return -1
	}
	i := 0
	for _, field := range ftype.Results.List {
		if len(field.Names) == 0 {
			i++
			continue
		}
		for _, name := range field.Names {
			if helpers.IsIdentNamed(field.Type, "string") && helpers.HasLeadingWord(name.Name, "err") {
				return i
			}
			i++
		}
	}
	return -1
}

// bodyReturnsErrorText reports a branch returning a non-empty error text in
// that result.
func bodyReturnsErrorText(body *ast.BlockStmt, result int) bool {
	if result < 0 {
		return false
	}
	for _, stmt := range body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok || result >= len(ret.Results) {
			continue
		}
		if lit, ok := ret.Results[result].(*ast.BasicLit); !ok || lit.Value != `""` {
			return true
		}
	}
	return false
}

// errSource returns the single-call assignment of the error the if tests: its
// init statement, or the last assignment of the name before it.
func errSource(body *ast.BlockStmt, ifStmt *ast.IfStmt, errName string) *ast.AssignStmt {
	var source *ast.AssignStmt
	if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok {
		source = assign
	} else {
		ast.Inspect(body, func(n ast.Node) bool {
			if assign, ok := n.(*ast.AssignStmt); ok && assign.Pos() < ifStmt.Pos() && patternkit.AssignsName(assign, errName) {
				source = assign
			}
			return true
		})
	}
	if source == nil || len(source.Rhs) != 1 || !patternkit.AssignsName(source, errName) {
		return nil
	}
	return source
}

// numericNameFilter reports a branch that skips an entry whose name is not a
// number (pid, err := strconv.Atoi(d.Name()); if err != nil { continue }): it
// picks the numbered entries out of a listing, like the processes of /proc, and
// the error says only that this entry is not one of them.
func numericNameFilter(body *ast.BlockStmt, ifStmt *ast.IfStmt) bool {
	if len(ifStmt.Body.List) != 1 {
		return false
	}
	if branch, ok := ifStmt.Body.List[0].(*ast.BranchStmt); !ok || branch.Tok != token.CONTINUE || branch.Label != nil {
		return false
	}
	source := errSource(body, ifStmt, patternkit.ErrNilCheckName(ifStmt.Cond))
	if source == nil {
		return false
	}
	call, ok := source.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	if !patternkit.IsSelectorCall(call, "strconv", "Atoi") && !patternkit.IsSelectorCall(call, "strconv", "ParseInt") && !patternkit.IsSelectorCall(call, "strconv", "ParseUint") {
		return false
	}
	name, ok := call.Args[0].(*ast.CallExpr)
	if !ok || len(name.Args) != 0 {
		return false
	}
	sel, ok := name.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Name"
}

// countsIntoResult reports a branch that counts the failure in a tally the
// function returns: bad++ where the function ends with return items, bad, nil
// or declares bad as a named result. The caller gets the number of failures.
func countsIntoResult(ftype *ast.FuncType, body, branch *ast.BlockStmt) bool {
	for _, stmt := range branch.List {
		name := incrementedName(stmt)
		if name != "" && (namedResults(ftype)[name] || returnedByFunc(body, name)) {
			return true
		}
	}
	return false
}

// appendsIntoResult reports a check whose only answer is its error
// (_, err := parse(row.Addr)) where the branch hands the checked item on to
// the slice the function returns, as it is or marked: out = append(out, row)
// or addr+" (unknown)" among the branch's own statements. The error answers
// which way the item goes; it is no failure to report. A fallback the success
// path could also have produced (a cached item, a zero, defaults) hides the
// failure and keeps the finding.
func appendsIntoResult(ftype *ast.FuncType, body *ast.BlockStmt, ifStmt *ast.IfStmt) bool {
	branch := ifStmt.Body
	for _, stmt := range branch.List {
		dst, items := appendToSelf(stmt)
		if dst == "" || (!namedResults(ftype)[dst] && !returnedByFunc(body, dst)) {
			continue
		}
		if declaresName(branch, dst) || returnsWithout(branch, dst) {
			return false
		}
		checked := predicateSubjects(ifStmt)
		for _, item := range items {
			if checked[keptItem(item)] {
				return true
			}
		}
	}
	return false
}

// appendToSelf returns x and the appended items of x = append(x, items...).
func appendToSelf(stmt ast.Stmt) (string, []ast.Expr) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return "", nil
	}
	dst, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return "", nil
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) < 2 {
		return "", nil
	}
	if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "append" {
		return "", nil
	}
	if base, ok := call.Args[0].(*ast.Ident); !ok || base.Name != dst.Name {
		return "", nil
	}
	return dst.Name, call.Args[1:]
}

// declaresName reports a declaration of name in the branch: the slice there
// is another one.
func declaresName(branch *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(branch, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				for _, lhs := range n.Lhs {
					found = found || patternkit.MentionsIdent(lhs, name)
				}
			}
		case *ast.ValueSpec:
			for _, id := range n.Names {
				found = found || id.Name == name
			}
		}
		return !found
	})
	return found
}

// returnsWithout reports a return in the branch that does not hand name to
// the caller.
func returnsWithout(branch *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(branch, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			found = found || !patternkit.ReturnsIdent(n, name)
		}
		return !found
	})
	return found
}

// keptItem is the variable an appended item carries on as it is or marked
// with a string literal: row, addr+" (unknown)", "unknown: "+addr; else "".
func keptItem(item ast.Expr) string {
	switch e := ast.Unparen(item).(type) {
	case *ast.Ident:
		return e.Name
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return ""
		}
		if lit, ok := ast.Unparen(e.Y).(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if id, ok := ast.Unparen(e.X).(*ast.Ident); ok {
				return id.Name
			}
		}
		if lit, ok := ast.Unparen(e.X).(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if id, ok := ast.Unparen(e.Y).(*ast.Ident); ok {
				return id.Name
			}
		}
	}
	return ""
}

// predicateSubjects are the variables a check whose only answer is its error
// reads: row for if _, err := parse(row.Addr); err != nil. Empty when the if
// keeps a value of the call.
func predicateSubjects(ifStmt *ast.IfStmt) map[string]bool {
	init, ok := ifStmt.Init.(*ast.AssignStmt)
	if !ok || len(init.Rhs) != 1 || len(init.Lhs) < 2 {
		return nil
	}
	errName := patternkit.ErrNilCheckName(ifStmt.Cond)
	for _, lhs := range init.Lhs {
		name, ok := lhs.(*ast.Ident)
		if !ok || (name.Name != "_" && name.Name != errName) {
			return nil
		}
	}
	call, ok := init.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil
	}
	subjects := map[string]bool{}
	for _, arg := range call.Args {
		if root := rootIdentName(arg); root != "" {
			subjects[root] = true
		}
	}
	return subjects
}

// incrementedName is the variable of x++ or x += n, or "".
func incrementedName(stmt ast.Stmt) string {
	switch s := stmt.(type) {
	case *ast.IncDecStmt:
		if id, ok := s.X.(*ast.Ident); ok && s.Tok == token.INC {
			return id.Name
		}
	case *ast.AssignStmt:
		if s.Tok == token.ADD_ASSIGN && len(s.Lhs) == 1 {
			if id, ok := s.Lhs[0].(*ast.Ident); ok {
				return id.Name
			}
		}
	}
	return ""
}

// returnedByFunc reports whether any return of the function (excluding returns
// inside closures) hands name to the caller. Accumulating with OR makes the
// answer independent of the source order of return statements.
func returnedByFunc(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			found = found || patternkit.ReturnsIdent(n, name)
		}
		return true
	})
	return found
}

func conditionTakesError(cond ast.Expr, imports map[string]string) bool {
	found := false
	ast.Inspect(cond, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isStandardErrorClassifier(call, imports) {
			return false
		}
		if callTakesErrorArgument(call) {
			found = true
			return false
		}
		return true
	})
	return found
}

func standardImportAliases(file *ast.File) map[string]string {
	aliases := make(map[string]string, len(file.Imports))
	for _, spec := range file.Imports {
		importPath, ok := patternkit.GoStringLiteral(spec.Path)
		if !ok {
			continue
		}
		name := path.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != "." && name != "_" {
			aliases[name] = importPath
		}
	}
	return aliases
}

// isStandardErrorClassifier recognizes standard-library calls that inspect an
// error's kind without reporting or forwarding the error.
func isStandardErrorClassifier(call *ast.CallExpr, imports map[string]string) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if selector.Sel.Name == "Is" && callTakesErrorArgument(call) {
		for _, importPath := range imports {
			if importPath == "syscall" {
				return true // syscall.Errno.Is classifies the target error.
			}
		}
	}
	qualifier, ok := ast.Unparen(selector.X).(*ast.Ident)
	if !ok {
		return false
	}
	importPath := imports[qualifier.Name]
	switch importPath {
	case "errors":
		return selector.Sel.Name == "Is" || selector.Sel.Name == "As"
	case "os":
		switch selector.Sel.Name {
		case "IsNotExist", "IsExist", "IsPermission", "IsTimeout":
			return true
		}
	case "io/fs", "net", "syscall", "context":
		return strings.HasPrefix(selector.Sel.Name, "Is") || selector.Sel.Name == "As"
	}
	return false
}

type assignedErrorScope struct{ insideTarget bool }

type assignedErrorFlow struct {
	target  *ast.IfStmt
	errName string
	found   bool
}

func (r *assignedErrorFlow) CloneState(paths []bool) []bool { return slices.Clone(paths) }
func (r *assignedErrorFlow) JoinStates(left, right []bool) []bool {
	return patternkit.JoinFlowPaths(left, right, func(assigned bool) string {
		if assigned {
			return "assigned"
		}
		return "unassigned"
	})
}
func (r *assignedErrorFlow) LiveState(paths []bool) bool { return len(paths) != 0 }
func (r *assignedErrorFlow) DeadState() []bool           { return nil }
func (r *assignedErrorFlow) EnterScope(_ patternkit.FlowScopeKind, node ast.Node, parent assignedErrorScope, paths []bool) (assignedErrorScope, []bool) {
	if node == r.target.Body {
		return assignedErrorScope{insideTarget: true}, paths
	}
	return parent, paths
}
func (*assignedErrorFlow) LeaveScope(patternkit.FlowScopeKind, assignedErrorScope, *patternkit.FlowEdges[[]bool]) {
}
func (r *assignedErrorFlow) SimpleStmt(stmt ast.Stmt, paths []bool, scope assignedErrorScope) ([]bool, bool) {
	if assign, ok := stmt.(*ast.AssignStmt); ok && patternkit.AssignsName(assign, r.errName) {
		for i := range paths {
			paths[i] = scope.insideTarget && assignedNonNilValue(assign, r.errName)
		}
	}
	if ret, ok := stmt.(*ast.ReturnStmt); ok {
		if patternkit.ReturnsIdent(ret, r.errName) {
			for _, assigned := range paths {
				r.found = r.found || assigned
			}
		}
		return nil, true
	}
	return paths, false
}
func (r *assignedErrorFlow) IfCondition(_ *ast.IfStmt, paths []bool, _ assignedErrorScope) ([]bool, []bool) {
	return slices.Clone(paths), slices.Clone(paths)
}
func (*assignedErrorFlow) FlowExpr(_ ast.Expr, paths []bool, _ assignedErrorScope) []bool {
	return paths
}
func (*assignedErrorFlow) RangeVars(_ *ast.RangeStmt, paths []bool, _ assignedErrorScope) []bool {
	return paths
}
func (*assignedErrorFlow) TypeSwitchGuard(_ ast.Stmt, paths []bool, _ assignedErrorScope) []bool {
	return paths
}
func (*assignedErrorFlow) CaseClause(_ ast.Stmt, _ *ast.CaseClause, paths []bool, parent assignedErrorScope) ([]bool, assignedErrorScope) {
	return paths, parent
}
func (*assignedErrorFlow) CommClause(_ *ast.CommClause, paths []bool, parent assignedErrorScope) ([]bool, assignedErrorScope) {
	return paths, parent
}
func (*assignedErrorFlow) Normalize(*patternkit.FlowEdges[[]bool]) {}

// assignedNonNilValue reports whether the assignment gives name a value that
// may carry an error. Nil and empty literals do not make the checked error visible.
func assignedNonNilValue(assign *ast.AssignStmt, name string) bool {
	for i, lhs := range assign.Lhs {
		id, ok := lhs.(*ast.Ident)
		if !ok || id.Name != name {
			continue
		}
		var rhs ast.Expr
		if len(assign.Rhs) == 1 {
			rhs = assign.Rhs[0]
		} else if i < len(assign.Rhs) {
			rhs = assign.Rhs[i]
		}
		if rhs == nil {
			return false
		}
		switch value := ast.Unparen(rhs).(type) {
		case *ast.Ident:
			return value.Name != "nil"
		case *ast.BasicLit:
			return value.Value != `""` && value.Value != "0"
		}
		return true
	}
	return false
}

// assignedErrorReturnedAfterIf follows the function's control flow and reports
// only when an assignment in this branch reaches a return of the same variable.
func assignedErrorReturnedAfterIf(body *ast.BlockStmt, target *ast.IfStmt) bool {
	errName := patternkit.ErrNilCheckName(target.Cond)
	if errName == "" && narrowedErrCheck(target.Cond) {
		if cond, ok := ast.Unparen(target.Cond).(*ast.BinaryExpr); ok {
			errName = patternkit.ErrNilCheckName(ast.Unparen(cond.X))
		}
	}
	if errName == "" {
		return false
	}
	hasAssignment := false
	ast.Inspect(target.Body, func(node ast.Node) bool {
		if _, ok := node.(*ast.FuncLit); ok {
			return false
		}
		if assign, ok := node.(*ast.AssignStmt); ok && patternkit.AssignsName(assign, errName) {
			hasAssignment = true
		}
		return !hasAssignment
	})
	if !hasAssignment {
		return false
	}
	analyzer := &assignedErrorFlow{target: target, errName: errName}
	walker := &patternkit.FlowWalker[[]bool, assignedErrorScope]{Rule: analyzer}
	walker.Walk(body, []bool{false}, assignedErrorScope{})
	return analyzer.found
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
	name := patternkit.ErrNilCheckName(ast.Unparen(bin.X))
	return name != "" && !patternkit.Mentions(bin.Y, name)
}
