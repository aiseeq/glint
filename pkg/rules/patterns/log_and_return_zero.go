package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
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
// A setup function without results has the same failure in another shape: it
// warns and returns before building the dependency it exists to build, and
// the field stays nil.
//
// Inside an `if err != nil` branch of a function that fetches data (fetch,
// load, get...) a log at any level counts: a Debug line hides the failure
// even better. There the rule also reports a function that
// converts its input and answers a failed lookup with the input itself, and a
// builder that logs a failed constructor and stores the dependency only in
// the else branch.
//
// Not flagged: Info/Debug logs outside an error branch, `return false` (see
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
			"Detects a logged failure followed by a zero-value or own-input return in functions without an error result, or by a return or else branch that leaves the dependency a setup function builds unset",
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
			violations = append(violations, r.checkSetupLeavesUnset(ctx, fn)...)
			return true
		}
		if !hasNonErrorResults(fn.Type.Results) {
			return true
		}

		// A Debug line in an error branch hides a failure of a function that
		// fetches data; a try-function answering nil ("not this way") has
		// that contract.
		errBranches := map[*ast.Stmt]bool{}
		if fetchesData(fn.Name.Name) {
			errBranches = errorBranchBodies(fn.Body)
		}
		inputs := inputValues(fn)
		allErrBranches := errorBranchBodies(fn.Body)
		forEachOwnStatementList(fn.Body, func(list []ast.Stmt) {
			inErrBranch := len(list) > 0 && allErrBranches[&list[0]]
			quietCounts := len(list) > 0 && errBranches[&list[0]]
			for i := 0; i+1 < len(list); i++ {
				// In an `if err != nil` branch of a data fetch a log at any
				// level reports the failure; elsewhere only Error/Warn says
				// something failed.
				if !isErrorOrWarnLogStmt(list[i]) && (!quietCounts || !isLoggerStmt(list[i])) {
					continue
				}
				ret, ok := list[i+1].(*ast.ReturnStmt)
				if !ok {
					continue
				}
				switch {
				case allResultsAreZeroValues(ret):
					violations = append(violations, r.violationAt(ctx, ret,
						"Log followed by a zero-value return — the caller cannot distinguish this failure from a valid value"))
				case inErrBranch && returnsInputFallback(fn.Body, ret, inputs):
					violations = append(violations, r.violationAt(ctx, ret,
						"A failed lookup is logged and answered with the function's own input — the caller takes the unconverted value for the looked-up one"))
				}
			}
		})
		if ret := unparsedInputReturned(fn, inputs); ret != nil {
			violations = append(violations, r.violationAt(ctx, ret,
				"Input that none of the parsers read is returned unchanged — the caller takes the raw text for a parsed value"))
		}
		violations = append(violations, r.checkConstructorLeftUnset(ctx, fn)...)
		violations = append(violations, r.checkWriteMissingFromResultError(ctx, fn)...)

		return true
	})

	return violations
}

func (r *LogAndReturnZeroRule) violationAt(ctx *core.FileContext, node ast.Node, message string) *core.Violation {
	pos := ctx.PositionFor(node)
	v := r.CreateViolation(ctx.RelPath, pos.Line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
	v.WithSuggestion("Change the signature to (T, error) and return an explicit error instead of the substitute value")
	return v
}

// fetchVerbs lead the names of functions that bring data.
var fetchVerbs = []string{"fetch", "load", "get", "list", "read", "query", "collect"}

func fetchesData(name string) bool {
	words := helpers.IdentifierWords(name)
	return len(words) > 0 && slices.Contains(fetchVerbs, strings.ToLower(words[0]))
}

// errorBranchBodies returns the first statements of the bodies of
// `if err != nil` branches, the key forEachOwnStatementList lists share.
func errorBranchBodies(body *ast.BlockStmt) map[*ast.Stmt]bool {
	bodies := make(map[*ast.Stmt]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		if ifStmt, ok := n.(*ast.IfStmt); ok && errNilCheckName(ifStmt.Cond) != "" && len(ifStmt.Body.List) > 0 {
			bodies[&ifStmt.Body.List[0]] = true
		}
		return true
	})
	return bodies
}

// isLoggerStmt reports a statement that is a bare logger call at any level.
func isLoggerStmt(stmt ast.Stmt) bool {
	exprStmt, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	return ok && helpers.IsLoggerCall(call)
}

// inputValues returns the names of the function's parameters and of the
// locals set once from nothing but them (trimmed := strings.TrimSpace(wallet)).
func inputValues(fn *ast.FuncDecl) map[string]bool {
	inputs := make(map[string]bool)
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			inputs[name.Name] = true
		}
	}
	for _, stmt := range fn.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		name, ok := assign.Lhs[0].(*ast.Ident)
		if ok && derivedOnlyFrom(assign.Rhs[0], inputs) {
			inputs[name.Name] = true
		}
	}
	return inputs
}

// derivedOnlyFrom reports an expression whose variables are all inputs: a
// call may name a package function (strings.TrimSpace), not a receiver.
func derivedOnlyFrom(expr ast.Expr, inputs map[string]bool) bool {
	usesInput, other := false, false
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := node.X.(*ast.Ident); ok && !inputs[pkg.Name] {
				return false
			}
		case *ast.Ident:
			if inputs[node.Name] {
				usesInput = true
			} else if node.Obj != nil {
				other = true
			}
		}
		return true
	})
	return usesInput && !other
}

// unparsedInputReturned returns the final `return value` of a function that
// tries parsers on its input and returns the parsed form on success:
//
//	for _, layout := range layouts {
//	    if parsed, err := time.Parse(layout, value); err == nil { return parsed.Format(...) }
//	}
//	return value // text no layout reads passes for a date
//
// The function has no error result, so the failure leaves without a sign.
func unparsedInputReturned(fn *ast.FuncDecl, inputs map[string]bool) *ast.ReturnStmt {
	if len(fn.Body.List) == 0 || fn.Type.Results.NumFields() != 1 {
		return nil
	}
	ret, ok := fn.Body.List[len(fn.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil
	}
	input, ok := ret.Results[0].(*ast.Ident)
	if !ok || !inputs[input.Name] {
		return nil
	}
	// The parsers are tried in a loop (layouts, formats) on the value that is
	// returned: one parse with a default parameter is an env helper's shape.
	parses := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch loop := n.(type) {
		case *ast.RangeStmt:
			body = loop.Body
		case *ast.ForStmt:
			body = loop.Body
		default:
			return !parses
		}
		for _, stmt := range body.List {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				continue
			}
			errName, ok := successGuardErrName(ifStmt.Cond)
			if !ok || len(ifStmt.Body.List) != 1 {
				continue
			}
			source := errSourceExpr(fn.Body, ifStmt, errName)
			if !isParseCall(source) || !slices.ContainsFunc(source.Args, func(arg ast.Expr) bool { return isIdentNamed(arg, input.Name) }) {
				continue
			}
			success, ok := ifStmt.Body.List[0].(*ast.ReturnStmt)
			parses = parses || ok && len(success.Results) == 1 && !derivedOnlyFrom(success.Results[0], inputs)
		}
		return !parses
	})
	if !parses {
		return nil
	}
	return ret
}

// returnsInputFallback reports a single-value return of an input while
// another return of the function hands out something else: the function
// converts its input, and the failed conversion answers with the input.
func returnsInputFallback(body *ast.BlockStmt, ret *ast.ReturnStmt, inputs map[string]bool) bool {
	if len(ret.Results) != 1 {
		return false
	}
	ident, ok := ret.Results[0].(*ast.Ident)
	if !ok || !inputs[ident.Name] {
		return false
	}
	converts := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) == 1 && !derivedOnlyFrom(node.Results[0], inputs) && !isZeroValueExpr(node.Results[0]) {
				converts = true
			}
		}
		return true
	})
	return converts
}

// checkConstructorLeftUnset reports, in a function returning values without
// an error, a constructor whose error is only logged while the dependency is
// stored in the else branch: the function hands back a value with that
// dependency silently missing.
func (r *LogAndReturnZeroRule) checkConstructorLeftUnset(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation
	for i, stmt := range fn.Body.List {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok || i == 0 || errNilCheckName(ifStmt.Cond) == "" || len(ifStmt.Body.List) == 0 {
			continue
		}
		if !slices.ContainsFunc(ifStmt.Body.List, isLoggerStmt) || !allStmtsAreLogs(ifStmt.Body.List) {
			continue
		}
		elseBlock, ok := ifStmt.Else.(*ast.BlockStmt)
		if !ok {
			continue
		}
		built := constructedName(fn.Body.List[i-1], errNilCheckName(ifStmt.Cond))
		if built == "" || !storesIntoField(elseBlock, built) {
			continue
		}
		if ctx.IsSuppressed(ctx.LineFor(ifStmt), r.Name()) {
			continue
		}
		violations = append(violations, r.violationAt(ctx, ifStmt,
			"A failed constructor is only logged and the dependency is left unset - the function returns a value without it and nobody learns why"))
	}
	return violations
}

// checkWriteMissingFromResultError reports, in a function that reports its
// failures through result.Error, a write (a save of progress, FinishSync)
// whose error is only logged: the result goes out with an empty Error and the
// caller takes the run as complete while its progress was never stored.
func (r *LogAndReturnZeroRule) checkWriteMissingFromResultError(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	carriers := make(map[string]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 {
			return true
		}
		if sel, ok := assign.Lhs[0].(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" {
			if holder, ok := sel.X.(*ast.Ident); ok {
				carriers[holder.Name] = true
			}
		}
		return true
	})
	if len(carriers) == 0 {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Else != nil || errNilCheckName(ifStmt.Cond) == "" || !allStmtsAreLogs(ifStmt.Body.List) {
			return true
		}
		assign, ok := ifStmt.Init.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || !isProgressWrite(call) {
			return true
		}
		if ctx.IsSuppressed(ctx.LineFor(ifStmt), r.Name()) {
			return true
		}
		violations = append(violations, r.violationAt(ctx, ifStmt,
			"A failed write is only logged in a function that reports failures through its result's Error field - the result goes out as a success"))
		return true
	})
	return violations
}

// isProgressWrite reports a method call that stores state or closes a run:
// a write verb, or Finish/Complete.
func isProgressWrite(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	name := sel.Sel.Name
	return helpers.IsWriteName(name) || helpers.HasLeadingWord(name, "Finish") || helpers.HasLeadingWord(name, "Complete")
}

func allStmtsAreLogs(list []ast.Stmt) bool {
	for _, stmt := range list {
		if !isLoggerStmt(stmt) {
			return false
		}
	}
	return true
}

// constructedName returns the value of `x, err := NewX(...)` (or
// pkg.NewClient(...)) whose error is errName, or "".
func constructedName(stmt ast.Stmt, errName string) string {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return ""
	}
	value, ok1 := assign.Lhs[0].(*ast.Ident)
	errIdent, ok2 := assign.Lhs[1].(*ast.Ident)
	call, ok3 := assign.Rhs[0].(*ast.CallExpr)
	if !ok1 || !ok2 || !ok3 || errIdent.Name != errName {
		return ""
	}
	name := ""
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		name = fun.Sel.Name
	}
	if !helpers.HasLeadingWord(name, "New") {
		return ""
	}
	return value.Name
}

// storesIntoField reports a block that assigns name to a field (c.chain = name).
func storesIntoField(block *ast.BlockStmt, name string) bool {
	for _, stmt := range block.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		_, isField := assign.Lhs[0].(*ast.SelectorExpr)
		if value, ok := assign.Rhs[0].(*ast.Ident); ok && isField && value.Name == name {
			return true
		}
	}
	return false
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

// checkSetupLeavesUnset reports, in a function without results that builds a
// dependency into a field (ctx.sessionManager = NewSessionManager(...)), an
// earlier branch that logs an error or a warning and returns: the field
// stays nil, startup goes on, and the failure surfaces later as errors on
// every call that needs the dependency.
func (r *LogAndReturnZeroRule) checkSetupLeavesUnset(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	if words := helpers.IdentifierWords(fn.Name.Name); len(words) == 0 || !slices.Contains(setupVerbs, words[0]) {
		return nil
	}
	holders := make(map[string]bool)
	for _, list := range []*ast.FieldList{fn.Recv, fn.Type.Params} {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			for _, name := range field.Names {
				holders[name.Name] = true
			}
		}
	}
	body := fn.Body
	var violations []*core.Violation
	for i, stmt := range body.List {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok || ifStmt.Else != nil || len(ifStmt.Body.List) < 2 {
			continue
		}
		ret, ok := ifStmt.Body.List[len(ifStmt.Body.List)-1].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 0 || !slices.ContainsFunc(ifStmt.Body.List, isErrorOrWarnLogStmt) {
			continue
		}
		field := builtField(body.List[i+1:], holders)
		if field == "" {
			continue
		}
		line := ctx.LineFor(ret)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line,
			"Setup logs a problem and returns, leaving "+field+" unset — startup goes on and the nil dependency fails later, on every call that needs it")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Return an error and let startup fail, or make the dependency optional where it is used")
		violations = append(violations, v)
	}
	return violations
}

// setupVerbs start the names of functions that wire a dependency at startup.
var setupVerbs = []string{"create", "init", "initialize", "setup", "build", "configure", "wire", "register", "start"}

// builtField returns the field of a receiver or a parameter that a later
// top-level statement fills with a constructor's result
// (ctx.sessionManager = NewSessionManager(...)), or "".
func builtField(rest []ast.Stmt, holders map[string]bool) string {
	for _, stmt := range rest {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		sel, ok := assign.Lhs[0].(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if holder, ok := sel.X.(*ast.Ident); !ok || !holders[holder.Name] {
			continue
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			continue
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if helpers.HasLeadingWord(name, "New") {
			return types.ExprString(sel)
		}
	}
	return ""
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
