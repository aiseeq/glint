package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

var retryCallbackMethods = map[string]bool{
	"Retry":       true,
	"WithRetry":   true,
	"DoWithRetry": true,
}

func init() {
	rules.Register(NewProviderCommandRetryRule())
}

// ProviderCommandRetryRule detects automatic retries of destructive provider commands.
//
// A retry is a retry callback (Retry(func() { ... })), a same-file helper
// called with its retry flag set, or a loop that repeats one command: every
// iteration calls the same receiver with the same arguments (nothing derived
// from the loop variables or from a channel receive), and the loop repeats by
// construction (an attempt counter, a range without values) or on failure
// (a sleep or backoff, an error check that continues, a success check that
// leaves). A loop over providers or a worker draining a channel sends a new
// command each time and is not a retry.
//
// The retry may sit lower than the command: SendTransaction calls a POST
// helper that wraps the request in a same-file retry helper (a function that
// calls its func parameter in a retry loop). And it may be spread over time:
// a resend entry point (ResendConfirmed) that a reconciler calls for rows of
// an unknown outcome reaches the command again.
type ProviderCommandRetryRule struct {
	*rules.BaseRule
}

// NewProviderCommandRetryRule creates the rule.
func NewProviderCommandRetryRule() *ProviderCommandRetryRule {
	return &ProviderCommandRetryRule{BaseRule: rules.NewBaseRule(
		"provider-command-retry",
		"patterns",
		"Detects destructive provider commands executed with automatic retry",
		core.SeverityCritical,
	)}
}

type providerCommandRetryAnalyzer struct {
	rule          *ProviderCommandRetryRule
	ctx           *core.FileContext
	retryParams   map[string][]int
	reportedCalls map[*ast.CallExpr]bool
	violations    []*core.Violation
}

// AnalyzeFile checks same-file helper signatures, retry callbacks, and loops.
func (r *ProviderCommandRetryRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	analyzer := &providerCommandRetryAnalyzer{
		rule:          r,
		ctx:           ctx,
		retryParams:   collectRetryBoolParameters(ctx.GoAST),
		reportedCalls: make(map[*ast.CallExpr]bool),
	}
	for _, declaration := range ctx.GoAST.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		analyzer.analyzeFunction(function)
	}
	decls := fileFunctions(ctx.GoAST)
	analyzer.detectRetryHelperPaths(decls)
	analyzer.detectResends(ctx.GoAST, decls)
	return analyzer.violations
}

// fileFunctions indexes the file's function declarations by name.
func fileFunctions(file *ast.File) map[string]*ast.FuncDecl {
	decls := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			decls[fn.Name.Name] = fn
		}
	}
	return decls
}

// detectRetryHelperPaths reports a destructive command whose request goes
// through a same-file retry helper: SendTransaction -> signedPOST ->
// withRetry(func() { POST }). The helper repeats the POST on errors that come
// after the server took the request (a timeout, a decode error after a 2xx),
// and the command is executed twice. A helper is a function taking a func
// parameter that it calls inside a retry loop.
func (a *providerCommandRetryAnalyzer) detectRetryHelperPaths(decls map[string]*ast.FuncDecl) {
	helpers := make(map[string]bool)
	for name, fn := range decls {
		if retriesFuncParam(fn) {
			helpers[name] = true
		}
	}
	if len(helpers) == 0 {
		return
	}
	names := make([]string, 0, len(decls))
	for name := range decls {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !providerCommandMethods[name] {
			continue
		}
		for _, call := range retriedPosts(decls[name], decls, helpers, map[string]bool{name: true}) {
			a.report(call, name, name, "retry_helper")
		}
	}
}

// retriesFuncParam reports a function that calls one of its func parameters
// inside a retry loop (an attempt counter, a backoff, an error check that
// continues).
func retriesFuncParam(fn *ast.FuncDecl) bool {
	params := make(map[string]bool)
	for _, field := range fn.Type.Params.List {
		if _, ok := field.Type.(*ast.FuncType); ok {
			for _, name := range field.Names {
				params[name.Name] = true
			}
		}
	}
	if len(params) == 0 {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		loop, ok := n.(*ast.ForStmt)
		if !ok || found {
			return !found
		}
		if countingForLoop(loop) || retryBodyEvidence(loop.Body) {
			ast.Inspect(loop.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if ident, ok := call.Fun.(*ast.Ident); ok && params[ident.Name] {
						found = true
					}
				}
				return !found
			})
		}
		return !found
	})
	return found
}

// retriedPosts returns the calls of retry helpers, reached from fn through
// same-file calls, whose callback sends a POST request.
func retriedPosts(fn *ast.FuncDecl, decls map[string]*ast.FuncDecl, helpers, seen map[string]bool) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calledFunctionName(call.Fun)
		if helpers[name] {
			for _, arg := range call.Args {
				if lit, ok := ast.Unparen(arg).(*ast.FuncLit); ok && buildsPost(lit.Body) {
					calls = append(calls, call)
				}
			}
			return true
		}
		if callee, ok := decls[name]; ok && !seen[name] {
			seen[name] = true
			calls = append(calls, retriedPosts(callee, decls, helpers, seen)...)
		}
		return true
	})
	return calls
}

// buildsPost reports a body that creates a POST request:
// http.NewRequest(http.MethodPost, ...) or with "POST".
func buildsPost(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if name := calledFunctionName(call.Fun); (name == "NewRequest" || name == "NewRequestWithContext") && len(call.Args) >= 2 {
			for _, arg := range call.Args[:2] {
				switch arg := arg.(type) {
				case *ast.SelectorExpr:
					found = found || arg.Sel.Name == "MethodPost"
				case *ast.BasicLit:
					found = found || arg.Value == `"POST"`
				}
			}
		}
		return !found
	})
	return found
}

// resendName is an entry point that executes a command again: a reconciler's
// resend of a row whose first send has an unknown outcome.
var resendName = regexp.MustCompile(`(?i)^re(?:send|submit|dispatch|execute|drive|play)`)

// detectResends reports a resend entry point that reaches a destructive
// provider command through same-file calls: a reconciler calling it on every
// tick repeats the command for a row whose first send may have succeeded.
func (a *providerCommandRetryAnalyzer) detectResends(file *ast.File, decls map[string]*ast.FuncDecl) {
	sends := sendingFunctions(file)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !resendName.MatchString(fn.Name.Name) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !sendsCommand(call, sends) {
				return true
			}
			command := reachedCommand(call, decls, map[string]bool{fn.Name.Name: true})
			if command != "" {
				a.report(call, fn.Name.Name, command, "resend")
			}
			return false
		})
	}
}

// reachedCommand returns the provider command a call issues, directly or
// through same-file functions.
func reachedCommand(call *ast.CallExpr, decls map[string]*ast.FuncDecl, seen map[string]bool) string {
	name := calledFunctionName(call.Fun)
	if _, method := call.Fun.(*ast.SelectorExpr); method && providerCommandMethods[name] {
		return name
	}
	callee, ok := decls[name]
	if !ok || seen[name] {
		return ""
	}
	seen[name] = true
	command := ""
	ast.Inspect(callee.Body, func(n ast.Node) bool {
		if inner, ok := n.(*ast.CallExpr); ok && command == "" {
			command = reachedCommand(inner, decls, seen)
		}
		return command == ""
	})
	return command
}

func collectRetryBoolParameters(file *ast.File) map[string][]int {
	declarationCounts := make(map[string]int)
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			declarationCounts[function.Name.Name]++
		}
	}

	parameters := make(map[string][]int)
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Type.Params == nil || declarationCounts[function.Name.Name] != 1 {
			continue
		}
		position := 0
		for _, field := range function.Type.Params.List {
			count := len(field.Names)
			if count == 0 {
				count = 1
			}
			if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "bool" {
				for index, name := range field.Names {
					if strings.Contains(strings.ToLower(name.Name), "retry") {
						parameters[function.Name.Name] = append(parameters[function.Name.Name], position+index)
					}
				}
			}
			position += count
		}
	}
	return parameters
}

func (a *providerCommandRetryAnalyzer) analyzeFunction(function *ast.FuncDecl) {
	if providerCommandMethods[function.Name.Name] {
		a.detectBoolHelperCalls(function)
	}

	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.CallExpr:
			if retryCallbackMethods[calledFunctionName(current.Fun)] {
				a.detectRetryCallbacks(function.Name.Name, current)
			}
		case *ast.ForStmt:
			if !countingForLoop(current) && !retryBodyEvidence(current.Body) {
				return true
			}
			variables := derivedLoopVariables(current.Body, forLoopVariables(current))
			a.detectCommands(function.Name.Name, current.Body, "loop", variables)
		case *ast.RangeStmt:
			if !repetitionRange(current) && !retryBodyEvidence(current.Body) {
				return true
			}
			variables := derivedLoopVariables(current.Body, rangeLoopVariables(current))
			a.detectCommands(function.Name.Name, current.Body, "loop", variables)
		}
		return true
	})
}

// countingForLoop reports whether the loop counts its iterations itself
// (for attempt := 0; attempt < n; attempt++): each iteration is one more
// attempt, not one more item.
func countingForLoop(loop *ast.ForStmt) bool {
	return loop.Init != nil && loop.Cond != nil
}

// repetitionRange reports whether a range loop repeats rather than walks:
// it binds no value (for range delays) or binds an attempt number
// (for attempt := range maxAttempts).
func repetitionRange(loop *ast.RangeStmt) bool {
	bound := false
	for _, expression := range []ast.Expr{loop.Key, loop.Value} {
		identifier, ok := expression.(*ast.Ident)
		if expression == nil || (ok && identifier.Name == "_") {
			continue
		}
		bound = true
		if ok && attemptCounterName(identifier.Name) {
			return true
		}
	}
	return !bound
}

// attemptCounterName reports whether a variable counts attempts.
func attemptCounterName(name string) bool {
	for _, token := range identifierTokens(name) {
		switch token {
		case "attempt", "attempts", "retry", "retries", "try", "tries":
			return true
		}
	}
	return false
}

// retryBodyEvidence reports whether a loop body repeats its work on failure:
// it waits between iterations (a sleep, a timer, a backoff), counts attempts,
// continues after an error or leaves on success. Nested loops and function
// literals are not searched: their continue, break and counters are their own.
func retryBodyEvidence(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		switch current := node.(type) {
		case *ast.FuncLit, *ast.ForStmt, *ast.RangeStmt:
			return false
		case *ast.CallExpr:
			found = waitsBetweenAttempts(current)
		case *ast.IncDecStmt:
			identifier, ok := current.X.(*ast.Ident)
			found = ok && current.Tok == token.INC && attemptCounterName(identifier.Name)
		case *ast.AssignStmt:
			if current.Tok == token.ADD_ASSIGN && len(current.Lhs) == 1 {
				identifier, ok := current.Lhs[0].(*ast.Ident)
				found = ok && attemptCounterName(identifier.Name)
			}
		case *ast.IfStmt:
			found = errorCheckRepeats(current)
		}
		return !found
	})
	return found
}

// waitsBetweenAttempts reports whether the call pauses before the next
// attempt: time.Sleep, time.After, time.NewTimer, or a sleep/backoff helper.
func waitsBetweenAttempts(call *ast.CallExpr) bool {
	name := calledFunctionName(call.Fun)
	lower := strings.ToLower(name)
	if strings.Contains(lower, "sleep") || strings.Contains(lower, "backoff") {
		return true
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && pkg.Name == "time" && (name == "After" || name == "NewTimer")
}

// errorCheckRepeats reports whether the if statement turns an error into
// another iteration (err != nil → continue) or success into leaving the loop
// (err == nil → return/break).
func errorCheckRepeats(stmt *ast.IfStmt) bool {
	comparison, ok := ast.Unparen(stmt.Cond).(*ast.BinaryExpr)
	if !ok || (comparison.Op != token.NEQ && comparison.Op != token.EQL) {
		return false
	}
	if !comparesErrorWithNil(comparison) {
		return false
	}
	if comparison.Op == token.NEQ {
		return blockBranches(stmt.Body, func(branch ast.Stmt) bool {
			jump, ok := branch.(*ast.BranchStmt)
			return ok && jump.Tok == token.CONTINUE && jump.Label == nil
		})
	}
	return blockBranches(stmt.Body, func(branch ast.Stmt) bool {
		if _, ok := branch.(*ast.ReturnStmt); ok {
			return true
		}
		jump, ok := branch.(*ast.BranchStmt)
		return ok && jump.Tok == token.BREAK && jump.Label == nil
	})
}

// comparesErrorWithNil reports whether a comparison is err == nil / err != nil.
func comparesErrorWithNil(comparison *ast.BinaryExpr) bool {
	for _, pair := range [2][2]ast.Expr{{comparison.X, comparison.Y}, {comparison.Y, comparison.X}} {
		value, valueOK := pair[0].(*ast.Ident)
		nilIdent, nilOK := pair[1].(*ast.Ident)
		if !valueOK || !nilOK || nilIdent.Name != "nil" {
			continue
		}
		for _, token := range identifierTokens(value.Name) {
			if token == "err" || token == "error" {
				return true
			}
		}
	}
	return false
}

// blockBranches reports whether a statement of the block, or of a block or if
// nested in it, satisfies match.
func blockBranches(block *ast.BlockStmt, match func(ast.Stmt) bool) bool {
	for _, stmt := range block.List {
		switch current := stmt.(type) {
		case *ast.BlockStmt:
			if blockBranches(current, match) {
				return true
			}
		case *ast.IfStmt:
			if blockBranches(current.Body, match) {
				return true
			}
			if elseBlock, ok := current.Else.(*ast.BlockStmt); ok && blockBranches(elseBlock, match) {
				return true
			}
		default:
			if match(stmt) {
				return true
			}
		}
	}
	return false
}

func (a *providerCommandRetryAnalyzer) detectBoolHelperCalls(function *ast.FuncDecl) {
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, position := range a.retryParams[calledFunctionName(call.Fun)] {
			if position < len(call.Args) && isTrueLiteral(call.Args[position]) {
				a.report(call, function.Name.Name, function.Name.Name, "bool_helper")
				break
			}
		}
		return true
	})
}

func (a *providerCommandRetryAnalyzer) detectRetryCallbacks(function string, retryCall *ast.CallExpr) {
	for _, argument := range retryCall.Args {
		callback, ok := ast.Unparen(argument).(*ast.FuncLit)
		if !ok {
			continue
		}
		a.detectCommands(function, callback.Body, "retry_callback", nil)
	}
}

func (a *providerCommandRetryAnalyzer) detectCommands(function string, root ast.Node, evidence string, loopVariables map[string]bool) {
	ast.Inspect(root, func(node ast.Node) bool {
		if _, nestedFunction := node.(*ast.FuncLit); nestedFunction {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if command, ok := providerCommandMethod(call); ok && !callUsesIdentifiers(call, loopVariables) {
			a.report(call, function, command, evidence)
		}
		return true
	})
}

func derivedLoopVariables(root ast.Node, loopVariables map[string]bool) map[string]bool {
	derived := make(map[string]bool, len(loopVariables))
	for name := range loopVariables {
		derived[name] = true
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(root, func(node ast.Node) bool {
			switch current := node.(type) {
			case *ast.FuncLit:
				return false
			case *ast.RangeStmt:
				if expressionsUseIdentifiers([]ast.Expr{current.X}, derived) {
					changed = addDerivedIdentifiers([]ast.Expr{current.Key, current.Value}, derived) || changed
				}
			case *ast.AssignStmt:
				// A value received from a channel is new on every iteration,
				// as is anything derived from a loop variable.
				if expressionsUseIdentifiers(current.Rhs, derived) || receivesFromChannel(current.Rhs) {
					changed = addDerivedIdentifiers(current.Lhs, derived) || changed
				}
			case *ast.ValueSpec:
				if expressionsUseIdentifiers(current.Values, derived) || receivesFromChannel(current.Values) {
					for _, name := range current.Names {
						if name.Name != "_" && !derived[name.Name] {
							derived[name.Name] = true
							changed = true
						}
					}
				}
			}
			return true
		})
	}
	return derived
}

// receivesFromChannel reports whether an expression is a channel receive.
func receivesFromChannel(expressions []ast.Expr) bool {
	for _, expression := range expressions {
		unary, ok := ast.Unparen(expression).(*ast.UnaryExpr)
		if ok && unary.Op == token.ARROW {
			return true
		}
	}
	return false
}

func addDerivedIdentifiers(expressions []ast.Expr, identifiers map[string]bool) bool {
	changed := false
	for _, expression := range expressions {
		identifier, ok := expression.(*ast.Ident)
		if ok && identifier.Name != "_" && !identifiers[identifier.Name] {
			identifiers[identifier.Name] = true
			changed = true
		}
	}
	return changed
}

func forLoopVariables(loop *ast.ForStmt) map[string]bool {
	variables := make(map[string]bool)
	assignment, ok := loop.Init.(*ast.AssignStmt)
	if !ok {
		return variables
	}
	for _, expression := range assignment.Lhs {
		if identifier, ok := expression.(*ast.Ident); ok && identifier.Name != "_" {
			variables[identifier.Name] = true
		}
	}
	return variables
}

func rangeLoopVariables(loop *ast.RangeStmt) map[string]bool {
	variables := make(map[string]bool)
	for _, expression := range []ast.Expr{loop.Key, loop.Value} {
		if identifier, ok := expression.(*ast.Ident); ok && identifier.Name != "_" {
			variables[identifier.Name] = true
		}
	}
	return variables
}

// callUsesIdentifiers reports whether the call's receiver or arguments use one
// of the identifiers: a loop over providers calls a different receiver on
// every iteration just as a loop over payouts sends a different payout.
func callUsesIdentifiers(call *ast.CallExpr, identifiers map[string]bool) bool {
	operands := call.Args
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		operands = append([]ast.Expr{selector.X}, call.Args...)
	}
	return expressionsUseIdentifiers(operands, identifiers)
}

func expressionsUseIdentifiers(expressions []ast.Expr, identifiers map[string]bool) bool {
	if len(identifiers) == 0 {
		return false
	}
	uses := false
	for _, expression := range expressions {
		ast.Inspect(expression, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && identifiers[identifier.Name] {
				uses = true
				return false
			}
			return !uses
		})
		if uses {
			return true
		}
	}
	return false
}

func (a *providerCommandRetryAnalyzer) report(call *ast.CallExpr, function, command, evidence string) {
	if a.reportedCalls[call] {
		return
	}
	a.reportedCalls[call] = true
	line := lineFromNode(a.ctx, call)
	if a.ctx.IsSuppressed(line, a.rule.Name()) {
		return
	}

	violation := a.rule.CreateViolation(a.ctx.RelPath, line,
		"destructive provider command '"+command+"' executes with automatic retry")
	violation.WithCode(a.ctx.GetLine(line))
	violation.WithSuggestion("Execute destructive provider commands once; reconcile status without resending or require explicit human approval")
	violation.WithContext("pattern", "provider_command_retry")
	violation.WithContext("function", function)
	violation.WithContext("command", command)
	violation.WithContext("retry_evidence", evidence)
	a.violations = append(a.violations, violation)
}

func calledFunctionName(expression ast.Expr) string {
	switch function := ast.Unparen(expression).(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	default:
		return ""
	}
}

func isTrueLiteral(expression ast.Expr) bool {
	ident, ok := ast.Unparen(expression).(*ast.Ident)
	return ok && ident.Name == "true"
}
