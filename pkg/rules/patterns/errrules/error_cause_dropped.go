package errrules

import (
	"go/ast"
	"go/token"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewErrorCauseDroppedRule())
}

// ErrorCauseDroppedRule detects error branches that hand the caller a fixed message
// while the real cause is only logged or not used at all.
//
// The shape is the same in both languages: the code knows why the operation failed
// (the error value is right there), yet what reaches the caller, the API client or
// the screen is a constant like "failed to save" that names the operation and nothing
// else. The reader then has to dig in logs that they usually do not have.
//
// Go:  if err != nil { log.Error(err); return errors.New("save failed") }
//
//	if err != nil { http.Error(w, "internal error", 500) }
//
// TS:  catch (e) { console.error(e); toast.error('Не удалось сохранить') }
//
// Not flagged: the cause is wrapped or passed on (%w, err.Error(), `${e}`, rethrow,
// return err), classified before the text is chosen (errors.Is/As, instanceof), a 5xx
// response logs the cause as required by error-detail-in-5xx-response, or the process
// stops with it (panic, os.Exit, log.Fatal).
type ErrorCauseDroppedRule struct {
	*rules.BaseRule
	catchStart    *regexp.Regexp
	catchVar      *regexp.Regexp
	tsFeedback    *regexp.Regexp
	tsMessageProp *regexp.Regexp
	tsLogging     *regexp.Regexp
}

// NewErrorCauseDroppedRule creates the rule
func NewErrorCauseDroppedRule() *ErrorCauseDroppedRule {
	return &ErrorCauseDroppedRule{
		BaseRule: rules.NewBaseRule(
			"error-cause-dropped",
			"patterns",
			"Detects error branches that replace the real cause with a fixed message — the caller learns that something failed, never why",
			core.SeverityMedium,
		),
		catchStart: regexp.MustCompile(`\bcatch\b(?:\s*\(([^)]*)\))?\s*\{`),
		catchVar:   regexp.MustCompile(`^\s*([A-Za-z_$][A-Za-z0-9_$]*)`),
		// A user-facing message built from a string literal: state setters, toasts,
		// alerts, notifications, an error object with a literal text, or a rethrow
		// that starts from a fresh literal.
		tsFeedback: regexp.MustCompile(`\b(?:set[A-Za-z0-9_]*(?:Error|Message|Notice|Alert|Toast|Status)\s*\(|toast(?:\.[a-z]+)?\s*\(|showToast\s*\(|alert\s*\(|notify[A-Za-z0-9_]*\s*\(|throw\s+new\s+[A-Za-z0-9_.]*Error\s*\()\s*(?:\{\s*)?[\x60'"]`),
		// `message: '…'` as an object property; `err.message : 'unknown'` in a ternary is
		// a read of the cause, not a fixed text, hence the no-dot guard.
		tsMessageProp: regexp.MustCompile(`(?:^|[^.A-Za-z0-9_$?])message\s*:\s*[\x60'"]`),
		tsLogging:     regexp.MustCompile(`\b(?:console|logger|log|Sentry)\.[A-Za-z]+\s*\(`),
	}
}

// AnalyzeFile dispatches by language
func (r *ErrorCauseDroppedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	switch {
	case ctx.IsGoFile():
		if !ctx.HasGoAST() || ctx.IsTestFile() || strings.Contains(ctx.RelPath, "testdata/") {
			return nil
		}
		return r.analyzeGo(ctx)
	case ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile():
		if patternkit.SkipFrontendPath(ctx) {
			return nil
		}
		return r.analyzeTS(ctx)
	}
	return nil
}

// --- Go -----------------------------------------------------------------------

func (r *ErrorCauseDroppedRule) analyzeGo(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		errName := patternkit.ErrNilCheckName(ifStmt.Cond)
		if errName == "" {
			return true
		}
		if emission := r.droppedCauseEmission(ifStmt.Body, errName); emission != nil {
			violations = append(violations, r.goViolation(ctx, emission, errName))
		}
		return true
	})
	return violations
}

// droppedCauseEmission returns the call that hands out a fixed message when the
// error variable never reaches anything but a logger inside the branch.
func (r *ErrorCauseDroppedRule) droppedCauseEmission(body *ast.BlockStmt, errName string) *ast.CallExpr {
	if body == nil {
		return nil
	}
	var emission *ast.CallExpr
	causeUsed := false
	causeLogged := false
	terminates := false

	// A nested `if errors.Is(err, …)` chain classifies the cause: the walk below sees
	// errName used and the branch is not reported.
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if isProcessStop(node) {
				terminates = true
				return false
			}
			if isCauseLogCall(node) {
				causeLogged = causeLogged || nodeReadsIdent(node, errName)
				// The cause may be logged — that is not the caller seeing it.
				return false
			}
			if emission == nil && emitsFixedMessage(node) {
				emission = node
			}
		case *ast.Ident:
			if node.Name == errName {
				causeUsed = true
			}
		}
		return true
	})

	if emission == nil || causeUsed || terminates {
		return nil
	}
	unexpandedLog := causeLoggedInUnexpandedLiteral(body, errName)
	if unlogged, reached := firstUnloggedResponse(body, errName, emission); unlogged != nil {
		if unexpandedLog && emitsFixedMessage(emission) && isServerErrorResponse(emission) {
			return nil
		}
		return unlogged
	} else if reached {
		return nil
	}
	// Preserve the former whole-branch result when the walker cannot reach the
	// selected emission, such as a function literal stored for a later call.
	if (causeLogged || unexpandedLog) && emitsFixedMessage(emission) && isServerErrorResponse(emission) {
		return nil
	}
	return emission
}

type causeLogFlowState struct {
	live    bool
	logged  bool
	pending []*ast.CallExpr
}

type causeLogFlowRule struct {
	errName    string
	bad        *[]*ast.CallExpr
	selected   *ast.CallExpr
	reached    *bool
	branchBody *ast.BlockStmt
	exits      []causeLogFlowState
	completed  []causeLogFlowState
}

func firstUnloggedResponse(body *ast.BlockStmt, errName string, selected *ast.CallExpr) (*ast.CallExpr, bool) {
	var bad []*ast.CallExpr
	var reached bool
	rule := &causeLogFlowRule{
		errName: errName, bad: &bad, selected: selected, reached: &reached,
		branchBody: body,
	}
	walker := &patternkit.FlowWalker[causeLogFlowState, struct{}]{Rule: rule}
	edges := walker.Stmt(body, causeLogFlowState{live: true}, struct{}{})
	states := append(rule.exits, rule.completed...)
	states = append(states, edges.Next, edges.Breaks, edges.Continues)
	for _, state := range states {
		bad = append(bad, state.pending...)
	}
	if len(bad) == 0 {
		return nil, reached
	}
	sort.SliceStable(bad, func(left, right int) bool { return bad[left].Pos() < bad[right].Pos() })
	return bad[0], reached
}

func causeLoggedInUnexpandedLiteral(body *ast.BlockStmt, errName string) bool {
	var literals []*ast.FuncLit
	called := make(map[*ast.FuncLit]bool)
	ast.Inspect(body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.FuncLit:
			literals = append(literals, current)
		case *ast.CallExpr:
			if literal, ok := ast.Unparen(current.Fun).(*ast.FuncLit); ok {
				called[literal] = true
			}
		}
		return true
	})
	for _, literal := range literals {
		if called[literal] {
			continue
		}
		logged := false
		ast.Inspect(literal.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if isCauseLogCall(call) && nodeReadsIdent(call, errName) {
				logged = true
				return false
			}
			return !isCauseLogCall(call)
		})
		if logged {
			return true
		}
	}
	return false
}

func (r *causeLogFlowRule) CloneState(state causeLogFlowState) causeLogFlowState {
	state.pending = append([]*ast.CallExpr(nil), state.pending...)
	return state
}

func (r *causeLogFlowRule) JoinStates(left, right causeLogFlowState) causeLogFlowState {
	joined := causeLogFlowState{live: left.live || right.live, logged: left.logged && right.logged}
	joined.pending = append(joined.pending, left.pending...)
	for _, pending := range right.pending {
		if !slices.Contains(joined.pending, pending) {
			joined.pending = append(joined.pending, pending)
		}
	}
	return joined
}

func (r *causeLogFlowRule) LiveState(state causeLogFlowState) bool { return state.live }

func (r *causeLogFlowRule) DeadState() causeLogFlowState { return causeLogFlowState{} }

func (r *causeLogFlowRule) EnterScope(_ patternkit.FlowScopeKind, _ ast.Node, parent struct{}, state causeLogFlowState) (struct{}, causeLogFlowState) {
	return parent, state
}

func (r *causeLogFlowRule) LeaveScope(patternkit.FlowScopeKind, struct{}, *patternkit.FlowEdges[causeLogFlowState]) {
}

func (r *causeLogFlowRule) FlowScopeLeft(_ patternkit.FlowScopeKind, node ast.Node, edges *patternkit.FlowEdges[causeLogFlowState]) {
	if node == r.branchBody {
		r.exits = append(r.exits, r.CloneState(edges.Next), r.CloneState(edges.Breaks), r.CloneState(edges.Continues))
	}
}

func (r *causeLogFlowRule) SimpleStmt(stmt ast.Stmt, state causeLogFlowState, _ struct{}) (causeLogFlowState, bool) {
	state = r.scanNode(stmt, state)
	if _, ok := stmt.(*ast.ReturnStmt); ok {
		r.completed = append(r.completed, state)
		return causeLogFlowState{}, true
	}
	return state, false
}

func (r *causeLogFlowRule) scanNode(node ast.Node, state causeLogFlowState) causeLogFlowState {
	var calls []*ast.CallExpr
	ast.Inspect(node, func(current ast.Node) bool {
		if _, ok := current.(*ast.FuncLit); ok {
			return false
		}
		if call, ok := current.(*ast.CallExpr); ok {
			calls = append(calls, call)
			if isCauseLogCall(call) {
				return false
			}
		}
		return true
	})
	sort.SliceStable(calls, func(left, right int) bool { return calls[left].End() < calls[right].End() })
	for _, call := range calls {
		if literal, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
			state = r.inlineBody(literal.Body, state)
		}
		if r.reached != nil && call == r.selected {
			*r.reached = true
		}
		if isCauseLogCall(call) && nodeReadsIdent(call, r.errName) {
			state.logged = true
			state.pending = nil
			continue
		}
		if isCauseLogCall(call) {
			continue
		}
		if !emitsFixedMessage(call) {
			continue
		}
		if !isServerErrorResponse(call) {
			*r.bad = append(*r.bad, call)
		} else if !state.logged && !slices.Contains(state.pending, call) {
			state.pending = append(state.pending, call)
		}
	}
	return state
}

func (r *causeLogFlowRule) inlineBody(body *ast.BlockStmt, state causeLogFlowState) causeLogFlowState {
	child := &causeLogFlowRule{errName: r.errName, bad: r.bad, selected: r.selected, reached: r.reached}
	walker := &patternkit.FlowWalker[causeLogFlowState, struct{}]{Rule: child}
	edges := walker.Stmt(body, state, struct{}{})
	completed := append([]causeLogFlowState(nil), child.completed...)
	for _, edge := range []causeLogFlowState{edges.Next, edges.Breaks, edges.Continues} {
		if child.LiveState(edge) {
			completed = append(completed, edge)
		}
	}
	if len(completed) == 0 {
		return state
	}
	joined := completed[0]
	for _, result := range completed[1:] {
		joined = r.JoinStates(joined, result)
	}
	return joined
}

func (r *causeLogFlowRule) IfCondition(stmt *ast.IfStmt, state causeLogFlowState, _ struct{}) (causeLogFlowState, causeLogFlowState) {
	state = r.scanNode(stmt.Cond, state)
	return state, state
}

func (r *causeLogFlowRule) FlowExpr(expr ast.Expr, state causeLogFlowState, _ struct{}) causeLogFlowState {
	return r.scanNode(expr, state)
}

func (r *causeLogFlowRule) RangeVars(_ *ast.RangeStmt, state causeLogFlowState, _ struct{}) causeLogFlowState {
	return state
}

func (r *causeLogFlowRule) TypeSwitchGuard(stmt ast.Stmt, state causeLogFlowState, _ struct{}) causeLogFlowState {
	return r.scanNode(stmt, state)
}

func (r *causeLogFlowRule) CaseClause(_ ast.Stmt, clause *ast.CaseClause, state causeLogFlowState, parent struct{}) (causeLogFlowState, struct{}) {
	for _, expression := range clause.List {
		state = r.scanNode(expression, state)
	}
	return state, parent
}

func (r *causeLogFlowRule) CommClause(_ *ast.CommClause, state causeLogFlowState, parent struct{}) (causeLogFlowState, struct{}) {
	return state, parent
}

func (r *causeLogFlowRule) Normalize(*patternkit.FlowEdges[causeLogFlowState]) {}

// isCauseLogCall also accepts With-style logger calls, which attach the error to
// the logger context before the response is written.
func isCauseLogCall(call *ast.CallExpr) bool {
	if helpers.IsLoggerCall(call) {
		return true
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !helpers.IsLoggerReceiver(sel.X) {
		return false
	}
	return strings.HasPrefix(strings.ToLower(sel.Sel.Name), "with")
}

// isServerErrorResponse recognizes the fixed-text response forms handled by this
// rule, restricted to explicit 5xx statuses or server-error responder names.
func isServerErrorResponse(call *ast.CallExpr) bool {
	if !isErrorResponder(call) {
		return false
	}
	name := strings.ToLower(core.ExtractFullFunctionName(call))
	if strings.Contains(name, "servererror") || strings.Contains(name, "internalservererror") {
		return true
	}
	for _, arg := range call.Args {
		switch a := arg.(type) {
		case *ast.BasicLit:
			if a.Kind == token.INT && len(a.Value) == 3 && a.Value[0] == '5' {
				return true
			}
		case *ast.SelectorExpr:
			if x, ok := a.X.(*ast.Ident); ok && x.Name == "http" && serverErrorStatus[a.Sel.Name] {
				return true
			}
		}
	}
	return false
}

var serverErrorStatus = map[string]bool{
	"StatusInternalServerError": true, "StatusNotImplemented": true, "StatusBadGateway": true,
	"StatusServiceUnavailable": true, "StatusGatewayTimeout": true, "StatusHTTPVersionNotSupported": true,
	"StatusVariantAlsoNegotiates": true, "StatusInsufficientStorage": true, "StatusLoopDetected": true,
	"StatusNotExtended": true, "StatusNetworkAuthenticationRequired": true,
}

// emitsFixedMessage reports whether the call produces an error or an error response
// whose text is a string literal: errors.New("…"), fmt.Errorf("…") without cause,
// http.Error(w, "…", 500), writeError(w, 500, "…"), respondError(w, 500, "…", code).
func emitsFixedMessage(call *ast.CallExpr) bool {
	if text, ok := errorFlashText(call); ok {
		return !selfExplanatoryText.MatchString(text)
	}
	if !patternkit.CallCreatesError(call) && !isErrorResponder(call) {
		return false
	}
	if isClientErrorResponse(call) {
		// 4xx is a verdict on the caller's input; the parser's own words would not
		// explain more than "invalid request body" already does.
		return false
	}
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		text := strings.TrimSpace(strings.Trim(lit.Value, "`\""))
		if text == "" {
			continue
		}
		if strings.Contains(text, "%") && len(call.Args) > 1 {
			// Format verbs with arguments: the text carries specifics of its own
			// ("invalid %s: %q") even without the error value.
			return false
		}
		if selfExplanatoryText.MatchString(text) {
			return false
		}
		return true
	}
	return false
}

// errorFlashLevels are the levels a flash message or a redirect helper takes
// for a failure.
var errorFlashLevels = map[string]bool{"error": true, "danger": true, "err": true, "fail": true, "failure": true}

// errorFlashText returns the literal message of a flash or redirect helper
// called with an error level: redirectItems(w, r, "error", "Cannot delete").
// The level is the argument right before the message.
func errorFlashText(call *ast.CallExpr) (string, bool) {
	for i := 0; i+1 < len(call.Args); i++ {
		level, ok := helpers.StringLiteral(call.Args[i])
		if !ok || !errorFlashLevels[strings.ToLower(level)] {
			continue
		}
		text, ok := helpers.StringLiteral(call.Args[i+1])
		if !ok || strings.TrimSpace(text) == "" {
			return "", false
		}
		return text, true
	}
	return "", false
}

// selfExplanatoryText matches validation verdicts: a message that says what was expected
// ("portfolio_id must be a UUID", "unsupported chain") explains itself; the underlying
// parser error would only repeat it in other words.
var selfExplanatoryText = regexp.MustCompile(`(?i)\b(invalid|malformed|must\b|expected|required|missing|unsupported|not allowed|out of range|too (?:long|short|large|small|many|few)|not a\b|neither|mismatch|not found|unavailable|not available)|(невалид|некоррект|неверн|долж|ожида|обязател|отсутств|не поддержив|слишком|не совпада|недопустим|не найден|недоступ)`)

// isClientErrorResponse recognises a 4xx answer: an http.Status* 4xx constant or a
// literal 400–499 among the arguments, or a callee whose name already says so
// (sendValidationError, sendDenied, respondNotFound).
func isClientErrorResponse(call *ast.CallExpr) bool {
	name := strings.ToLower(core.ExtractFullFunctionName(call))
	for _, marker := range []string{"unauthorized", "forbidden", "notfound", "badrequest", "validation", "invalid", "conflict", "unprocessable", "toomany", "notallowed"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	for _, arg := range call.Args {
		switch a := arg.(type) {
		case *ast.SelectorExpr:
			if x, ok := a.X.(*ast.Ident); ok && x.Name == "http" && clientErrorStatus[a.Sel.Name] {
				return true
			}
		case *ast.BasicLit:
			if a.Kind == token.INT && len(a.Value) == 3 && a.Value[0] == '4' {
				return true
			}
		}
	}
	return false
}

var clientErrorStatus = map[string]bool{
	"StatusBadRequest": true, "StatusUnauthorized": true, "StatusPaymentRequired": true,
	"StatusForbidden": true, "StatusNotFound": true, "StatusMethodNotAllowed": true,
	"StatusNotAcceptable": true, "StatusRequestTimeout": true, "StatusConflict": true,
	"StatusGone": true, "StatusPreconditionFailed": true, "StatusRequestEntityTooLarge": true,
	"StatusUnsupportedMediaType": true, "StatusUnprocessableEntity": true,
	"StatusLocked": true, "StatusTooManyRequests": true,
}

// isErrorResponder recognises HTTP/RPC helpers that answer the caller with an error:
// the callee name carries error/fail/abort (http.Error, writeError, respondWithError,
// sendValidationError, c.AbortWithStatusJSON, failRequest).
func isErrorResponder(call *ast.CallExpr) bool {
	name := core.ExtractFullFunctionName(call)
	base := name
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		base = base[idx+1:]
	}
	lower := strings.ToLower(base)
	return strings.Contains(lower, "error") || strings.Contains(lower, "fail") || strings.HasPrefix(lower, "abort")
}

// isProcessStop recognises panic, os.Exit and log.Fatal*: the cause is printed and
// nothing is handed back to a caller.
func isProcessStop(call *ast.CallExpr) bool {
	name := core.ExtractFullFunctionName(call)
	if name == "panic" || name == "os.Exit" {
		return true
	}
	base := name
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		base = base[idx+1:]
	}
	return strings.HasPrefix(strings.ToLower(base), "fatal")
}

func (r *ErrorCauseDroppedRule) goViolation(ctx *core.FileContext, call *ast.CallExpr, errName string) *core.Violation {
	pos := ctx.PositionFor(call)
	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"Error branch drops the cause: `"+errName+"` is at best logged while the caller gets a fixed message")
	v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
	v.WithSuggestion("Wrap the cause (%w, err.Error() in details) or classify it (errors.Is/As) before choosing the text; a message that only names the operation leaves the reader guessing why it failed.")
	v.WithContext("pattern", "error-cause-dropped")
	v.WithContext("language", "go")
	return v
}

// --- TypeScript / JavaScript -------------------------------------------------------

func (r *ErrorCauseDroppedRule) analyzeTS(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	src := patternkit.NewJSSource(ctx)
	for i := 0; i < len(src.Code); i++ {
		loc := r.catchStart.FindStringSubmatchIndex(src.Code[i])
		if loc == nil {
			continue
		}
		binding := ""
		if loc[2] >= 0 {
			binding = src.Code[i][loc[2]:loc[3]]
		}
		block, end, ok := patternkit.JsBlockAt(src, i, loc[0])
		if !ok {
			continue
		}
		if r.tsDropsCause(block, binding) {
			violations = append(violations, r.tsViolation(ctx, i+1, ctx.Lines[i], binding))
		}
		i = end
	}
	return violations
}

// tsDropsCause: the block shows the user a literal message (or rethrows a fresh
// literal error) and the caught value is not referenced outside logging calls.
func (r *ErrorCauseDroppedRule) tsDropsCause(block, binding string) bool {
	if !r.tsFeedback.MatchString(block) && !r.tsMessageProp.MatchString(block) && !errorEnvelope(r.withoutLogging(block)) {
		return false
	}
	name := ""
	if sub := r.catchVar.FindStringSubmatch(binding); sub != nil {
		name = sub[1]
	}
	if name == "" {
		// `catch {` — nothing to pass on; a destructured binding is a use by itself.
		return !strings.HasPrefix(strings.TrimSpace(binding), "{")
	}
	var rest []string
	for l := range strings.SplitSeq(block, "\n") {
		if r.tsLogging.MatchString(l) {
			continue
		}
		rest = append(rest, l)
	}
	body := strings.Join(rest, "\n")
	// Strip the catch header itself so the binding declaration does not count as a use.
	if idx := strings.Index(body, "{"); idx >= 0 {
		body = body[idx+1:]
	}
	return !mentionsBinding(body, name)
}

// withoutLogging returns the lines of a block that are not logging calls: the
// fields of a log record ({ error: String(err) }) are not an answer.
func (r *ErrorCauseDroppedRule) withoutLogging(block string) string {
	var rest []string
	for l := range strings.SplitSeq(block, "\n") {
		if !r.tsLogging.MatchString(l) {
			rest = append(rest, l)
		}
	}
	return strings.Join(rest, "\n")
}

// tsErrorProp is an `error:` property of an object literal: after its '{',
// a ',' or at the start of a line, so "load error:" in a message and
// `res.error :` in a ternary are not one.
var tsErrorProp = regexp.MustCompile(`(?m)(?:[{,]|^)\s*error\s*:\s*([^\s,}]+)`)

// errorEnvelope reports an object built with an error property that carries
// a value ({ error: response.statusText }): the catch answers its caller with
// an error of its own making. { error: null } is the absence of one.
func errorEnvelope(block string) bool {
	for _, m := range tsErrorProp.FindAllStringSubmatch(block, -1) {
		switch m[1] {
		case "null", "undefined", "false", "true", "''", `""`:
			continue
		}
		return true
	}
	return false
}

// mentionsBinding reports whether text uses the binding name the way the
// pattern (?:^|[^A-Za-z0-9_$.])name\b reads it: not as a part of a longer
// identifier and not as a property after a dot. Matching by hand spares a
// regexp compiled for every catch block.
func mentionsBinding(text, name string) bool {
	if name == "" {
		return false
	}
	for from := 0; ; {
		idx := strings.Index(text[from:], name)
		if idx < 0 {
			return false
		}
		start := from + idx
		end := start + len(name)
		beforeOK := start == 0 || (!patternkit.IsWordChar(text[start-1]) && text[start-1] != '$' && text[start-1] != '.')
		afterOK := patternkit.IsWordChar(name[len(name)-1]) != (end < len(text) && patternkit.IsWordChar(text[end]))
		if beforeOK && afterOK {
			return true
		}
		from = start + 1
	}
}

func (r *ErrorCauseDroppedRule) tsViolation(ctx *core.FileContext, lineNum int, line, binding string) *core.Violation {
	what := "the caught error"
	if b := strings.TrimSpace(binding); b != "" {
		what = "`" + b + "`"
	}
	v := r.CreateViolation(ctx.RelPath, lineNum,
		"catch block shows a fixed message while "+what+" is at best logged — the user learns that it failed, never why")
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("Put the cause into the message (e.g. getErrorMessage(error)) or branch on it (instanceof, error code) before choosing the text.")
	v.WithContext("pattern", "error-cause-dropped")
	v.WithContext("language", "typescript")
	return v
}
