package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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
// return err), classified before the text is chosen (errors.Is/As, instanceof), or the
// process stops with it (panic, os.Exit, log.Fatal).
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
		if skipFrontendPath(ctx) {
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
		errName := errNilCheckName(ifStmt.Cond)
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

// errNilCheckName returns the identifier compared with nil in `X != nil`, or "".
func errNilCheckName(cond ast.Expr) string {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return ""
	}
	ident, ok := bin.X.(*ast.Ident)
	if !ok || !isNilIdent(bin.Y) {
		return ""
	}
	lower := strings.ToLower(ident.Name)
	if lower != "err" && !strings.HasSuffix(lower, "err") && !strings.HasSuffix(lower, "error") {
		return ""
	}
	return ident.Name
}

// droppedCauseEmission returns the call that hands out a fixed message when the
// error variable never reaches anything but a logger inside the branch.
func (r *ErrorCauseDroppedRule) droppedCauseEmission(body *ast.BlockStmt, errName string) *ast.CallExpr {
	if body == nil {
		return nil
	}
	var emission *ast.CallExpr
	causeUsed := false
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
			if isLoggerCall(node) {
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
	return emission
}

// emitsFixedMessage reports whether the call produces an error or an error response
// whose text is a string literal: errors.New("…"), fmt.Errorf("…") without cause,
// http.Error(w, "…", 500), writeError(w, 500, "…"), respondError(w, 500, "…", code).
func emitsFixedMessage(call *ast.CallExpr) bool {
	if !callCreatesError(call) && !isErrorResponder(call) {
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

// selfExplanatoryText matches validation verdicts: a message that says what was expected
// ("portfolio_id must be a UUID", "unsupported chain") explains itself; the underlying
// parser error would only repeat it in other words.
var selfExplanatoryText = regexp.MustCompile(`(?i)\b(invalid|malformed|must\b|expected|required|missing|unsupported|not allowed|out of range|too (?:long|short|large|small|many|few)|not a\b|neither|mismatch|not found|unavailable|not available)|(невалид|некоррект|неверн|долж|ожида|обязател|отсутств|не поддержив|слишком|не совпада|недопустим|не найден|недоступ)`)

// isClientErrorResponse recognises a 4xx answer: an http.Status* 4xx constant or a
// literal 400–499 among the arguments, or a callee whose name already says so
// (sendValidationError, sendUnauthorized, respondNotFound).
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

// isLoggerCall recognises calls on a logger: the receiver mentions log (log, logger,
// slog, zlog, r.logger, logging.X) or is a known logging package, and the method is a
// logging verb. fmt.Print* is not a logger: on a CLI stdout is the caller.
func isLoggerCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	verb := strings.ToLower(sel.Sel.Name)
	if !loggingVerbs[strings.TrimSuffix(strings.TrimSuffix(verb, "structured"), "context")] &&
		!strings.HasPrefix(verb, "log") {
		return false
	}
	receiver := strings.ToLower(exprText(sel.X))
	return strings.Contains(receiver, "log") ||
		strings.HasPrefix(receiver, "zap") || strings.HasPrefix(receiver, "logrus") ||
		strings.HasPrefix(receiver, "zerolog") || strings.HasPrefix(receiver, "slog") ||
		strings.HasPrefix(receiver, "sentry") || strings.HasPrefix(receiver, "span")
}

var loggingVerbs = map[string]bool{
	"error": true, "errorf": true, "errorw": true, "errorln": true,
	"warn": true, "warnf": true, "warnw": true, "warning": true, "warningf": true,
	"info": true, "infof": true, "infow": true,
	"debug": true, "debugf": true, "debugw": true,
	"trace": true, "tracef": true,
	"print": true, "printf": true, "println": true,
	"log": true, "logf": true,
	"capture": true, "captureexception": true, "capturemessage": true, "recorderror": true,
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
	for i := 0; i < len(ctx.Lines); i++ {
		line := ctx.Lines[i]
		m := r.catchStart.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		start := i
		block, end := collectBraceBlock(ctx.Lines, i)
		if end > i {
			i = end
		}
		if r.tsDropsCause(block, m[1]) {
			violations = append(violations, r.tsViolation(ctx, start+1, line, m[1]))
		}
	}
	return violations
}

// tsDropsCause: the block shows the user a literal message (or rethrows a fresh
// literal error) and the caught value is not referenced outside logging calls.
func (r *ErrorCauseDroppedRule) tsDropsCause(block, binding string) bool {
	if !r.tsFeedback.MatchString(block) && !r.tsMessageProp.MatchString(block) {
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
	for _, l := range strings.Split(block, "\n") {
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
	use := regexp.MustCompile(`(?:^|[^A-Za-z0-9_$.])` + regexp.QuoteMeta(name) + `\b`)
	return !use.MatchString(body)
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
