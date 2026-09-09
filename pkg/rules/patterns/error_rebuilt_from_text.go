package patterns

import (
	"go/ast"
	"go/token"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorRebuiltFromTextRule())
}

// ErrorRebuiltFromTextRule detects an error rebuilt from another error's text:
// fmt.Errorf with %v or %s over a cause, or errors.New over a formatted message.
//
// The text still names the cause, so the defect is invisible in logs — and the
// chain is gone: errors.Is and errors.As stop matching, and every branch that
// depends on them (a not-found answered 404, a cancelled request answered 499,
// a duplicate answered 409) silently degrades to a generic server error.
//
// Real case (projectA, 2026-09): services returned failures as result objects
// and callers rebuilt an error from result.Error.Message. A request the client
// had cancelled reached the boundary as 500 and raised an operational alert
// every time someone navigated away from a slow page.
//
// Not flagged: a call that already wraps a real cause with %w (the chain
// survives, and a second error printed beside it is a choice, not a loss),
// formatting of non-error values, and a cause printed into a log line rather
// than into a returned error.
type ErrorRebuiltFromTextRule struct {
	*rules.BaseRule
}

// NewErrorRebuiltFromTextRule creates the rule.
func NewErrorRebuiltFromTextRule() *ErrorRebuiltFromTextRule {
	return &ErrorRebuiltFromTextRule{
		BaseRule: rules.NewBaseRule(
			"error-rebuilt-from-text",
			"patterns",
			"Detects an error rebuilt from another error's text (%v/%s instead of %w) — errors.Is and errors.As stop working at the boundary",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile reports errors built from the text of another error.
func (r *ErrorRebuiltFromTextRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return analyzeGoFunctions(ctx, func(fn *ast.FuncDecl) []*core.Violation {
		return r.checkFunction(ctx, fn)
	})
}

// checkFunction inspects one function body. Messages assembled into a variable
// first are resolved here: errMsg := fmt.Sprintf("…: %v", err) is the same
// defect as inlining the call into errors.New.
func (r *ErrorRebuiltFromTextRule) checkFunction(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	messages := formattedMessageVars(fn.Body)

	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !r.rebuildsErrorFromText(call, messages) {
			return true
		}
		line := lineFromNode(ctx, call)
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, line,
			"error rebuilt from the text of another error — the chain is lost and errors.Is stops matching at the boundary")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Wrap the cause: fmt.Errorf(\"context: %w\", err), so callers keep classifying it")
		v.WithContext("pattern", "error_rebuilt_from_text")
		violations = append(violations, v)
		return true
	})
	return violations
}

// rebuildsErrorFromText reports whether the call produces an error whose cause
// survives only as text.
func (r *ErrorRebuiltFromTextRule) rebuildsErrorFromText(call *ast.CallExpr, messages map[string]*ast.CallExpr) bool {
	switch calleeName(call) {
	case "fmt.Errorf":
		return formatsCauseWithoutWrap(call)
	case "errors.New":
		return len(call.Args) == 1 && buildsTextFromCause(call.Args[0], messages)
	}
	return false
}

// buildsTextFromCause reports whether the expression is a formatted string that
// carries a cause, either inline or through a variable holding it.
func buildsTextFromCause(expr ast.Expr, messages map[string]*ast.CallExpr) bool {
	switch current := expr.(type) {
	case *ast.CallExpr:
		return calleeName(current) == "fmt.Sprintf" && formatsCauseWithoutWrap(current)
	case *ast.Ident:
		if source, ok := messages[current.Name]; ok {
			return formatsCauseWithoutWrap(source)
		}
	}
	return false
}

// formattedMessageVars maps variables assigned from fmt.Sprintf to that call.
func formattedMessageVars(body *ast.BlockStmt) map[string]*ast.CallExpr {
	messages := make(map[string]*ast.CallExpr)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || calleeName(call) != "fmt.Sprintf" {
			return true
		}
		messages[ident.Name] = call
		return true
	})
	return messages
}

// formatsCauseWithoutWrap reports whether any argument that looks like a cause
// is printed with a verb that does not keep the chain.
func formatsCauseWithoutWrap(call *ast.CallExpr) bool {
	if len(call.Args) < 2 {
		return false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	// Литерал читается как есть, без раскавычивания: экранирование в Go-строке
	// не порождает и не прячет глаголов формата, а разбор кавычек добавил бы
	// ошибку там, где она ничего не решает.
	verbs := formatVerbs(lit.Value)
	if wrapsRealCause(call.Args[1:], verbs) {
		return false
	}
	for i, arg := range call.Args[1:] {
		if i >= len(verbs) || !isTextLosingVerb(verbs[i]) {
			continue
		}
		if expressionCarriesCause(arg) {
			return true
		}
	}
	return false
}

// wrapsRealCause reports whether the call already keeps a cause in the chain.
// A sentinel wrapped with %w does not count: errors.Is keeps matching the
// category, while the cause standing next to it still arrives as text only.
func wrapsRealCause(args []ast.Expr, verbs []byte) bool {
	for i, arg := range args {
		if i >= len(verbs) || verbs[i] != 'w' {
			continue
		}
		if !isSentinelName(arg) {
			return true
		}
	}
	return false
}

// isSentinelName reports whether the expression names a declared error value
// (ErrNotFound, errInvalidFilter, models.ErrNotFound) rather than a caught one.
func isSentinelName(expr ast.Expr) bool {
	var name string
	switch current := expr.(type) {
	case *ast.Ident:
		name = current.Name
	case *ast.SelectorExpr:
		name = current.Sel.Name
	default:
		return false
	}
	for _, prefix := range []string{"Err", "err"} {
		if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
			continue
		}
		return unicode.IsUpper(rune(name[len(prefix)]))
	}
	return false
}

// isTextLosingVerb reports whether the verb prints an error without keeping it
// in the chain. %w is the only verb that wraps.
func isTextLosingVerb(verb byte) bool {
	return verb == 'v' || verb == 's' || verb == 'q'
}

// formatVerbs returns the verb of every operand of a format string, in order.
func formatVerbs(format string) []byte {
	var verbs []byte
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		if i >= len(format) || format[i] == '%' {
			continue
		}
		// Skip flags, width and precision: %+v, %-10s, %.2f.
		for i < len(format) && strings.ContainsRune("+-# 0123456789.*", rune(format[i])) {
			i++
		}
		if i < len(format) {
			verbs = append(verbs, format[i])
		}
	}
	return verbs
}

// expressionCarriesCause reports whether the expression is an error or the text
// of one: err, parseErr, err.Error(), result.Error, result.Error.Message.
func expressionCarriesCause(expr ast.Expr) bool {
	switch current := expr.(type) {
	case *ast.Ident:
		return looksLikeErrorName(current.Name)
	case *ast.CallExpr:
		if sel, ok := current.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" && len(current.Args) == 0 {
			return true
		}
	case *ast.SelectorExpr:
		if looksLikeErrorName(current.Sel.Name) {
			return true
		}
		// result.Error.Message: the field below the error is its text.
		if inner, ok := current.X.(*ast.SelectorExpr); ok && looksLikeErrorName(inner.Sel.Name) {
			return true
		}
	}
	return false
}
