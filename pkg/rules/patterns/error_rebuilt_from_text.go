package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

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
// The cause is recognized by its type, not by its name: a decoded payload with
// an Error field of its own carries no chain to lose. Not flagged either: a
// call that already wraps a real cause with %w (a second failure printed beside
// it is a choice), and a cause printed into a log line rather than into a
// returned error.
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

// AnalyzeFile is a no-op: whether an expression is an error or a field that
// merely spells "Error" is a question about its type, not about the text.
func (r *ErrorRebuiltFromTextRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ErrorRebuiltFromTextRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports errors built from the text of another error.
func (r *ErrorRebuiltFromTextRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), r.analyzeFile)
}

// analyzeFile inspects every function of one file. Messages assembled into a
// variable first are resolved here: errMsg := fmt.Sprintf("…: %v", err) is the
// same defect as inlining the call into errors.New.
func (r *ErrorRebuiltFromTextRule) analyzeFile(ctx *core.FileContext, info *types.Info) []*core.Violation {
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		violations = append(violations, r.checkFunction(ctx, info, fn)...)
	}
	return violations
}

// checkFunction inspects one function body.
func (r *ErrorRebuiltFromTextRule) checkFunction(ctx *core.FileContext, info *types.Info, fn *ast.FuncDecl) []*core.Violation {
	messages := formattedMessageVars(fn.Body)

	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !r.rebuildsErrorFromText(call, info, messages) {
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
func (r *ErrorRebuiltFromTextRule) rebuildsErrorFromText(
	call *ast.CallExpr,
	info *types.Info,
	messages map[string][]*ast.CallExpr,
) bool {
	switch calleeName(call) {
	case "fmt.Errorf":
		return formatsCauseWithoutWrap(call, info)
	case "errors.New":
		return len(call.Args) == 1 && buildsTextFromCause(call.Args[0], info, messages)
	}
	return false
}

// buildsTextFromCause reports whether the expression is a formatted string that
// carries a cause, either inline or through a variable holding it.
func buildsTextFromCause(expr ast.Expr, info *types.Info, messages map[string][]*ast.CallExpr) bool {
	switch current := expr.(type) {
	case *ast.CallExpr:
		return calleeName(current) == "fmt.Sprintf" && formatsCauseWithoutWrap(current, info)
	case *ast.Ident:
		if source := nearestAssignment(messages[current.Name], current.Pos()); source != nil {
			return formatsCauseWithoutWrap(source, info)
		}
	}
	return false
}

// nearestAssignment returns the last assignment made above the use. One name
// commonly holds a different message in every branch of a function, and only
// the one standing above this use describes it.
func nearestAssignment(sources []*ast.CallExpr, use token.Pos) *ast.CallExpr {
	var nearest *ast.CallExpr
	for _, source := range sources {
		if source.Pos() < use {
			nearest = source
		}
	}
	return nearest
}

// formattedMessageVars maps variables assigned from fmt.Sprintf to those calls,
// in source order.
func formattedMessageVars(body *ast.BlockStmt) map[string][]*ast.CallExpr {
	messages := make(map[string][]*ast.CallExpr)
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
		messages[ident.Name] = append(messages[ident.Name], call)
		return true
	})
	return messages
}

// formatsCauseWithoutWrap reports whether any argument that carries a cause is
// printed with a verb that does not keep the chain.
func formatsCauseWithoutWrap(call *ast.CallExpr, info *types.Info) bool {
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
	args := call.Args[1:]
	if wrapsRealCause(args, verbs, info) {
		return false
	}
	for i, arg := range args {
		if i >= len(verbs) || !isTextLosingVerb(verbs[i]) {
			continue
		}
		if expressionCarriesCause(arg, info) {
			return true
		}
	}
	return false
}

// wrapsRealCause reports whether the call already keeps a cause in the chain.
// A sentinel wrapped with %w does not count: errors.Is keeps matching the
// category, while the cause standing next to it still arrives as text only.
func wrapsRealCause(args []ast.Expr, verbs []byte, info *types.Info) bool {
	for i, arg := range args {
		if i >= len(verbs) || verbs[i] != 'w' {
			continue
		}
		if !isDeclaredSentinel(arg, info) {
			return true
		}
	}
	return false
}

// isDeclaredSentinel reports whether the expression is a package-level error
// value (ErrNotFound, models.ErrNotFound): it names a category, not a cause.
func isDeclaredSentinel(expr ast.Expr, info *types.Info) bool {
	var ident *ast.Ident
	switch current := expr.(type) {
	case *ast.Ident:
		ident = current
	case *ast.SelectorExpr:
		ident = current.Sel
	default:
		return false
	}
	variable, ok := info.ObjectOf(ident).(*types.Var)
	if !ok || variable.IsField() {
		return false
	}
	parent := variable.Parent()
	return parent != nil && parent.Parent() == types.Universe
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
// of one: err, err.Error(), result.Error, result.Error.Message. A field named
// Error on a decoded payload is a string of its own and carries no chain.
func expressionCarriesCause(expr ast.Expr, info *types.Info) bool {
	switch current := expr.(type) {
	case *ast.CallExpr:
		sel, ok := current.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Error" || len(current.Args) != 0 {
			return false
		}
		return isErrorValue(sel.X, info)
	case *ast.SelectorExpr:
		// result.Error.Message: the field below the error holding its text. A
		// data field of an error (an id, an address) is not the error itself.
		if isErrorValue(current.X, info) && isMessageFieldName(current.Sel.Name) {
			return true
		}
	}
	return isErrorValue(expr, info)
}

// messageFieldNames are the fields an error type keeps its own text in.
var messageFieldNames = map[string]bool{
	"Message": true, "Msg": true, "Error": true, "Text": true,
	"Detail": true, "Details": true, "Reason": true, "Description": true,
}

// isMessageFieldName reports whether the field holds the text of the error.
func isMessageFieldName(name string) bool {
	return messageFieldNames[name]
}

// isErrorValue reports whether the expression's type implements error.
func isErrorValue(expr ast.Expr, info *types.Info) bool {
	typ := info.TypeOf(expr)
	if typ == nil {
		return false
	}
	errorType, ok := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return types.Implements(typ, errorType)
}
