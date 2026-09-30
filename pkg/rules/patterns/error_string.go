package patterns

import (
	"go/ast"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorStringRule())
}

// ErrorStringRule detects error strings that don't follow Go conventions
type ErrorStringRule struct {
	*rules.BaseRule
}

// NewErrorStringRule creates the rule
func NewErrorStringRule() *ErrorStringRule {
	return &ErrorStringRule{
		BaseRule: rules.NewBaseRule(
			"error-string",
			"patterns",
			"Error strings should not be capitalized or end with punctuation (Go convention)",
			core.SeverityLow,
		),
	}
}

var errorFuncs = map[string]bool{
	"errors.New": true,
	"fmt.Errorf": true,
}

// AnalyzeFile checks error string formatting
func (r *ErrorStringRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if vs := r.checkCall(ctx, n); len(vs) > 0 {
			violations = append(violations, vs...)
		}
		return true
	})

	return violations
}

func (r *ErrorStringRule) checkCall(ctx *core.FileContext, n ast.Node) []*core.Violation {
	call, ok := n.(*ast.CallExpr)
	if !ok || !r.isErrorCreation(call) || len(call.Args) == 0 {
		return nil
	}

	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return nil
	}

	val := strings.Trim(lit.Value, "`\"")
	if val == "" {
		return nil
	}

	return r.checkErrorString(ctx, lit, val)
}

func (r *ErrorStringRule) checkErrorString(ctx *core.FileContext, lit *ast.BasicLit, val string) []*core.Violation {
	var violations []*core.Violation
	pos := ctx.PositionFor(lit)

	if r.startsWithCapital(val) {
		v := r.CreateViolation(ctx.RelPath, pos.Line, "Error strings should not be capitalized")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Use lowercase for error strings (Go convention)")
		violations = append(violations, v)
	}

	if r.endsWithPunctuation(val) {
		v := r.CreateViolation(ctx.RelPath, pos.Line, "Error strings should not end with punctuation")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Remove trailing punctuation from error string")
		violations = append(violations, v)
	}

	return violations
}

func (r *ErrorStringRule) isErrorCreation(call *ast.CallExpr) bool {
	// Check for errors.New or fmt.Errorf
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}

	funcName := ident.Name + "." + sel.Sel.Name
	return errorFuncs[funcName]
}

// startsWithCapital reports whether the error string starts with a capitalized
// word. A word with another capital or a digit after its first letter is an
// initialism (HTTP, TLS1.2, ID) or an identifier (GetUser, AppConfig) and
// keeps its spelling; a capitalized English word (Failed, Invalid, Canceled)
// is reported.
func (r *ErrorStringRule) startsWithCapital(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check for format verbs at start (like %s, %v)
	if s[0] == '%' {
		return false
	}

	first, size := utf8.DecodeRuneInString(s)

	// Only check Latin letters for capitalization
	// Non-Latin scripts (Cyrillic, etc.) have different conventions
	// and error messages in these languages are valid
	if !unicode.Is(unicode.Latin, first) || !unicode.IsUpper(first) {
		return false
	}

	rest := s[size:]
	if end := strings.IndexByte(rest, ' '); end >= 0 {
		rest = rest[:end]
	}
	for _, c := range rest {
		if unicode.IsUpper(c) || unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

func (r *ErrorStringRule) endsWithPunctuation(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check for format verbs at end
	if len(s) >= 2 && s[len(s)-2] == '%' {
		return false
	}

	lastRune := rune(s[len(s)-1])
	// . ! ? are problematic, but : is often used in structured errors
	return lastRune == '.' || lastRune == '!' || lastRune == '?'
}
