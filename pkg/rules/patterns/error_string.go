package patterns

import (
	"go/ast"
	"regexp"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorStringRule())
}

// ErrorStringRule detects error strings that don't follow Go conventions
type ErrorStringRule struct {
	*rules.BaseRule
	// Common acronyms that are acceptable at the start
	acronyms map[string]bool
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
		acronyms: map[string]bool{
			"API":   true,
			"URL":   true,
			"HTTP":  true,
			"HTTPS": true,
			"JSON":  true,
			"XML":   true,
			"SQL":   true,
			"EOF":   true,
			"ID":    true,
			"UUID":  true,
			"JWT":   true,
			"TLS":   true,
			"SSL":   true,
			"DNS":   true,
			"TCP":   true,
			"UDP":   true,
			"IP":    true,
			"OS":    true,
			"IO":    true,
		},
	}
}

var errorFuncs = map[string]bool{
	"errors.New": true,
	"fmt.Errorf": true,
}

var errorStringPattern = regexp.MustCompile(`^["` + "`" + `]([^"` + "`" + `]+)["` + "`" + `]`)

// AnalyzeFile checks error string formatting
func (r *ErrorStringRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		if !r.isErrorCreation(call) {
			return true
		}

		// Check the first string argument
		if len(call.Args) == 0 {
			return true
		}

		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}

		// Extract string value
		val := strings.Trim(lit.Value, "`\"")
		if val == "" {
			return true
		}

		// Check for capital letter at start
		if r.startsWithCapital(val) {
			pos := ctx.PositionFor(lit)
			v := r.CreateViolation(ctx.RelPath, pos.Line, "Error strings should not be capitalized")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Use lowercase for error strings (Go convention)")
			violations = append(violations, v)
			return true
		}

		// Check for punctuation at end
		if r.endsWithPunctuation(val) {
			pos := ctx.PositionFor(lit)
			v := r.CreateViolation(ctx.RelPath, pos.Line, "Error strings should not end with punctuation")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Remove trailing punctuation from error string")
			violations = append(violations, v)
		}

		return true
	})

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

func (r *ErrorStringRule) startsWithCapital(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check for format verbs at start (like %s, %v)
	if s[0] == '%' {
		return false
	}

	firstRune := rune(s[0])
	if !unicode.IsUpper(firstRune) {
		return false
	}

	// Check if it's a known acronym
	firstWord := strings.Split(s, " ")[0]
	firstWord = strings.TrimRight(firstWord, ":")
	if r.acronyms[strings.ToUpper(firstWord)] {
		return false
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
