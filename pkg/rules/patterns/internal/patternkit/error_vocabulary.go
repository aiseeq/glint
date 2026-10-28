package patternkit

import (
	"go/ast"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// IsErrorVarName reports whether an identifier is spelled as an error value:
// err, a camelCase name ending in the word Err (dbErr, loadErr) or a name
// ending in error (loadError, lastError). stderr and interrupted are words of
// their own, not errors.
func IsErrorVarName(name string) bool {
	// One letter before err (perr, rerr, werr) is the short local idiom.
	return name == "err" || len(name) == 4 && strings.HasSuffix(name, "err") || strings.HasSuffix(name, "Err") ||
		strings.HasSuffix(strings.ToLower(name), "error")
}

// IsSentinelErrorName reports whether the name is spelled as a declared error
// value: the word Err leading a camelCase name (ErrNotFound, errClosed).
func IsSentinelErrorName(name string) bool {
	return helpers.HasLeadingWord(name, "Err")
}

// ExprCarriesError reports whether the expression hands an error on: an
// error variable (err, dbErr), a sentinel (ErrNotFound, store.ErrClosed), a
// call creating an error (errors.New, fmt.Errorf, newValidationError) or a
// call wrapping one of those (errors.Wrap(err, "..."), withStack(err)).
func ExprCarriesError(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return IsErrorVarName(e.Name) || IsSentinelErrorName(e.Name)
	case *ast.SelectorExpr:
		return IsSentinelErrorName(e.Sel.Name)
	case *ast.CallExpr:
		// A constructor named as a sentinel: domain.ErrNotFound("order", id).
		if CallCreatesError(e) || IsSentinelErrorName(helpers.CalleeName(e)) {
			return true
		}
		if slices.ContainsFunc(e.Args, ExprCarriesError) {
			return true
		}
	}
	return false
}

// errorLevelVerbs are the logging verbs that report a failure: Error, Warn and
// Fatal levels, in the spelling logVerb returns.
var errorLevelVerbs = map[string]bool{
	"error": true, "errorf": true, "errorw": true, "errorln": true,
	"warn": true, "warnf": true, "warnw": true, "warning": true, "warningf": true,
	"fatal": true, "fatalf": true, "fatalw": true, "fatalln": true,
}

// IsErrorLevelLogCall reports whether the call logs on a logger (see
// isLoggerReceiver) at Error, Warn or Fatal level.
func IsErrorLevelLogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && errorLevelVerbs[helpers.LogVerb(sel)] && helpers.IsLoggerReceiver(sel.X)
}

// wordStartsAt reports whether a camelCase word of name starts at byte offset
// i: the name starts there, the rune there is upper-case, or the previous rune
// is a separator.
func wordStartsAt(name string, i int) bool {
	if i == 0 {
		return true
	}
	current, _ := utf8.DecodeRuneInString(name[i:])
	if unicode.IsUpper(current) {
		return true
	}
	prev, _ := utf8.DecodeLastRuneInString(name[:i])
	return !unicode.IsLetter(prev) && !unicode.IsDigit(prev)
}

// HasCamelWord reports whether name contains the camelCase word, compared
// case-insensitively and bounded on both sides: GetRealIP contains "ip",
// GetRecipient does not.
func HasCamelWord(name, word string) bool {
	lowerName := strings.ToLower(name)
	lowerWord := strings.ToLower(word)
	for from := 0; ; {
		idx := strings.Index(lowerName[from:], lowerWord)
		if idx < 0 {
			return false
		}
		start := from + idx
		if wordStartsAt(name, start) && helpers.WordEndsAt(name, start+len(word)) {
			return true
		}
		from = start + 1
	}
}

// ForEachFunction visits every function of the file with its own signature:
// declarations with their name, function literals with the name of the
// declaration around them ("" at package level). A literal's body belongs to
// the literal, so visit sees each statement once, under the signature it
// returns through.
func ForEachFunction(file *ast.File, visit func(name string, ftype *ast.FuncType, body *ast.BlockStmt)) {
	var walk func(name string, ftype *ast.FuncType, body *ast.BlockStmt)
	walk = func(name string, ftype *ast.FuncType, body *ast.BlockStmt) {
		if body == nil {
			return
		}
		visit(name, ftype, body)
		ast.Inspect(body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok {
				walk(name, lit.Type, lit.Body)
				return false
			}
			return true
		})
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			walk(fn.Name.Name, fn.Type, fn.Body)
			return false
		case *ast.FuncLit:
			walk("", fn.Type, fn.Body)
			return false
		}
		return true
	})
}
