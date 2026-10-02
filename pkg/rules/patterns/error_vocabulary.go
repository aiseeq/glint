package patterns

import (
	"go/ast"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// Shared vocabulary of the error-handling rules: how an error variable is
// spelled, which function names are predicates, where one camelCase word ends.
// File rules without type information decide by these spellings; every rule
// that asks the same question asks it here, so the rules cannot disagree.

// isErrorVarName reports whether an identifier is spelled as an error value:
// err, a camelCase name ending in the word Err (dbErr, loadErr) or a name
// ending in error (loadError, lastError). stderr and interrupted are words of
// their own, not errors.
func isErrorVarName(name string) bool {
	// One letter before err (perr, rerr, werr) is the short local idiom.
	return name == "err" || len(name) == 4 && strings.HasSuffix(name, "err") || strings.HasSuffix(name, "Err") ||
		strings.HasSuffix(strings.ToLower(name), "error")
}

// isSentinelErrorName reports whether the name is spelled as a declared error
// value: the word Err leading a camelCase name (ErrNotFound, errClosed).
func isSentinelErrorName(name string) bool {
	return helpers.HasLeadingWord(name, "Err")
}

// exprCarriesError reports whether the expression hands an error on: an
// error variable (err, dbErr), a sentinel (ErrNotFound, store.ErrClosed), a
// call creating an error (errors.New, fmt.Errorf, newValidationError) or a
// call wrapping one of those (errors.Wrap(err, "..."), withStack(err)).
func exprCarriesError(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return isErrorVarName(e.Name) || isSentinelErrorName(e.Name)
	case *ast.SelectorExpr:
		return isSentinelErrorName(e.Sel.Name)
	case *ast.CallExpr:
		if callCreatesError(e) {
			return true
		}
		for _, arg := range e.Args {
			if exprCarriesError(arg) {
				return true
			}
		}
	}
	return false
}

// returnCarriesError reports whether any value of the return hands an error on.
func returnCarriesError(ret *ast.ReturnStmt) bool {
	for _, result := range ret.Results {
		if exprCarriesError(result) {
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

// isErrorLevelLogCall reports whether the call logs on a logger (see
// isLoggerReceiver) at Error, Warn or Fatal level.
func isErrorLevelLogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && errorLevelVerbs[helpers.LogVerb(sel)] && helpers.IsLoggerReceiver(sel.X)
}

// predicatePrefixes are the leading words of a function whose bool result is
// its whole answer: IsEmpty, HasRole, CanWrite, ShouldRetry.
var predicatePrefixes = []string{
	"Is", "Has", "Can", "Should", "Must", "Will", "Was", "Does", "Did",
	"Contains", "Matches", "Exists", "Supports", "Equal", "Equals", "Valid",
}

// isPredicateName reports whether the function name starts with a predicate
// word followed by a word boundary: IsEmpty and isEmpty are predicates,
// HashPassword, CancelOrder, Issue and Validate are not.
func isPredicateName(name string) bool {
	for _, prefix := range predicatePrefixes {
		if helpers.HasLeadingWord(name, prefix) {
			return true
		}
	}
	return false
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

// hasCamelWord reports whether name contains the camelCase word, compared
// case-insensitively and bounded on both sides: GetRealIP contains "ip",
// GetRecipient does not.
func hasCamelWord(name, word string) bool {
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

// forEachFunction visits every function of the file with its own signature:
// declarations with their name, function literals with the name of the
// declaration around them ("" at package level). A literal's body belongs to
// the literal, so visit sees each statement once, under the signature it
// returns through.
func forEachFunction(file *ast.File, visit func(name string, ftype *ast.FuncType, body *ast.BlockStmt)) {
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

// nodeReadsIdent reports whether the node reads the named variable: an
// identifier with that name occurs anywhere except as a direct target of an
// assignment (`err = nil` overwrites the error, it does not look at it).
func nodeReadsIdent(node ast.Node, name string) bool {
	targets := make(map[*ast.Ident]bool)
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		switch current := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range current.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					targets[ident] = true
				}
			}
		case *ast.Ident:
			found = current.Name == name && !targets[current]
		}
		return !found
	})
	return found
}
