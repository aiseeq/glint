package patternkit

import (
	"go/ast"
	"go/types"
	"strings"
)

// FormatVerbs returns, for every operand of a format string, the verb that
// prints it: verbs[i] is the verb of the i-th argument after the format, 0 for
// an argument consumed by a `*` width or precision. Argument indexes follow
// fmt: %[n]v prints the n-th argument and the ones after continue from there.
// An argument printed more than once keeps %w if any of its verbs is %w.
func FormatVerbs(format string) []byte {
	var verbs []byte
	set := func(arg int, verb byte) {
		for len(verbs) <= arg {
			verbs = append(verbs, 0)
		}
		if verbs[arg] == 0 || verb == 'w' {
			verbs[arg] = verb
		}
	}
	argNum := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		if i >= len(format) || format[i] == '%' {
			continue
		}
		// Flags: %+v, %-10s, %#x, % d, %05d.
		for i < len(format) && strings.IndexByte("+-# 0", format[i]) >= 0 {
			i++
		}
		// A malformed index makes fmt print %!v(BADINDEX): the verb takes
		// no argument.
		var good bool
		i, argNum, good = formatArgIndex(format, i, argNum, true)
		i, argNum = formatWidth(format, i, argNum)
		if i < len(format) && format[i] == '.' {
			i, argNum, good = formatArgIndex(format, i+1, argNum, good)
			i, argNum = formatWidth(format, i, argNum)
		}
		i, argNum, good = formatArgIndex(format, i, argNum, good)
		if i < len(format) && good {
			set(argNum, format[i])
			argNum++
		}
	}
	return verbs
}

// formatArgIndex reads an explicit argument index [n] at i and returns the
// position after it with the argument it selects; without one, position and
// argument stay. good turns false on an index that is not a positive number
// or is not closed, and stays false once it is.
func formatArgIndex(format string, i, argNum int, good bool) (int, int, bool) {
	if i >= len(format) || format[i] != '[' {
		return i, argNum, good
	}
	end := strings.IndexByte(format[i:], ']')
	if end < 0 {
		return i, argNum, false
	}
	n := 0
	for _, digit := range format[i+1 : i+end] {
		if digit < '0' || digit > '9' {
			return i + end + 1, argNum, false
		}
		n = n*10 + int(digit-'0')
	}
	if n < 1 {
		return i + end + 1, argNum, false
	}
	return i + end + 1, n - 1, good
}

// formatWidth skips a width or precision at i: digits, or a `*` that takes
// the current argument.
func formatWidth(format string, i, argNum int) (int, int) {
	if i < len(format) && format[i] == '*' {
		return i + 1, argNum + 1
	}
	for i < len(format) && format[i] >= '0' && format[i] <= '9' {
		i++
	}
	return i, argNum
}

// IsErrorValue reports whether the expression's type implements error.
func IsErrorValue(expr ast.Expr, info *types.Info) bool {
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
