package security

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"regexp/syntax"
	"strconv"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// regexpPatternFuncs are the functions of package regexp whose first argument
// is a pattern, mapped to the syntax that pattern is parsed with.
var regexpPatternFuncs = map[string]syntax.Flags{
	"Compile":          syntax.Perl,
	"MustCompile":      syntax.Perl,
	"Match":            syntax.Perl,
	"MatchString":      syntax.Perl,
	"MatchReader":      syntax.Perl,
	"CompilePOSIX":     syntax.POSIX,
	"MustCompilePOSIX": syntax.POSIX,
}

// regexpPatternLiteral is a string literal handed to package regexp as a
// pattern. A pattern describes the shape of a value, so text that merely looks
// like a credential in it (a prefix followed by a class and a repetition) is not
// one. Only the fixed text of the pattern - what it matches verbatim - can carry
// a real credential.
type regexpPatternLiteral struct {
	start, end token.Position
	fixed      []string
	// invalid is why the literal is not a valid pattern. Such a literal
	// describes no shape, so nothing in it is exempt.
	invalid error
}

// regexpPatternLiterals finds the literal patterns a Go file passes to package
// regexp.
func regexpPatternLiterals(ctx *core.FileContext) []regexpPatternLiteral {
	if ctx.GoAST == nil || ctx.GoFileSet == nil {
		return nil
	}
	aliases := helpers.PackageAliases(ctx.GoAST, `"regexp"`, "regexp")
	if len(aliases) == 0 {
		return nil
	}

	var literals []regexpPatternLiteral
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		flags, isPatternFunc := regexpPatternFuncs[sel.Sel.Name]
		pkg, ok := sel.X.(*ast.Ident)
		if !isPatternFunc || !ok || !aliases[pkg.Name] {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		fixed, err := patternFixedText(lit, flags)
		literals = append(literals, regexpPatternLiteral{
			start:   ctx.GoFileSet.Position(lit.Pos()),
			end:     ctx.GoFileSet.Position(lit.End()),
			fixed:   fixed,
			invalid: err,
		})
		return true
	})
	return literals
}

// patternFixedText parses a string literal as a regexp pattern and returns its
// fixed text.
func patternFixedText(lit *ast.BasicLit, flags syntax.Flags) ([]string, error) {
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return nil, fmt.Errorf("unquote pattern literal: %w", err)
	}
	parsed, err := syntax.Parse(value, flags)
	if err != nil {
		return nil, fmt.Errorf("parse pattern: %w", err)
	}
	return fixedText(parsed, nil), nil
}

// fixedText collects the runs of a parsed pattern that match verbatim.
func fixedText(re *syntax.Regexp, runs []string) []string {
	if re.Op == syntax.OpLiteral {
		return append(runs, string(re.Rune))
	}
	for _, sub := range re.Sub {
		runs = fixedText(sub, runs)
	}
	return runs
}

// contains reports whether a one-based line and column fall inside the literal.
func (l regexpPatternLiteral) contains(line, column int) bool {
	afterStart := line > l.start.Line || (line == l.start.Line && column >= l.start.Column)
	beforeEnd := line < l.end.Line || (line == l.end.Line && column < l.end.Column)
	return afterStart && beforeEnd
}

// exempts reports whether a secret match inside the literal describes a shape
// rather than a value: the pattern is valid and no verbatim part of it holds the
// secret on its own.
func (l regexpPatternLiteral) exempts(secret *regexp.Regexp) bool {
	if l.invalid != nil {
		return false
	}
	for _, run := range l.fixed {
		if secret.MatchString(run) {
			return false
		}
	}
	return true
}

// regexpPatternAt returns the pattern literal a one-based position falls in.
func regexpPatternAt(literals []regexpPatternLiteral, line, column int) (regexpPatternLiteral, bool) {
	for _, literal := range literals {
		if literal.contains(line, column) {
			return literal, true
		}
	}
	return regexpPatternLiteral{}, false
}
