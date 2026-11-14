// Package helpers provides shared utilities for rule implementations.
package helpers

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// StringLiteral returns the unquoted value of a string literal.
func StringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

// MaskJSCommentsAndStrings returns a copy of TypeScript/JavaScript source lines
// in which every comment (//, /* */ spanning lines, JSDoc) and the contents of
// every literal — '…', "…", template text between ${…} holes, /regex/ — are
// replaced with spaces. String, template and regex delimiters stay in place,
// and so does the code inside ${…}. Every line keeps its byte length, so line
// numbers and byte columns of the masked text point at the original source.
//
// Line rules use it for structure — braces, parentheses, calls — that must
// not be read out of prose or literal text.
//
// There is no parser behind it: an apostrophe in JSX text ("Don't") opens a
// string that ends with the line, and a '/' is taken for a regex literal only
// where an operand is expected. Both keep the damage within one line.
func MaskJSCommentsAndStrings(lines []string) []string {
	return core.MaskJS(lines, true)
}

// ContainsAny reports whether s contains one of the needles: the cheap check
// rules run before a regexp every match of which holds a needle.
func ContainsAny(s string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// jsMaskKey keys the masked views of a file in core.FileShared.
type jsMaskKey struct{ maskLiterals bool }

// FileJSCode is MaskJSCommentsAndStrings of the file's lines, masked once per
// file for all rules. The result must not be modified.
func FileJSCode(ctx *core.FileContext) []string {
	return core.FileShared(ctx, jsMaskKey{maskLiterals: true}, func() []string { return core.MaskJS(ctx.Lines, true) })
}

// FileJSText is MaskJSComments of the file's lines, masked once per file for
// all rules. The result must not be modified.
func FileJSText(ctx *core.FileContext) []string {
	return core.FileShared(ctx, jsMaskKey{maskLiterals: false}, func() []string { return core.MaskJS(ctx.Lines, false) })
}

// MaskJSComments is MaskJSCommentsAndStrings for rules that read literal text
// (env names, selectors, URLs): only comments are blanked, literals stay.
func MaskJSComments(lines []string) []string {
	return core.MaskJS(lines, false)
}

// IsStandardLibraryPath reports whether an import path names a standard
// library package: its first element has no dot, unlike a module host.
func IsStandardLibraryPath(pkgPath string) bool {
	first, _, _ := strings.Cut(pkgPath, "/")
	return !strings.Contains(first, ".")
}

// IsStandInDataPath reports a file of stand-in data nobody keeps in step with the
// program: a mock (__mocks__/, mocks/), a stub, a storybook story or a static
// design prototype (prototype/, prototypes/).
func IsStandInDataPath(relPath string) bool {
	path := "/" + strings.ToLower(filepath.ToSlash(relPath))
	for _, dir := range []string{"/__mocks__/", "/mocks/", "/stubs/", "/prototype/", "/prototypes/"} {
		if strings.Contains(path, dir) {
			return true
		}
	}
	return strings.Contains(path, ".stories.")
}
