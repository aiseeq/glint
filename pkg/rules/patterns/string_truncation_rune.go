package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewStringTruncationSplitsRuneRule())
}

// StringTruncationSplitsRuneRule detects a string cut to a length limit by a
// byte slice:
//
//	func truncate(s string, maxLen int) string {
//	    if len(s) <= maxLen { return s }
//	    return s[:maxLen]
//	}
//
// len counts bytes: a limit that falls inside a multi-byte character cuts
// it in half. The result is not valid UTF-8 - PostgreSQL refuses it in a
// text column, JSON encoders replace it, a UI shows a broken glyph. Cut at a
// rune boundary (utf8.RuneStart, or []rune for a limit in characters).
// Reported only where the function compares len of the same string with the
// same limit, and the limit is one for text: named as a limit (maxLen, n,
// errorDetailLimit) or a literal preview of 32 bytes and more, or any cut
// followed by an ellipsis. Not reported: a cut at a found position ([:i]), a
// prefix test (s[:len(p)] == p), a short literal cut of a date or an id
// ([:10]), a value named as an id, a hash or a token, and a function that
// already looks at runes (utf8, []rune).
type StringTruncationSplitsRuneRule struct {
	*rules.BaseRule
}

// NewStringTruncationSplitsRuneRule creates the rule
func NewStringTruncationSplitsRuneRule() *StringTruncationSplitsRuneRule {
	return &StringTruncationSplitsRuneRule{BaseRule: rules.NewBaseRule(
		"string-truncation-splits-rune",
		"patterns",
		"Detects a string cut to a length limit with s[:n] after len(s) is compared with n — the cut can split a multi-byte character and leave invalid UTF-8",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: whether the sliced value is a string decides.
func (r *StringTruncationSplitsRuneRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *StringTruncationSplitsRuneRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the byte truncations of strings to a limit.
func (r *StringTruncationSplitsRuneRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if file.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || looksAtRunes(fn.Body, info) {
				continue
			}
			limits := lengthLimits(fn.Body, info)
			if len(limits) == 0 {
				continue
			}
			compared, ellipsized := sliceUses(fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				slice, ok := n.(*ast.SliceExpr)
				if !ok || slice.High == nil || slice.Slice3 || !zeroOrAbsent(slice.Low) || !isStringType(info.TypeOf(slice.X)) {
					return true
				}
				limit := limitOf(slice.High)
				if !limits[limitKey(slice.X, limit)] || compared[slice] || machineText(slice.X) ||
					!textLimit(limit, ellipsized[slice]) {
					return true
				}
				line := file.LineFor(slice)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line, "String cut to a byte limit with "+types.ExprString(slice)+" — the cut can split a multi-byte character, and the result is not valid UTF-8")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Step back to a rune boundary (for n > 0 && !utf8.RuneStart(s[n]) { n-- }), or cut []rune(s) for a limit in characters")
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

// sliceUses returns the slices a function compares (a prefix test, not a
// cut) and the ones it ends with an ellipsis (a preview of text).
func sliceUses(body *ast.BlockStmt) (compared, ellipsized map[*ast.SliceExpr]bool) {
	compared = make(map[*ast.SliceExpr]bool)
	ellipsized = make(map[*ast.SliceExpr]bool)
	mark := func(set map[*ast.SliceExpr]bool, exprs ...ast.Expr) {
		for _, expr := range exprs {
			if slice, ok := ast.Unparen(expr).(*ast.SliceExpr); ok {
				set[slice] = true
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			switch node.Op {
			case token.EQL, token.NEQ:
				mark(compared, node.X, node.Y)
			case token.ADD:
				if text, ok := literalText(node.Y); ok && (strings.HasPrefix(text, "...") || strings.HasPrefix(text, "…")) {
					mark(ellipsized, node.X)
				}
			}
		case *ast.CallExpr:
			switch calledName(node) {
			case "EqualFold", "HasPrefix", "HasSuffix", "Compare", "Contains":
				mark(compared, node.Args...)
			}
		}
		return true
	})
	return compared, ellipsized
}

// limitName names a length limit: maxLen, limit, n, previewSize.
var limitName = regexp.MustCompile(`(?i)^n$|max|limit|cap|size|width|length|len$`)

// machineName names a value of ASCII by construction: an id, a hash, a token.
var machineName = regexp.MustCompile(`(?i)token|hash|uuid|sha\d*$|hex|secret|signature|^id$|[a-z]ids?$|key$`)

// textLimit reports a bound that is a length limit for text: a variable or
// constant named as a limit, or a number of characters a person reads (a
// preview of 32 bytes and more, or any cut ending in an ellipsis). A short
// literal cut ([:10], [:8]) takes a date or an id prefix, a position from
// a search ([:i], [:end]) is not a limit, and len(prefix) matches a prefix.
func textLimit(limit ast.Expr, ellipsized bool) bool {
	switch bound := limit.(type) {
	case *ast.Ident:
		return limitName.MatchString(bound.Name)
	case *ast.SelectorExpr:
		return limitName.MatchString(bound.Sel.Name)
	case *ast.BasicLit:
		n, err := strconv.Atoi(bound.Value)
		return err == nil && (ellipsized || n >= minTextPreview)
	}
	return false
}

// minTextPreview is the shortest literal cut taken for a text preview.
const minTextPreview = 32

// machineText reports a sliced value named as an id, a hash or a token.
func machineText(expr ast.Expr) bool {
	switch value := expr.(type) {
	case *ast.Ident:
		return machineName.MatchString(value.Name)
	case *ast.SelectorExpr:
		return machineName.MatchString(value.Sel.Name)
	}
	return false
}

// lengthLimits returns the (string, limit) pairs a function compares:
// len(s) <= maxLen, limit < len(r.Description).
func lengthLimits(body *ast.BlockStmt, info *types.Info) map[string]bool {
	limits := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		cmp, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		switch cmp.Op {
		case token.LSS, token.LEQ, token.GTR, token.GEQ:
		default:
			return true
		}
		if s, ok := lenOf(cmp.X, info); ok {
			limits[limitKey(s, cmp.Y)] = true
		}
		if s, ok := lenOf(cmp.Y, info); ok {
			limits[limitKey(s, cmp.X)] = true
		}
		return true
	})
	return limits
}

// lenOf returns s of a builtin call len(s) on a string.
func lenOf(expr ast.Expr, info *types.Info) (ast.Expr, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil, false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "len" {
		return nil, false
	}
	if _, builtin := info.Uses[ident].(*types.Builtin); !builtin || !isStringType(info.TypeOf(call.Args[0])) {
		return nil, false
	}
	return call.Args[0], true
}

// limitOf strips a constant reserve from a slice bound: s[:maxLen-3] + "..."
// is cut at the limit maxLen.
func limitOf(high ast.Expr) ast.Expr {
	if bin, ok := high.(*ast.BinaryExpr); ok && bin.Op == token.SUB {
		if _, ok := bin.Y.(*ast.BasicLit); ok {
			return bin.X
		}
	}
	return high
}

func limitKey(s, limit ast.Expr) string {
	return types.ExprString(s) + "\x00" + types.ExprString(limit)
}

func zeroOrAbsent(low ast.Expr) bool {
	if low == nil {
		return true
	}
	lit, ok := low.(*ast.BasicLit)
	return ok && lit.Value == "0"
}

// looksAtRunes reports a function that already handles characters: it uses
// unicode/utf8 or converts to []rune.
func looksAtRunes(body *ast.BlockStmt, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if ident, ok := node.X.(*ast.Ident); ok {
				if pkg, ok := info.Uses[ident].(*types.PkgName); ok && pkg.Imported().Path() == "unicode/utf8" {
					found = true
				}
			}
		case *ast.CallExpr:
			if slice, ok := info.TypeOf(node.Fun).(*types.Slice); ok {
				if basic, ok := slice.Elem().(*types.Basic); ok && basic.Kind() == types.Int32 {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
