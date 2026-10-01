package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode/utf8"

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
					!textLimit(limit, ellipsized[slice]) || asciiBefore(file.GoAST, fn.Body, slice, info) {
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

// asciiBefore reports a sliced variable that holds ASCII only at the cut: a
// regexp removed every character outside a set of ASCII characters, and the
// steps after it (ASCII replacements, case changes, trims) kept it ASCII. Each
// byte of such a string is a whole character.
func asciiBefore(file *ast.File, body *ast.BlockStmt, slice *ast.SliceExpr, info *types.Info) bool {
	return asciiValue(file, body, slice.X, slice.Pos(), info, maxASCIITrace)
}

// maxASCIITrace bounds the assignments followed back from a cut.
const maxASCIITrace = 8

// asciiValue reports an expression, evaluated at pos, whose value is ASCII.
func asciiValue(file *ast.File, body *ast.BlockStmt, expr ast.Expr, pos token.Pos, info *types.Info, depth int) bool {
	if depth == 0 {
		return false
	}
	switch value := ast.Unparen(expr).(type) {
	case *ast.Ident:
		rhs, at, ok := lastAssignment(body, info.ObjectOf(value), pos, info)
		return ok && asciiValue(file, body, rhs, at, info, depth-1)
	case *ast.CallExpr:
		return asciiCall(file, body, value, info, depth)
	}
	return false
}

// asciiCall reports a call whose result is ASCII: a regexp replacement that
// removes non-ASCII or replaces with ASCII in ASCII input, or a strings
// function that keeps ASCII input ASCII.
func asciiCall(file *ast.File, body *ast.BlockStmt, call *ast.CallExpr, info *types.Info, depth int) bool {
	if len(call.Args) == 0 {
		return false
	}
	input := func() bool { return asciiValue(file, body, call.Args[0], call.Pos(), info, depth-1) }
	if isPackageFuncCall(file, info, call, "strings", "ToLower", "ToUpper", "TrimSpace", "Trim", "TrimLeft", "TrimRight", "TrimPrefix", "TrimSuffix") {
		return input()
	}
	if isPackageFuncCall(file, info, call, "strings", "ReplaceAll", "Replace") {
		return len(call.Args) >= 3 && asciiLiteral(call.Args[2]) && input()
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) != 2 || (sel.Sel.Name != "ReplaceAllString" && sel.Sel.Name != "ReplaceAllLiteralString") || !asciiLiteral(call.Args[1]) {
		return false
	}
	pattern, ok := compiledPattern(file, sel.X, info)
	return ok && (removesNonASCII(pattern) || input())
}

// lastAssignment returns the value last assigned to obj by a statement that
// ends before pos, and where that statement starts.
func lastAssignment(body *ast.BlockStmt, obj types.Object, pos token.Pos, info *types.Info) (ast.Expr, token.Pos, bool) {
	if obj == nil {
		return nil, token.NoPos, false
	}
	var last ast.Expr
	at := token.NoPos
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.End() > pos || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && info.ObjectOf(ident) == obj {
				last, at = assign.Rhs[i], assign.Pos()
			}
		}
		return true
	})
	return last, at, last != nil
}

// compiledPattern returns the parsed pattern of regexp.MustCompile(<literal>),
// written in place or as the initializer of a package variable of the file.
// A pattern that does not parse panics at start-up and proves nothing here.
func compiledPattern(file *ast.File, expr ast.Expr, info *types.Info) (*syntax.Regexp, bool) {
	if ident, ok := expr.(*ast.Ident); ok {
		init, found := packageVarInit(file, info.ObjectOf(ident), info)
		if !found {
			return nil, false
		}
		expr = init
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !isPackageFuncCall(file, info, call, "regexp", "MustCompile", "MustCompilePOSIX") {
		return nil, false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return nil, false
	}
	pattern, ok := goStringLiteral(lit)
	if !ok {
		return nil, false
	}
	re, err := syntax.Parse(pattern, syntax.Perl)
	return re, err == nil
}

// packageVarInit returns the initializer of a package variable declared in file.
func packageVarInit(file *ast.File, obj types.Object, info *types.Info) (ast.Expr, bool) {
	if obj == nil {
		return nil, false
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Values) != len(vs.Names) {
				continue
			}
			for i, name := range vs.Names {
				if info.Defs[name] == obj {
					return vs.Values[i], true
				}
			}
		}
	}
	return nil, false
}

// removesNonASCII reports a pattern matching one character class (possibly
// repeated) that takes in every character from U+0080 up: what it leaves
// behind is ASCII.
func removesNonASCII(re *syntax.Regexp) bool {
	re = re.Simplify()
	for (re.Op == syntax.OpPlus || re.Op == syntax.OpStar || re.Op == syntax.OpQuest || re.Op == syntax.OpRepeat) && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpCharClass {
		return false
	}
	next := rune(utf8.RuneSelf)
	for i := 0; i+1 < len(re.Rune); i += 2 {
		lo, hi := re.Rune[i], re.Rune[i+1]
		if hi < next {
			continue
		}
		if lo > next {
			return false
		}
		next = hi + 1
	}
	return next > utf8.MaxRune
}

// asciiLiteral reports a string literal of ASCII characters.
func asciiLiteral(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return false
	}
	text, ok := goStringLiteral(lit)
	if !ok {
		return false
	}
	for i := 0; i < len(text); i++ {
		if text[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
