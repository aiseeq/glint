package typesafety

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTokenPosOffsetRule())
}

// TokenPosOffsetRule detects token.Pos values treated as an offset into one
// file's bytes:
//
//	offset := int(node.Pos()) - 1
//	line := 1
//	for i := 0; i < offset; i++ { … }   // counts the wrong lines
//
// A token.Pos is an offset into the whole FileSet, not into the file being
// analyzed. With one file per set the two coincide and the code looks correct;
// as soon as several files share a set — which is what happens once a project is
// type-checked — every position past the first file points somewhere else. The
// failure is silent: no panic, no error, just wrong line numbers.
//
// The fix is always the same: ask the file set, FileSet.Position(pos).Line.
type TokenPosOffsetRule struct {
	*rules.BaseRule
}

// NewTokenPosOffsetRule creates the rule
func NewTokenPosOffsetRule() *TokenPosOffsetRule {
	return &TokenPosOffsetRule{
		BaseRule: rules.NewBaseRule(
			"token-pos-offset",
			"typesafety",
			"Detects token.Pos used as an offset into a file's content instead of being resolved through the FileSet",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile is a no-op: recognizing a token.Pos needs type information.
func (r *TokenPosOffsetRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *TokenPosOffsetRule) RequiresSSA() bool { return false }

// AnalyzeGoProject inspects the analyzed files of every loaded package.
func (r *TokenPosOffsetRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), r.analyzeFile)
}

func (r *TokenPosOffsetRule) analyzeFile(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
		misuse, ok := offsetArithmeticOnPos(n, info)
		if !ok {
			return true
		}
		line := fileCtx.LineFor(misuse)
		message := "token.Pos converted to int: it is an offset into the file set, not into this file, so the arithmetic is wrong for every file but the first"
		if _, converted := misuse.(*ast.CallExpr); !converted {
			message = "token.Pos used as an index into content: it is an offset into the file set, not into this file, so the index is wrong for every file but the first"
		}
		v := r.CreateViolation(fileCtx.RelPath, line, message)
		v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
		v.WithSuggestion("Resolve the position through the file set instead: fset.Position(pos).Line and .Column")
		v.WithContext("pattern", "token_pos_offset")
		violations = append(violations, v)
		return true
	})

	return violations
}

// offsetArithmeticOnPos returns the conversion of a token.Pos that is being used
// as a number - shifted by an offset, or used to index into content - or the
// token.Pos index expression that indexes content without a conversion.
// Converting a position to use it as a map key or to print it is not this
// rule's business: the value stays an opaque identifier there. Neither is the
// difference of two positions (a length, valid in any file set) nor a position
// minus its file's Base (the in-file offset, as token.File.Offset computes it).
func offsetArithmeticOnPos(n ast.Node, info *types.Info) (ast.Node, bool) {
	switch node := n.(type) {
	case *ast.BinaryExpr:
		if node.Op != token.ADD && node.Op != token.SUB {
			return nil, false
		}
		if node.Op == token.SUB && isPosRelativeSubtrahend(node.Y, info) {
			return nil, false
		}
		for _, operand := range []ast.Expr{node.X, node.Y} {
			if call, ok := intConversionOfPos(operand, info); ok {
				return call, true
			}
		}
	case *ast.IndexExpr:
		// Indexing a map by a position uses it as an identifier, which is fine;
		// indexing content by it treats it as an offset, which is the bug.
		if !isIndexableContent(info.TypeOf(node.X)) {
			return nil, false
		}
		return posAsOffset(node.Index, info)
	case *ast.SliceExpr:
		if !isIndexableContent(info.TypeOf(node.X)) {
			return nil, false
		}
		for _, bound := range []ast.Expr{node.Low, node.High, node.Max} {
			if bound == nil {
				continue
			}
			if misuse, ok := posAsOffset(bound, info); ok {
				return misuse, true
			}
		}
	}
	return nil, false
}

// posAsOffset returns an index or slice bound that is a token.Pos taken for an
// offset: an int(pos) conversion, or an expression of type token.Pos itself.
// Arithmetic inside the bound (int(pos)-1) is reported by the BinaryExpr case.
func posAsOffset(expr ast.Expr, info *types.Info) (ast.Node, bool) {
	if call, ok := intConversionOfPos(expr, info); ok {
		return call, true
	}
	if isTokenPos(info.TypeOf(expr)) {
		return expr, true
	}
	return nil, false
}

// isPosRelativeSubtrahend reports whether subtracting the expression from a
// position yields a quantity independent of the file set: another position
// (int(end) - int(pos) is a length) or a file's Base (int(pos) - f.Base() is
// the in-file offset).
func isPosRelativeSubtrahend(expr ast.Expr, info *types.Info) bool {
	expr = ast.Unparen(expr)
	if _, ok := intConversionOfPos(expr, info); ok {
		return true
	}
	if isTokenPos(info.TypeOf(expr)) {
		return true
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Base" {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "go/token" {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	return ok && sig.Recv() != nil
}

// isIndexableContent reports whether the value indexed is a sequence of bytes
// or elements, where the index is an offset.
func isIndexableContent(t types.Type) bool {
	if t == nil {
		return false
	}
	switch underlying := t.Underlying().(type) {
	case *types.Slice, *types.Array:
		return true
	case *types.Basic:
		return underlying.Info()&types.IsString != 0
	case *types.Pointer:
		_, isArray := underlying.Elem().Underlying().(*types.Array)
		return isArray
	}
	return false
}

// intConversionOfPos returns the expression as an int(pos) conversion.
func intConversionOfPos(expr ast.Expr, info *types.Info) (*ast.CallExpr, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || !isIntConversionOfPos(call, info) {
		return nil, false
	}
	return call, true
}

// isIntConversionOfPos reports whether the call converts a token.Pos to an
// integer.
func isIntConversionOfPos(call *ast.CallExpr, info *types.Info) bool {
	if len(call.Args) != 1 {
		return false
	}
	name, ok := call.Fun.(*ast.Ident)
	if !ok || !integerTypeNames[name.Name] {
		return false
	}
	if _, isConversion := info.Uses[name].(*types.TypeName); !isConversion && info.Uses[name] != nil {
		return false
	}
	return isTokenPos(info.TypeOf(call.Args[0]))
}

// integerTypeNames are the conversions that turn a position into a number.
var integerTypeNames = map[string]bool{
	"int": true, "int32": true, "int64": true,
	"uint": true, "uint32": true, "uint64": true,
}

// isTokenPos reports whether the type is go/token.Pos.
func isTokenPos(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "go/token" && named.Obj().Name() == "Pos"
}
