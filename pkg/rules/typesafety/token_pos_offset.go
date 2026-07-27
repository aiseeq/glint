package typesafety

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
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
	if ctx == nil {
		return nil, errors.New("token pos offset: nil Go project context")
	}

	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("token pos offset: package has no typed syntax")
		}
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			violations = append(violations, r.analyzeFile(fileCtx, pkg.Package.TypesInfo)...)
		}
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

func (r *TokenPosOffsetRule) analyzeFile(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
		conversion, ok := offsetArithmeticOnPos(n, info)
		if !ok {
			return true
		}
		line := fileCtx.LineFor(conversion)
		v := r.CreateViolation(fileCtx.RelPath, line,
			"token.Pos converted to int: it is an offset into the file set, not into this file, so the arithmetic is wrong for every file but the first")
		v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
		v.WithSuggestion("Resolve the position through the file set instead: fset.Position(pos).Line and .Column")
		v.WithContext("pattern", "token_pos_offset")
		violations = append(violations, v)
		return true
	})

	return violations
}

// offsetArithmeticOnPos returns the conversion of a token.Pos that is being used
// as a number: shifted by an offset, or used to index into content. Converting a
// position to use it as a map key or to print it is not this rule's business —
// the value stays an opaque identifier there.
func offsetArithmeticOnPos(n ast.Node, info *types.Info) (*ast.CallExpr, bool) {
	switch node := n.(type) {
	case *ast.BinaryExpr:
		if node.Op != token.ADD && node.Op != token.SUB {
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
		return intConversionOfPos(node.Index, info)
	case *ast.SliceExpr:
		for _, bound := range []ast.Expr{node.Low, node.High, node.Max} {
			if bound == nil {
				continue
			}
			if call, ok := intConversionOfPos(bound, info); ok {
				return call, true
			}
		}
	}
	return nil, false
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
