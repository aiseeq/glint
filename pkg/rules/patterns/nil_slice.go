package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ast/astutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNilSliceRule())
}

// NilSliceRule detects nil slice comparisons and returns
type NilSliceRule struct {
	*rules.BaseRule
}

// NewNilSliceRule creates the rule
func NewNilSliceRule() *NilSliceRule {
	return &NilSliceRule{
		BaseRule: rules.NewBaseRule(
			"nil-slice",
			"patterns",
			"Detects nil slice comparisons (use len(s) == 0 instead)",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *NilSliceRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *NilSliceRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; a variable declared anywhere in the
// project is judged by its declared type and declaration.
func (r *NilSliceRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, ctx)
	})
}

// analyze checks for nil slice comparisons. info and project are nil for a
// file without type information.
func (r *NilSliceRule) analyze(ctx *core.FileContext, info *types.Info, project *core.GoProjectContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	isSlice := func(ident *ast.Ident) bool { return r.isStatedSlice(ctx, info, project, ident) }
	if info == nil {
		typeInferrer := NewTypeInferrer(ctx.GoAST)
		isSlice = func(ident *ast.Ident) bool {
			// Skip any/interface{} types - nil check is correct for them
			if typeInferrer.IsAny(ident.Name) || r.looksLikeAnyByName(ident.Name) {
				return false
			}
			return r.isSliceVar(ident.Name, typeInferrer)
		}
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		binary, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}

		// Check for == nil or != nil
		if binary.Op != token.EQL && binary.Op != token.NEQ {
			return true
		}

		// Check if one side is nil
		var other ast.Expr
		isNilComparison := false

		if ident, ok := binary.Y.(*ast.Ident); ok && ident.Name == "nil" {
			other = binary.X
			isNilComparison = true
		} else if ident, ok := binary.X.(*ast.Ident); ok && ident.Name == "nil" {
			other = binary.Y
			isNilComparison = true
		}

		if !isNilComparison {
			return true
		}

		// Only a plain variable: a field keeps its nil semantics.
		ident, ok := other.(*ast.Ident)
		if !ok {
			return true
		}
		varName := ident.Name

		if r.hasIntentionalNilSemantics(varName) {
			return true
		}
		if !isSlice(ident) {
			return true
		}

		line := ctx.LineFor(binary)
		var suggestion string
		if binary.Op == token.EQL {
			suggestion = "Use 'len(" + varName + ") == 0' instead of '" + varName + " == nil'"
		} else {
			suggestion = "Use 'len(" + varName + ") > 0' instead of '" + varName + " != nil'"
		}

		v := r.CreateViolation(ctx.RelPath, line, "Nil slice comparison")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion(suggestion)
		v.WithContext("pattern", "nil_slice_compare")
		v.WithContext("variable", varName)

		violations = append(violations, v)

		return true
	})

	return violations
}

// isStatedSlice reports whether ident is a slice variable whose declaration
// says so: a parameter or variable declared with its type, or one initialized
// from a composite literal, make or append. A slice obtained from a call
// keeps the nil contract of the function that produced it (a regexp
// submatch is nil when nothing matched) and is left alone, as the untyped
// path leaves it.
func (r *NilSliceRule) isStatedSlice(ctx *core.FileContext, info *types.Info, project *core.GoProjectContext, ident *ast.Ident) bool {
	obj, ok := info.Uses[ident].(*types.Var)
	if !ok || obj.Type() == nil {
		return false
	}
	if _, isSlice := obj.Type().Underlying().(*types.Slice); !isSlice {
		return false
	}
	file := ctx.GoAST
	if pos := obj.Pos(); pos < file.FileStart || pos >= file.FileEnd {
		declCtx, err := project.FileForPosition(pos)
		if err != nil || declCtx.GoAST == nil {
			return false // declared outside the analyzed files
		}
		file = declCtx.GoAST
	}
	return declarationStatesSlice(file, obj.Pos())
}

// declarationStatesSlice classifies the declaration of the variable defined at
// pos in file.
func declarationStatesSlice(file *ast.File, pos token.Pos) bool {
	path, _ := astutil.PathEnclosingInterval(file, pos, pos)
	if len(path) < 2 {
		return false
	}
	name, ok := path[0].(*ast.Ident)
	if !ok || name.Pos() != pos {
		return false
	}
	switch decl := path[1].(type) {
	case *ast.Field:
		_, variadic := decl.Type.(*ast.Ellipsis)
		return !variadic
	case *ast.ValueSpec:
		if decl.Type != nil {
			return true
		}
		if len(decl.Values) != len(decl.Names) {
			return false
		}
		for i, declared := range decl.Names {
			if declared == name {
				return initializesSlice(decl.Values[i])
			}
		}
	case *ast.AssignStmt:
		if len(decl.Lhs) != len(decl.Rhs) {
			return false
		}
		for i, lhs := range decl.Lhs {
			if lhs == name {
				return initializesSlice(decl.Rhs[i])
			}
		}
	}
	return false
}

// initializesSlice reports whether expr builds the slice in place rather than
// receiving it from a call.
func initializesSlice(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.CompositeLit:
		return true
	case *ast.CallExpr:
		fun, ok := e.Fun.(*ast.Ident)
		return ok && (fun.Name == "make" || fun.Name == "append")
	}
	return false
}

func (r *NilSliceRule) isSliceVar(name string, inferrer *TypeInferrer) bool {
	// The inferrer is file-level, not scope-aware: a name it binds to
	// several types reports no type at all.
	if info, ok := inferrer.GetType(name); ok {
		// Double-check: if also marked as any, it's not a slice
		if info.TypeName == "any" || info.TypeName == "interface{}" {
			return false
		}
		return info.IsSlice
	}

	// The file either declares this name from an expression whose type
	// could not be resolved (an assignment from a selector or an unknown
	// call), or does not declare it at all. Guessing by name flagged
	// pointers such as `results := fn.Type.Results`, values with a
	// documented nil contract such as regexp submatches, and pointers
	// declared in another file of the package.
	return false
}

// looksLikeAnyByName checks if variable name suggests it's an any/interface{} type
func (r *NilSliceRule) looksLikeAnyByName(name string) bool {
	// Common parameter names for any/interface{} types
	anyPatterns := map[string]bool{
		"data":   true, // func Process(data any)
		"v":      true, // func Marshal(v any)
		"value":  true, // func Set(value any)
		"val":    true, // func Store(val any)
		"obj":    true, // func Clone(obj any)
		"input":  true, // func Handle(input any)
		"arg":    true, // func Call(arg any)
		"param":  true, // func Invoke(param any)
		"target": true, // func Copy(target any)
		"src":    true, // func Convert(src any)
		"dst":    true, // func Convert(dst any)
		"x":      true, // func Dump(x any)
		"i":      true, // interface{} receivers
	}
	return anyPatterns[name]
}

func (r *NilSliceRule) hasIntentionalNilSemantics(name string) bool {
	return name == "options" || strings.HasSuffix(name, "IDs")
}
