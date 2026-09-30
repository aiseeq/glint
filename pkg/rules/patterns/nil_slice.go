package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNilSliceRule())
}

// NilSliceRule detects nil slice comparisons and returns. A nil check that
// tells nil from empty on purpose is left alone: the slice is also compared
// by length, callers pass a literal nil for it, or it is a variable left nil
// until one path sets it to a slice it did not build.
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
	return r.analyze(ctx, nil, nil, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *NilSliceRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; a variable declared anywhere in the
// project is judged by its declared type and declaration.
func (r *NilSliceRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	nilArgs := parametersPassedNil(ctx)
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, ctx, nilArgs)
	})
}

// parametersPassedNil returns the parameters some call of the project sets
// to a literal nil: for them nil is part of the function's contract, "none
// given", and not an empty slice mixed up with a missing one.
func parametersPassedNil(ctx *core.GoProjectContext) map[types.Object]bool {
	passed := map[types.Object]bool{}
	if ctx == nil {
		return passed
	}
	forwarded := map[types.Object][]types.Object{}
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		info := pkgCtx.Package.TypesInfo
		for _, file := range pkgCtx.Package.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee, ok := typeutil.Callee(info, call).(*types.Func)
				if !ok {
					return true
				}
				signature, ok := callee.Origin().Type().(*types.Signature)
				if !ok {
					return true
				}
				for i, arg := range call.Args {
					if i >= signature.Params().Len() || (signature.Variadic() && i >= signature.Params().Len()-1) {
						break
					}
					ident, ok := ast.Unparen(arg).(*ast.Ident)
					if !ok {
						continue
					}
					switch used := info.Uses[ident].(type) {
					case *types.Nil:
						passed[signature.Params().At(i)] = true
					case *types.Var:
						forwarded[used] = append(forwarded[used], signature.Params().At(i))
					}
				}
				return true
			})
		}
	}
	// A parameter handed on unchanged to another function brings its nil
	// along: the helper behind a wrapper gets the same "none given".
	queue := make([]types.Object, 0, len(passed))
	for param := range passed {
		queue = append(queue, param)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, next := range forwarded[current] {
			if !passed[next] {
				passed[next] = true
				queue = append(queue, next)
			}
		}
	}
	return passed
}

// analyze checks for nil slice comparisons. info and project are nil for a
// file without type information; nilArgs are the parameters callers set to
// nil.
func (r *NilSliceRule) analyze(ctx *core.FileContext, info *types.Info, project *core.GoProjectContext, nilArgs map[types.Object]bool) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	// intentionalNil reports a nil check that tells nil apart from empty on
	// purpose. With types the evidence is the code itself: the same slice is
	// also compared by length. Without types the name is all there is.
	var isSlice func(ident *ast.Ident) bool
	var intentionalNil func(ident *ast.Ident) bool
	if info != nil {
		emptinessChecked := lengthComparedObjects(ctx.GoAST, info)
		isSlice = func(ident *ast.Ident) bool { return r.isStatedSlice(ctx, info, project, ident) }
		intentionalNil = func(ident *ast.Ident) bool {
			obj := info.Uses[ident]
			return emptinessChecked[obj] || nilArgs[obj] || r.nilMeansUnset(ctx, info, project, obj)
		}
	} else {
		typeInferrer := NewTypeInferrer(ctx.GoAST)
		isSlice = func(ident *ast.Ident) bool {
			// Skip any/interface{} types - nil check is correct for them
			if typeInferrer.IsAny(ident.Name) || r.looksLikeAnyByName(ident.Name) {
				return false
			}
			return r.isSliceVar(ident.Name, typeInferrer)
		}
		intentionalNil = func(ident *ast.Ident) bool { return r.hasIntentionalNilSemantics(ident.Name) }
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

		if isNilIdent(binary.Y) {
			other = binary.X
			isNilComparison = true
		} else if isNilIdent(binary.X) {
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

		if intentionalNil(ident) {
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

// nilMeansUnset reports a variable declared without a value and set, on some
// path, to a slice it did not build itself: a part of another slice, a call
// result, another variable. Its nil check asks whether that path ran - the
// part it got may be empty. A variable only ever built with append, make or
// a literal is nil exactly when it is empty.
func (r *NilSliceRule) nilMeansUnset(ctx *core.FileContext, info *types.Info, project *core.GoProjectContext, obj types.Object) bool {
	if obj == nil {
		return false
	}
	file := ctx.GoAST
	if pos := obj.Pos(); pos < file.FileStart || pos >= file.FileEnd {
		declCtx, err := project.FileForPosition(pos)
		if err != nil || declCtx.GoAST == nil {
			return false
		}
		file = declCtx.GoAST
	}
	path, _ := astutil.PathEnclosingInterval(file, obj.Pos(), obj.Pos())
	if len(path) < 2 {
		return false
	}
	spec, ok := path[1].(*ast.ValueSpec)
	if !ok || len(spec.Values) != 0 {
		return false
	}
	unset := false
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || unset {
			return !unset
		}
		for i, lhs := range assign.Lhs {
			ident, ok := ast.Unparen(lhs).(*ast.Ident)
			if !ok || info.Uses[ident] != obj {
				continue
			}
			if len(assign.Rhs) != len(assign.Lhs) || !initializesSlice(assign.Rhs[i]) {
				unset = true
			}
		}
		return !unset
	})
	return unset
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

// lengthComparedObjects returns the variables whose length the file compares
// with zero (len(x) == 0, len(x) > 0, len(x) < 1, ...).
func lengthComparedObjects(file *ast.File, info *types.Info) map[types.Object]bool {
	compared := make(map[types.Object]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		binary, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		for _, pair := range [][2]ast.Expr{{binary.X, binary.Y}, {binary.Y, binary.X}} {
			obj := lengthOperandObject(pair[0], info)
			if obj == nil {
				continue
			}
			if lit, ok := ast.Unparen(pair[1]).(*ast.BasicLit); ok && lit.Kind == token.INT && (lit.Value == "0" || lit.Value == "1") {
				compared[obj] = true
			}
		}
		return true
	})
	return compared
}

// lengthOperandObject returns x for len(x) with x a plain variable.
func lengthOperandObject(expr ast.Expr, info *types.Info) types.Object {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil
	}
	fun, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return nil
	}
	if builtin, ok := info.Uses[fun].(*types.Builtin); !ok || builtin.Name() != "len" {
		return nil
	}
	arg, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
	if !ok {
		return nil
	}
	return info.Uses[arg]
}

// hasIntentionalNilSemantics guesses deliberate nil semantics from the name,
// for files without type information only.
func (r *NilSliceRule) hasIntentionalNilSemantics(name string) bool {
	return name == "options" || strings.HasSuffix(name, "IDs")
}
