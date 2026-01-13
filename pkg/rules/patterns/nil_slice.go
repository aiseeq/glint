package patterns

import (
	"go/ast"
	"go/token"

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

// AnalyzeFile checks for nil slice comparisons
func (r *NilSliceRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	// Build type information from declarations
	typeInferrer := NewTypeInferrer(ctx.GoAST)

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

		// Get variable name and check if it's a slice
		varName := r.getVarName(other)
		if varName == "" {
			return true
		}

		// Skip any/interface{} types - nil check is correct for them
		// Check both type inference and common naming patterns
		if typeInferrer.IsAny(varName) || r.looksLikeAnyByName(varName) {
			return true
		}

		// Use type inference to check if it's a slice
		if !r.isSliceVar(varName, typeInferrer) {
			return true
		}

		line := r.getLineFromNode(ctx, binary)
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

func (r *NilSliceRule) getVarName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		// For x.Field, return the field name for heuristic matching
		return e.Sel.Name
	}
	return ""
}

func (r *NilSliceRule) isSliceVar(name string, inferrer *TypeInferrer) bool {
	// First, check type inference for slices
	// Note: type inferrer is file-level, not scope-aware
	// So we rely primarily on heuristics for accuracy
	if inferrer.IsSlice(name) {
		// Double-check: if also marked as any, it's not a slice
		if inferrer.IsAny(name) {
			return false
		}
		return true
	}

	// Fallback to heuristic for cases type inference can't catch
	// (e.g., struct fields from other packages)
	return r.looksLikeSliceByName(name)
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

func (r *NilSliceRule) looksLikeSliceByName(name string) bool {
	// Conservative list of names that are almost always slices
	slicePatterns := map[string]bool{
		"items":      true,
		"results":    true,
		"records":    true,
		"rows":       true,
		"elements":   true,
		"values":     true,
		"entries":    true,
		"files":      true,
		"users":      true,
		"violations": true,
		"args":       true,
		"names":      true,
		"ids":        true,
		"keys":       true,
		"paths":      true,
		"lines":      true,
		"tokens":     true,
		"parts":      true,
		"chunks":     true,
		"matches":    true,
		"children":   true,
		"nodes":      true,
	}

	return slicePatterns[name]
}

func (r *NilSliceRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
	if node == nil {
		return 1
	}

	pos := node.Pos()
	if pos == 0 {
		return 1
	}

	offset := int(pos) - 1
	if offset < 0 || offset >= len(ctx.Content) {
		return 1
	}

	line := 1
	for i := 0; i < offset && i < len(ctx.Content); i++ {
		if ctx.Content[i] == '\n' {
			line++
		}
	}
	return line
}
