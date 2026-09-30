package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewBoolCompareRule())
}

// BoolCompareRule detects redundant boolean comparisons
type BoolCompareRule struct {
	*rules.BaseRule
}

// NewBoolCompareRule creates the rule
func NewBoolCompareRule() *BoolCompareRule {
	return &BoolCompareRule{
		BaseRule: rules.NewBaseRule(
			"bool-compare",
			"patterns",
			"Detects redundant boolean comparisons (x == true, x == false)",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *BoolCompareRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *BoolCompareRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; an operand declared anywhere in the
// project is judged by its declared type.
func (r *BoolCompareRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks for redundant boolean comparisons. info is nil for a file
// without type information.
func (r *BoolCompareRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var typeInferrer *TypeInferrer
	if info == nil {
		typeInferrer = NewTypeInferrer(ctx.GoAST)
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		binary, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}

		// Check for == true, == false, != true, != false
		if binary.Op != token.EQL && binary.Op != token.NEQ {
			return true
		}

		var boolLit *ast.Ident
		var other ast.Expr

		// Check right side for true/false
		if ident, ok := binary.Y.(*ast.Ident); ok {
			if ident.Name == "true" || ident.Name == "false" {
				boolLit = ident
				other = binary.X
			}
		}

		// Check left side for true/false
		if boolLit == nil {
			if ident, ok := binary.X.(*ast.Ident); ok {
				if ident.Name == "true" || ident.Name == "false" {
					boolLit = ident
					other = binary.Y
				}
			}
		}

		if boolLit == nil {
			return true
		}
		// A package may declare its own true or false; only the predeclared
		// constants make the comparison redundant.
		if info != nil && info.Uses[boolLit] != types.Universe.Lookup(boolLit.Name) {
			return true
		}

		// Comparing a non-bool operand against true/false is not redundant:
		// a value read out of a map[string]any cannot be used as a condition
		// on its own.
		if !r.isKnownBool(other, info, typeInferrer) {
			return true
		}

		line := ctx.LineFor(binary)
		var suggestion string

		if binary.Op == token.EQL {
			if boolLit.Name == "true" {
				suggestion = "Use 'x' instead of 'x == true'"
			} else {
				suggestion = "Use '!x' instead of 'x == false'"
			}
		} else { // NEQ
			if boolLit.Name == "true" {
				suggestion = "Use '!x' instead of 'x != true'"
			} else {
				suggestion = "Use 'x' instead of 'x != false'"
			}
		}

		v := r.CreateViolation(ctx.RelPath, line, "Redundant boolean comparison")
		// The column pins the comparison, so the fixer rewrites this one and
		// not another on the same line.
		v.WithColumn(ctx.PositionFor(binary).Column)
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion(suggestion)
		v.WithContext("pattern", "bool_compare")
		v.WithContext("compared_to", boolLit.Name)

		violations = append(violations, v)

		return true
	})

	return violations
}

// isKnownBool reports whether the operand compared against true/false is
// itself a boolean. With type information its type answers. Without it only
// what the file declares counts: a name or field the file does not declare, a
// call or an index expression (a map[string]any lookup) is unknown, and
// rewriting a comparison on an unknown operand may not compile.
func (r *BoolCompareRule) isKnownBool(expr ast.Expr, info *types.Info, inferrer *TypeInferrer) bool {
	if info != nil {
		return isBooleanType(info.TypeOf(expr))
	}
	switch e := expr.(type) {
	case *ast.Ident:
		typ, ok := inferrer.GetType(e.Name)
		return ok && typ.TypeName == "bool"
	case *ast.SelectorExpr:
		typ, ok := inferrer.GetType(e.Sel.Name)
		return ok && typ.TypeName == "bool"
	case *ast.BinaryExpr:
		// Comparisons and logical operators always produce a bool.
		return true
	case *ast.UnaryExpr:
		return e.Op == token.NOT
	case *ast.ParenExpr:
		return r.isKnownBool(e.X, nil, inferrer)
	}
	return false
}

// isBooleanType reports whether t is a boolean type: bool, an untyped boolean
// constant or a named type whose underlying type is bool.
func isBooleanType(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsBoolean != 0
}
