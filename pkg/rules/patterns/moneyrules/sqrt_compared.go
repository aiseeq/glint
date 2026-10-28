package moneyrules

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewSqrtComparedToThresholdRule())
}

// NewSqrtComparedToThresholdRule creates sqrt-compared-to-threshold: in a
// loop or a function marked //glint:hot, math.Sqrt or math.Hypot is taken
// only to be compared - an operand of <, <=, >, >= - or to keep the smaller
// or larger of two distances (x = math.Min(x, math.Hypot(...))). Comparing
// squares answers the same question without the root, and Hypot costs more
// than Sqrt:
//
//	if math.Hypot(b.X-a.X, b.Y-a.Y) <= r { ... }
//	dx, dy := b.X-a.X, b.Y-a.Y
//	if dx*dx+dy*dy <= r*r { ... }
//
// The rewrite is not always bit-exact: on the boundary the last bit can
// differ, and a negative r, NaN or an overflowing square behave differently,
// so the suggestion asks to compare the output before and after. A root
// kept in a variable is used beyond the comparison and is not reported.
func NewSqrtComparedToThresholdRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"sqrt-compared-to-threshold",
			"patterns",
			"Detects math.Sqrt or math.Hypot in a loop or a //glint:hot function taken only to be compared or to keep the minimum or maximum — compare squares (dx*dx+dy*dy <= r*r) and take one root at the end",
			core.SeverityLow,
		),
		Suggestion: "Compare squares (dx*dx+dy*dy <= r*r) or keep the minimum of squares and take one root at the end; check the output is the same before and after — the boundary, a negative threshold and NaN behave differently",
	}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		hot := patternkit.HasDirective(fn.Doc, patternkit.HotFunctionDirective)
		loops := patternkit.LoopBodies(fn.Body)
		var findings []patternkit.FuncFinding
		report := func(node ast.Node, root string) {
			if hot || patternkit.InsideNodes(loops, node) {
				findings = append(findings, patternkit.FuncFinding{Node: node, Message: "math." + root + " is taken only to be compared — compare squares instead"})
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BinaryExpr:
				switch node.Op {
				case token.LSS, token.LEQ, token.GTR, token.GEQ:
					if root := rootCall(scope.Info, node.X); root != "" {
						report(node, root)
					} else if root := rootCall(scope.Info, node.Y); root != "" {
						report(node, root)
					}
				}
			case *ast.AssignStmt:
				if root := extremeOfRoot(scope.Info, node); root != "" {
					report(node, root)
				}
			}
			return true
		})
		return findings
	}
	return r
}

// rootCall names the root function an expression calls: "Sqrt", "Hypot", or
// "" for any other expression.
func rootCall(info *types.Info, expr ast.Expr) string {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return ""
	}
	if name, isMath := patternkit.PackageFuncName(nil, info, call, "math"); isMath && (name == "Sqrt" || name == "Hypot") {
		return name
	}
	return ""
}

// extremeOfRoot names the root of x = math.Min(x, root(...)) and its kin
// (math.Max, min, max): the extreme of roots is the root of the extreme of
// squares.
func extremeOfRoot(info *types.Info, assign *ast.AssignStmt) string {
	if assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return ""
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return ""
	}
	name, isMath := patternkit.PackageFuncName(nil, info, call, "math")
	builtin := patternkit.BuiltinCallName(info, call)
	extreme := (isMath && (name == "Min" || name == "Max")) || builtin == "min" || builtin == "max"
	if !extreme {
		return ""
	}
	target := types.ExprString(assign.Lhs[0])
	for i, arg := range call.Args {
		if types.ExprString(ast.Unparen(arg)) != target {
			continue
		}
		if root := rootCall(info, call.Args[1-i]); root != "" {
			return root
		}
	}
	return ""
}
