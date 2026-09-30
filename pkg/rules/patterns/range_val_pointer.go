package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"go/version"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewRangeValPointerRule())
}

// perIterationLoopVarsVersion is the language version from which every loop
// iteration declares its own variables.
const perIterationLoopVarsVersion = "go1.22"

// RangeValPointerRule detects a reference to a range loop variable that
// outlives its iteration in code compiled with the pre-Go 1.22 loop semantics,
// where one variable serves every iteration.
type RangeValPointerRule struct {
	*rules.BaseRule
}

// NewRangeValPointerRule creates the rule
func NewRangeValPointerRule() *RangeValPointerRule {
	return &RangeValPointerRule{
		BaseRule: rules.NewBaseRule(
			"range-val-pointer",
			"patterns",
			"Detects a pointer to a range loop variable (or a goroutine/defer closure over it) that outlives the iteration in files before Go 1.22, where all iterations share one variable",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks one file without type information. The language version
// of such a file is unknown, and unknown is not old: the rule stays silent.
func (r *RangeValPointerRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *RangeValPointerRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file whose language version is known.
func (r *RangeValPointerRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

func (r *RangeValPointerRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if info == nil || !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	fileVersion, known := info.FileVersions[ctx.GoAST]
	if !known || !version.IsValid(fileVersion) {
		return nil
	}
	if version.Compare(fileVersion, perIterationLoopVarsVersion) >= 0 {
		return nil
	}

	var violations []*core.Violation
	reported := make(map[int]bool)
	report := func(node ast.Node, name, message, suggestion string) {
		line := ctx.LineFor(node)
		if reported[line] {
			return
		}
		reported[line] = true
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion(suggestion)
		v.WithContext("pattern", "range_val_pointer")
		v.WithContext("variable", name)
		v.WithContext("go_version", fileVersion)
		violations = append(violations, v)
	}

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		rangeStmt, ok := n.(*ast.RangeStmt)
		if !ok || rangeStmt.Tok != token.DEFINE {
			return true
		}
		loopVars := rangeLoopVars(rangeStmt, info)
		if len(loopVars) == 0 {
			return true
		}
		r.checkRangeBody(rangeStmt, loopVars, info, report)
		return true
	})

	return violations
}

// rangeLoopVars returns the variables a `for k, v := range` statement declares.
func rangeLoopVars(rangeStmt *ast.RangeStmt, info *types.Info) map[types.Object]bool {
	vars := make(map[types.Object]bool)
	for _, expr := range []ast.Expr{rangeStmt.Key, rangeStmt.Value} {
		ident, ok := expr.(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		if obj := info.Defs[ident]; obj != nil {
			vars[obj] = true
		}
	}
	return vars
}

func (r *RangeValPointerRule) checkRangeBody(
	rangeStmt *ast.RangeStmt,
	loopVars map[types.Object]bool,
	info *types.Info,
	report func(node ast.Node, name, message, suggestion string),
) {
	var stack []ast.Node
	ast.Inspect(rangeStmt.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		switch node := n.(type) {
		case *ast.UnaryExpr:
			ident, ok := node.X.(*ast.Ident)
			if ok && node.Op == token.AND && loopVars[info.Uses[ident]] &&
				pointerOutlivesIteration(node, stack, rangeStmt, info) {
				report(node, ident.Name,
					"Taking address of range variable '"+ident.Name+"' - all iterations share same address",
					"Create a local copy: copy := "+ident.Name+"; use &copy")
			}
		case *ast.GoStmt:
			if name, ok := closureCapturesLoopVar(node.Call, loopVars, info); ok {
				report(node, name,
					"Goroutine closure captures range variable '"+name+"' - all iterations share it",
					"Pass the variable as an argument: go func("+name+" T) {...}("+name+")")
			}
		case *ast.DeferStmt:
			if name, ok := closureCapturesLoopVar(node.Call, loopVars, info); ok {
				report(node, name,
					"Deferred closure captures range variable '"+name+"' - all iterations share it",
					"Pass the variable as an argument: defer func("+name+" T) {...}("+name+")")
			}
		}
		stack = append(stack, n)
		return true
	})
}

// pointerOutlivesIteration reports whether the address taken by addr is kept
// beyond the current iteration: appended, stored in a variable declared
// outside the loop, returned, sent on a channel or handed to go/defer. A
// pointer passed to an ordinary call (json.Unmarshal(b, &v)) or kept in a
// loop-local variable does not outlive the iteration by itself.
func pointerOutlivesIteration(addr ast.Expr, stack []ast.Node, rangeStmt *ast.RangeStmt, info *types.Info) bool {
	current := ast.Node(addr)
	for i := len(stack) - 1; i >= 0; i-- {
		switch parent := stack[i].(type) {
		case *ast.ParenExpr, *ast.CompositeLit, *ast.KeyValueExpr:
			// The pointer becomes part of a larger value; follow that value.
		case *ast.UnaryExpr:
			if parent.Op != token.AND {
				return false
			}
		case *ast.CallExpr:
			if tv, ok := info.Types[parent.Fun]; ok && tv.IsType() {
				break // a conversion keeps the value
			}
			return isAppendCall(parent, info) && current != parent.Fun && len(parent.Args) > 0 && current != parent.Args[0]
		case *ast.AssignStmt:
			return parent.Tok != token.DEFINE && assignsOutsideLoop(parent, current, rangeStmt, info)
		case *ast.ReturnStmt, *ast.GoStmt, *ast.DeferStmt:
			return true
		case *ast.SendStmt:
			return current == parent.Value
		default:
			return false
		}
		current = stack[i]
	}
	return false
}

func isAppendCall(call *ast.CallExpr, info *types.Info) bool {
	ident, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	builtin, ok := info.Uses[ident].(*types.Builtin)
	return ok && builtin.Name() == "append"
}

// assignsOutsideLoop reports whether rhs is assigned to a location rooted in a
// variable declared outside the range statement.
func assignsOutsideLoop(assign *ast.AssignStmt, rhs ast.Node, rangeStmt *ast.RangeStmt, info *types.Info) bool {
	if len(assign.Lhs) != len(assign.Rhs) {
		return false
	}
	for i, expr := range assign.Rhs {
		if expr != rhs {
			continue
		}
		root := assignmentRoot(assign.Lhs[i])
		if root == nil {
			return false
		}
		obj := info.ObjectOf(root)
		if obj == nil {
			return false
		}
		return obj.Pos() < rangeStmt.Pos() || obj.Pos() >= rangeStmt.End()
	}
	return false
}

// assignmentRoot returns the variable an assignment target is rooted in:
// out for out[i], s for s.field, p for *p.
func assignmentRoot(expr ast.Expr) *ast.Ident {
	for {
		switch e := expr.(type) {
		case *ast.Ident:
			if e.Name == "_" {
				return nil
			}
			return e
		case *ast.SelectorExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.ParenExpr:
			expr = e.X
		default:
			return nil
		}
	}
}

// closureCapturesLoopVar reports a range variable used inside a function
// literal launched by go or defer: the closure runs after the iteration moved
// the shared variable on.
func closureCapturesLoopVar(call *ast.CallExpr, loopVars map[types.Object]bool, info *types.Info) (string, bool) {
	lit, ok := ast.Unparen(call.Fun).(*ast.FuncLit)
	if !ok {
		return "", false
	}
	var name string
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if name != "" {
			return false
		}
		if ident, ok := n.(*ast.Ident); ok && loopVars[info.Uses[ident]] {
			name = ident.Name
		}
		return true
	})
	return name, name != ""
}
