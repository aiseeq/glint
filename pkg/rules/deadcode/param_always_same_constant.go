package deadcode

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewParamAlwaysSameConstantRule())
}

// ParamAlwaysSameConstantRule detects parameters that receive one constant at
// every in-module call and control a branch in their function.
type ParamAlwaysSameConstantRule struct {
	*rules.BaseRule
}

// NewParamAlwaysSameConstantRule creates the rule.
func NewParamAlwaysSameConstantRule() *ParamAlwaysSameConstantRule {
	return &ParamAlwaysSameConstantRule{BaseRule: rules.NewBaseRule(
		"param-always-same-constant",
		"deadcode",
		"Detects parameters that always receive one constant at in-module calls and control a branch",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the rule needs the module-wide call index.
func (r *ParamAlwaysSameConstantRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough.
func (r *ParamAlwaysSameConstantRule) RequiresSSA() bool { return false }

type constantParamCallsKey struct{}

type paramCallIndex struct {
	calls     map[*types.Func][][]constant.Value
	uncertain map[*types.Func]bool
	fixed     *fixedSignatures
}

// AnalyzeGoProject indexes typed calls once across the loaded module, then
// reports declarations in the files selected for this run.
func (r *ParamAlwaysSameConstantRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("param always same constant: nil Go project context")
	}
	index, err := core.SharedLoad(ctx, constantParamCallsKey{}, func() (*paramCallIndex, error) {
		return buildParamCallIndex(ctx)
	})
	if err != nil {
		return nil, err
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyzeFile(fileCtx, info, index)
	})
}

func buildParamCallIndex(ctx *core.GoProjectContext) (*paramCallIndex, error) {
	index := &paramCallIndex{
		calls:     make(map[*types.Func][][]constant.Value),
		uncertain: make(map[*types.Func]bool),
	}
	fixed, err := collectFixedSignatures(ctx)
	if err != nil {
		return nil, err
	}
	index.fixed = fixed
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil || pkg.Package.Types == nil {
			return nil, errors.New("param always same constant: package has no typed syntax")
		}
		info := pkg.Package.TypesInfo
		// The typed load runs with Tests: false, so test calls never vote.
		for _, file := range pkg.Package.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn := calledFunc(call.Fun, info)
				if fn == nil {
					return true
				}
				fn = fn.Origin()
				if call.Ellipsis.IsValid() || isMethodExpression(call.Fun, info) {
					index.uncertain[fn] = true
					return true
				}
				values := make([]constant.Value, len(call.Args))
				for i, arg := range call.Args {
					if constantArgument(arg, info) {
						if tv, ok := info.Types[arg]; ok {
							values[i] = tv.Value
						}
					}
				}
				index.calls[fn] = append(index.calls[fn], values)
				return true
			})
		}
	}
	return index, nil
}

func constantArgument(expr ast.Expr, info *types.Info) bool {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		_, ok := info.Uses[expr].(*types.Const)
		return ok
	case *ast.SelectorExpr:
		_, ok := info.Uses[expr.Sel].(*types.Const)
		return ok
	case *ast.UnaryExpr:
		if expr.Op != token.ADD && expr.Op != token.SUB {
			return false
		}
		_, ok := ast.Unparen(expr.X).(*ast.BasicLit)
		return ok
	default:
		return false
	}
}

func calledFunc(fun ast.Expr, info *types.Info) *types.Func {
	switch expr := ast.Unparen(fun).(type) {
	case *ast.Ident:
		fn, _ := info.Uses[expr].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		fn, _ := info.Uses[expr.Sel].(*types.Func)
		return fn
	case *ast.IndexExpr:
		return calledFunc(expr.X, info)
	case *ast.IndexListExpr:
		return calledFunc(expr.X, info)
	}
	return nil
}

func (r *ParamAlwaysSameConstantRule) analyzeFile(fileCtx *core.FileContext, info *types.Info, index *paramCallIndex) []*core.Violation {
	if info == nil || fileCtx.GoAST == nil || fileCtx.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range fileCtx.GoAST.Decls {
		fnDecl, ok := decl.(*ast.FuncDecl)
		if !ok || fnDecl.Body == nil || fnDecl.Type.Params == nil {
			continue
		}
		fn, ok := info.Defs[fnDecl.Name].(*types.Func)
		if !ok || index.uncertain[fn.Origin()] || index.fixed.signatureIsFixed(fn) || exportedLibraryFunction(fn) {
			continue
		}
		calls := index.calls[fn.Origin()]
		if len(calls) < 2 {
			continue
		}
		paramIndex := 0
		variadicIndex := -1
		if signature, ok := fn.Type().(*types.Signature); ok && signature.Variadic() {
			variadicIndex = signature.Params().Len() - 1
		}
		for _, field := range fnDecl.Type.Params.List {
			if len(field.Names) == 0 {
				paramIndex++
				continue
			}
			for _, name := range field.Names {
				param := info.Defs[name]
				if param == nil || name.Name == "_" || paramIndex == variadicIndex {
					paramIndex++
					continue
				}
				value, ok := sameConstantAt(calls, paramIndex)
				if !ok || paramWritten(fnDecl.Body, param, info) || !controlsBranch(fnDecl.Body, param, value, info) {
					paramIndex++
					continue
				}
				line := fileCtx.LineFor(name)
				constantText := value.ExactString()
				v := r.CreateViolation(fileCtx.RelPath, line, "Parameter "+name.Name+" of "+fn.Name()+" is "+constantText+" at every call — the code for other values never runs")
				v.WithCode(fileCtx.GetLine(line))
				v.WithContext("param", name.Name)
				violations = append(violations, v)
				paramIndex++
			}
		}
	}
	return violations
}

func exportedLibraryFunction(fn *types.Func) bool {
	if !fn.Exported() || fn.Pkg() == nil || fn.Pkg().Name() == "main" {
		return false
	}
	return !strings.Contains("/"+fn.Pkg().Path()+"/", "/internal/")
}

func sameConstantAt(calls [][]constant.Value, param int) (constant.Value, bool) {
	var first constant.Value
	for i, args := range calls {
		if param >= len(args) || args[param] == nil {
			return nil, false
		}
		if i == 0 {
			first = args[param]
			continue
		}
		if !constant.Compare(first, token.EQL, args[param]) {
			return nil, false
		}
	}
	return first, first != nil
}

func isMethodExpression(fun ast.Expr, info *types.Info) bool {
	switch expr := ast.Unparen(fun).(type) {
	case *ast.IndexExpr:
		return isMethodExpression(expr.X, info)
	case *ast.IndexListExpr:
		return isMethodExpression(expr.X, info)
	case *ast.SelectorExpr:
		selection := info.Selections[expr]
		return selection != nil && selection.Kind() == types.MethodExpr
	default:
		return false
	}
}

// paramWritten reports an assignment to the parameter or its address taken:
// the value at the branch is then not the one every caller passes.
func paramWritten(body *ast.BlockStmt, param types.Object, info *types.Info) bool {
	written := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			written = written || slices.ContainsFunc(node.Lhs, func(lhs ast.Expr) bool { return helpers.IsObjectIdent(info, lhs, param) })
		case *ast.IncDecStmt:
			written = written || helpers.IsObjectIdent(info, node.X, param)
		case *ast.UnaryExpr:
			written = written || node.Op == token.AND && helpers.IsObjectIdent(info, node.X, param)
		}
		return !written
	})
	return written
}

func controlsBranch(body *ast.BlockStmt, param types.Object, value constant.Value, info *types.Info) bool {
	controls := false
	ast.Inspect(body, func(n ast.Node) bool {
		if controls {
			return false
		}
		switch stmt := n.(type) {
		case *ast.IfStmt:
			_, beforeKnown := evalCondition(stmt.Cond, param, nil, info)
			_, afterKnown := evalCondition(stmt.Cond, param, value, info)
			controls = !beforeKnown && afterKnown
		case *ast.SwitchStmt:
			controls = switchHasDeadArm(stmt, param, value, info)
		}
		return !controls
	})
	return controls
}

// evalCondition substitutes the parameter with value when non-nil. Unknown
// expressions stay dynamic, so a parameter only qualifies when its constant
// value makes the whole condition constant.
func evalCondition(expr ast.Expr, param types.Object, value constant.Value, info *types.Info) (bool, bool) {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if info.Uses[expr] == param {
			if value == nil || value.Kind() != constant.Bool {
				return false, false
			}
			return constant.BoolVal(value), true
		}
	case *ast.UnaryExpr:
		if expr.Op == token.NOT {
			result, known := evalCondition(expr.X, param, value, info)
			return !result, known
		}
	case *ast.BinaryExpr:
		switch expr.Op {
		case token.LAND, token.LOR:
			left, leftKnown := evalCondition(expr.X, param, value, info)
			right, rightKnown := evalCondition(expr.Y, param, value, info)
			if expr.Op == token.LAND {
				if (leftKnown && !left) || (rightKnown && !right) {
					return false, true
				}
				if leftKnown && rightKnown {
					return left && right, true
				}
			} else {
				if (leftKnown && left) || (rightKnown && right) {
					return true, true
				}
				if leftKnown && rightKnown {
					return left || right, true
				}
			}
			return false, false
		case token.EQL, token.NEQ:
			if result, ok := evalParamComparison(expr, param, value, info); ok {
				return result, true
			}
		}
	}
	if tv, ok := info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.Bool {
		return constant.BoolVal(tv.Value), true
	}
	return false, false
}

func evalParamComparison(expr *ast.BinaryExpr, param types.Object, value constant.Value, info *types.Info) (bool, bool) {
	if value == nil {
		return false, false
	}
	var other ast.Expr
	switch {
	case helpers.IsObjectIdent(info, expr.X, param):
		other = expr.Y
	case helpers.IsObjectIdent(info, expr.Y, param):
		other = expr.X
	default:
		return false, false
	}
	tv, ok := info.Types[other]
	if !ok || tv.Value == nil {
		return false, false
	}
	equal := constant.Compare(value, token.EQL, tv.Value)
	if expr.Op == token.NEQ {
		equal = !equal
	}
	return equal, true
}

func switchHasDeadArm(stmt *ast.SwitchStmt, param types.Object, value constant.Value, info *types.Info) bool {
	if !helpers.IsObjectIdent(info, stmt.Tag, param) {
		return false
	}
	matchedCase := false
	defaultArm := false
	deadCase := false
	for _, statement := range stmt.Body.List {
		clause, ok := statement.(*ast.CaseClause)
		if !ok {
			continue
		}
		if len(clause.List) == 0 {
			defaultArm = true
			continue
		}
		matches := false
		for _, expr := range clause.List {
			tv, ok := info.Types[expr]
			if !ok || tv.Value == nil {
				return false
			}
			if constant.Compare(value, token.EQL, tv.Value) {
				matches = true
			}
		}
		if matches {
			matchedCase = true
		} else {
			deadCase = true
		}
	}
	return deadCase || (matchedCase && defaultArm)
}
