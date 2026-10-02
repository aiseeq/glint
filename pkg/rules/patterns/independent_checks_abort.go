package patterns

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewIndependentChecksAbortTogetherRule())
}

// NewIndependentChecksAbortTogetherRule creates
// independent-checks-abort-together: a function with nothing to return that
// runs two unrelated fetch-and-act steps one after another, and returns when
// the first fails, silences the second whenever the first is broken:
//
//	yields, err := m.CheckYields(ctx)
//	if err != nil { log; return }        // a failing yield scan...
//	m.notify(ctx, yields)
//	pegs, err := m.CheckPegs(ctx)        // ...skips the peg check
//	if err != nil { log; return }
//	m.notify(ctx, pegs)
//
// A step is a call assigning a value and an error, a return on the error, and
// a call handed the value; the later step does not use anything the earlier
// one produced. The error cannot travel up from a function without results,
// so the return ends the whole pass.
func NewIndependentChecksAbortTogetherRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"independent-checks-abort-together",
			"patterns",
			"Detects unrelated steps of a pass where the first one's failure returns before the next runs — one broken check silences the others",
			core.SeverityMedium,
		),
		suggestion: "Run every step, log each failure and report them together (errors.Join), so one failing check does not skip the others",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		visit := func(results *ast.FieldList, body *ast.BlockStmt) {
			if results != nil && results.NumFields() > 0 {
				return
			}
			forEachOwnStatementList(body, func(list []ast.Stmt) {
				for _, check := range abortingSteps(scope.info, list) {
					findings = append(findings, funcFinding{node: check, message: "This step's failure returns before an unrelated later step runs — the later check is silent whenever this one fails"})
				}
			})
		}
		visit(fn.Type.Results, fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok {
				visit(lit.Type.Results, lit.Body)
			}
			return true
		})
		return findings
	}
	return r
}

// passStep is a fetch-and-act step of a statement list: list[at] assigns
// value and err from a call, list[at+1] returns on err, list[at+2] hands the
// value to a call.
type passStep struct {
	at    int
	value *types.Var
	call  *ast.CallExpr
	check *ast.IfStmt
}

// abortingSteps returns the error checks of steps followed by an unrelated
// step of the same list.
func abortingSteps(info *types.Info, list []ast.Stmt) []*ast.IfStmt {
	var steps []passStep
	for i := 0; i+2 < len(list); i++ {
		if step, ok := fetchActStep(info, list, i); ok {
			steps = append(steps, step)
		}
	}
	var checks []*ast.IfStmt
	for i, first := range steps {
		for _, later := range steps[i+1:] {
			if independentStep(info, list, first, later) {
				checks = append(checks, first.check)
				break
			}
		}
	}
	return checks
}

func fetchActStep(info *types.Info, list []ast.Stmt, at int) (passStep, bool) {
	assign, ok := list[at].(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return passStep{}, false
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	valueIdent, ok1 := assign.Lhs[0].(*ast.Ident)
	errIdent, ok2 := assign.Lhs[1].(*ast.Ident)
	if !ok || !ok1 || !ok2 {
		return passStep{}, false
	}
	value, _ := info.ObjectOf(valueIdent).(*types.Var)
	if value == nil {
		return passStep{}, false
	}
	check, ok := list[at+1].(*ast.IfStmt)
	if !ok || check.Init != nil || check.Else != nil || len(check.Body.List) == 0 {
		return passStep{}, false
	}
	if name, isCheck := errNotNilName(check.Cond); !isCheck || name != errIdent.Name {
		return passStep{}, false
	}
	if ret, isReturn := check.Body.List[len(check.Body.List)-1].(*ast.ReturnStmt); !isReturn || len(ret.Results) > 0 {
		return passStep{}, false
	}
	act, ok := list[at+2].(*ast.ExprStmt)
	if !ok {
		return passStep{}, false
	}
	actCall, ok := act.X.(*ast.CallExpr)
	if !ok || !mentionsVar(info, actCall, value) {
		return passStep{}, false
	}
	return passStep{at: at, value: value, call: call, check: check}, true
}

// independentStep reports a later step whose call uses nothing defined from
// the first step on.
func independentStep(info *types.Info, list []ast.Stmt, first, later passStep) bool {
	defined := make(map[types.Object]bool)
	for _, stmt := range list[first.at:later.at] {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}
		for _, lhs := range assign.Lhs {
			if ident, isIdent := lhs.(*ast.Ident); isIdent {
				if v, isVar := info.ObjectOf(ident).(*types.Var); isVar && !implementsError(v.Type()) {
					defined[v] = true
				}
			}
		}
	}
	uses := false
	ast.Inspect(later.call, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && defined[info.ObjectOf(ident)] {
			uses = true
		}
		return !uses
	})
	return !uses
}
