package patterns

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDerivedContextUnusedRule())
}

// DerivedContextUnusedRule detects a context derived with a timeout, a
// deadline or a cancel that is only waited on, while the calls of the
// function still get the parent context:
//
//	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
//	defer cancel()
//	for {
//		select {
//		case <-timeoutCtx.Done():
//			return nil, timeoutCtx.Err()
//		default:
//			receipt, err := client.TransactionReceipt(ctx, hash)
//
// The loop gives up on time, but a call that hangs is never cut: it runs
// with the parent's deadline, or none. Reported: each call after the
// derivation that gets the parent, when the derived context is passed to
// nothing (only its Done, Err, Deadline are read).
type DerivedContextUnusedRule struct {
	*rules.BaseRule
}

// NewDerivedContextUnusedRule creates the rule
func NewDerivedContextUnusedRule() *DerivedContextUnusedRule {
	return &DerivedContextUnusedRule{BaseRule: rules.NewBaseRule(
		"derived-context-unused",
		"patterns",
		"Detects a timeout or cancel context only waited on while the calls still get the parent context — the timeout cuts no call",
		core.SeverityHigh,
	)}
}

// boundingDerivations are the context functions whose result bounds the
// calls that get it.
var boundingDerivations = map[string]bool{
	"WithTimeout": true, "WithDeadline": true, "WithCancel": true,
	"WithTimeoutCause": true, "WithDeadlineCause": true, "WithCancelCause": true,
}

// AnalyzeFile reports the calls that get the parent of an unused derived context.
func (r *DerivedContextUnusedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	for _, body := range functionBodies(ctx.GoAST) {
		for _, derived := range contextDerivations(ctx.GoAST, body) {
			if passedOn(body, derived.child) {
				continue
			}
			for _, call := range callsPassing(body, derived.parent, derived.at) {
				line := ctx.LineFor(call)
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, line, fmt.Sprintf(
					"Call gets %s, while %s derived from it at line %d is only waited on — the call is not cut by its timeout or cancel",
					derived.parent.Name, derived.child.Name, ctx.LineFor(derived.child)))
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion(fmt.Sprintf("Pass %s to the call", derived.child.Name))
				violations = append(violations, v)
			}
		}
	}
	return violations
}

// contextDerivation is child, cancel := context.WithTimeout(parent, ...).
type contextDerivation struct {
	child, parent *ast.Ident
	at            ast.Node // the assignment
}

// contextDerivations returns the bounding derivations a body makes itself,
// outside its function literals, into a new name.
func contextDerivations(file *ast.File, body *ast.BlockStmt) []contextDerivation {
	var found []contextDerivation
	ast.Inspect(body, func(n ast.Node) bool {
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		name, ok := packageFuncName(file, nil, call, "context")
		if !ok || !boundingDerivations[name] {
			return true
		}
		child, childOK := assign.Lhs[0].(*ast.Ident)
		parent, parentOK := call.Args[0].(*ast.Ident)
		if !childOK || !parentOK || child.Name == "_" || child.Name == parent.Name || child.Obj == nil || parent.Obj == nil {
			return true
		}
		found = append(found, contextDerivation{child: child, parent: parent, at: assign})
		return true
	})
	return found
}

// passedOn reports a context the body uses other than by calling its own
// methods (Done, Err, Deadline): passed to a call, returned, stored.
func passedOn(body *ast.BlockStmt, child *ast.Ident) bool {
	receivers := make(map[*ast.Ident]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok {
				receivers[id] = true
			}
		}
		return true
	})
	passed := false
	ast.Inspect(body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if ok && id != child && id.Obj == child.Obj && !receivers[id] {
			passed = true
		}
		return !passed
	})
	return passed
}

// callsPassing returns the calls after a node whose arguments include the
// context, other than further derivations from it.
func callsPassing(body *ast.BlockStmt, parent *ast.Ident, after ast.Node) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || call.Pos() < after.End() {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "context" {
				return true
			}
		}
		for _, arg := range call.Args {
			if id, ok := arg.(*ast.Ident); ok && id.Obj == parent.Obj {
				calls = append(calls, call)
				break
			}
		}
		return true
	})
	return calls
}
