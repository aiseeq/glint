package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewChannelCloseNotIdempotentRule())
}

// ChannelCloseNotIdempotentRule detects a Close, Stop or Shutdown method that
// closes a channel field with nothing stopping a second call:
//
//	func (l *Limiter) Stop() {
//		close(l.stopCleanup)   // the second Stop panics: close of closed channel
//	}
//
// Shutdown paths run more than once: a deferred cleanup after an explicit
// stop, two owners of one service, a test closing what the server also
// closes. Guarded: the close inside a sync.Once.Do callback, a condition on a
// field the method itself sets (a closed flag) or on the channel field it
// resets to nil, and a select that receives from the channel first.
type ChannelCloseNotIdempotentRule struct {
	*rules.BaseRule
}

// NewChannelCloseNotIdempotentRule creates the rule
func NewChannelCloseNotIdempotentRule() *ChannelCloseNotIdempotentRule {
	return &ChannelCloseNotIdempotentRule{BaseRule: rules.NewBaseRule(
		"channel-close-not-idempotent",
		"patterns",
		"Detects a Close/Stop/Shutdown method closing a channel field with no sync.Once or closed flag — a second call panics",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the unguarded closes of the file's shutdown methods.
func (r *ChannelCloseNotIdempotentRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Recv == nil || !closeMethods[fn.Name.Name] {
			continue
		}
		recv, ok := receiverName(fn)
		if !ok {
			continue
		}
		assigned := assignedReceiverFields(fn.Body, recv)
		guards := guardedFields(fn.Body, recv)
		for _, call := range ownChannelCloses(fn.Body, recv) {
			field := receiverField(call.Args[0], recv)
			if assigned[field] || guards.receives[field] || guards.flagged(assigned) {
				continue
			}
			line := ctx.LineFor(call)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line,
				fn.Name.Name+" closes "+recv+"."+field+" with no guard — a second "+fn.Name.Name+" panics with close of closed channel")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Close inside a sync.Once field's Do, or set and check a closed flag under the mutex")
			violations = append(violations, v)
		}
	}
	return violations
}

// ownChannelCloses returns the close(recv.field) calls of the body outside
// function literals: a literal is the callback of a sync.Once or another
// deferred owner.
func ownChannelCloses(body *ast.BlockStmt, recv string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "close" {
			return true
		}
		if receiverField(call.Args[0], recv) != "" {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

// receiverField returns the field name of recv.field, "" for anything else.
func receiverField(expr ast.Expr, recv string) string {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if id, ok := sel.X.(*ast.Ident); ok && id.Name == recv {
		return sel.Sel.Name
	}
	return ""
}

// assignedReceiverFields returns the receiver fields the body assigns.
func assignedReceiverFields(body *ast.BlockStmt, recv string) map[string]bool {
	fields := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if field := receiverField(lhs, recv); field != "" {
					fields[field] = true
				}
			}
		}
		return true
	})
	return fields
}

// closeGuards are the receiver fields the body tests before acting.
type closeGuards struct {
	// conditions holds the fields an if condition reads.
	conditions map[string]bool
	// receives holds the fields a select case receives from.
	receives map[string]bool
}

// flagged reports a condition on a field the method sets: a closed flag.
func (g closeGuards) flagged(assigned map[string]bool) bool {
	for field := range g.conditions {
		if assigned[field] {
			return true
		}
	}
	return false
}

func guardedFields(body *ast.BlockStmt, recv string) closeGuards {
	guards := closeGuards{conditions: make(map[string]bool), receives: make(map[string]bool)}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			ast.Inspect(node.Cond, func(m ast.Node) bool {
				if expr, ok := m.(ast.Expr); ok {
					if field := receiverField(expr, recv); field != "" {
						guards.conditions[field] = true
					}
				}
				return true
			})
		case *ast.CommClause:
			if expr, ok := node.Comm.(*ast.ExprStmt); ok {
				if recvExpr, ok := expr.X.(*ast.UnaryExpr); ok {
					if field := receiverField(recvExpr.X, recv); field != "" {
						guards.receives[field] = true
					}
				}
			}
		}
		return true
	})
	return guards
}
