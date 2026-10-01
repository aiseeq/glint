package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnboundedGoroutineFanoutRule())
}

// UnboundedGoroutineFanoutRule detects a range loop that starts one goroutine
// per element and waits for them all, with nothing limiting how many run at
// once, when the goroutines call out (pass a context.Context on):
//
//	for i, wallet := range s.wallets {
//	    wg.Add(1)
//	    go func(idx int, addr string) {
//	        defer wg.Done()
//	        results[idx] = s.fetchBalance(ctx, addr)
//	    }(i, wallet)
//	}
//
// Every element becomes a concurrent request: an external API answers the
// burst with 429, a database runs out of connections. The loop is bounded by
// a semaphore (a send of struct{} or an Acquire before the work), a rate
// limiter's Wait, or errgroup's SetLimit; a worker pool ranges over a channel
// or a count, not over the data, and is not reported. Ranges over a literal, an
// array, a local slice built from a literal or a list of functions (tasks the
// code registers) are small fixed sets and are not reported either, and
// neither are goroutines doing in-memory work only.
type UnboundedGoroutineFanoutRule struct {
	*rules.BaseRule
}

// NewUnboundedGoroutineFanoutRule creates the rule.
func NewUnboundedGoroutineFanoutRule() *UnboundedGoroutineFanoutRule {
	return &UnboundedGoroutineFanoutRule{
		BaseRule: rules.NewBaseRule(
			"unbounded-goroutine-fanout",
			"patterns",
			"Detects a goroutine per element of a range loop, all waited for and none limited by a semaphore, errgroup.SetLimit or a worker pool — a burst of concurrent calls that external APIs answer with 429",
			core.SeverityMedium,
		),
	}
}

// RequiresSSA reports that typed syntax is enough.
func (r *UnboundedGoroutineFanoutRule) RequiresSSA() bool { return false }

// AnalyzeFile is a no-op: the wait group and context types need type
// information.
func (r *UnboundedGoroutineFanoutRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// AnalyzeGoProject reports the unbounded fan-outs.
func (r *UnboundedGoroutineFanoutRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				loop, ok := n.(*ast.RangeStmt)
				if !ok || smallFixedRange(info, fn.Body, loop.X) {
					return true
				}
				if spawn := unboundedSpawn(info, fn.Body, loop.Body); spawn != nil {
					line := file.LineFor(spawn)
					if !file.IsSuppressed(line, r.Name()) {
						violations = append(violations, r.violationFor(file, line))
					}
				}
				return true
			})
		}
		return violations
	})
}

func (r *UnboundedGoroutineFanoutRule) violationFor(file *core.FileContext, line int) *core.Violation {
	v := r.CreateViolation(file.RelPath, line,
		"One goroutine per element, all started at once and nothing limits how many run — every element becomes a concurrent outbound call, and the remote side answers the burst with 429 or runs out of connections")
	v.WithCode(strings.TrimSpace(file.GetLine(line)))
	v.WithSuggestion("Limit concurrency: errgroup with SetLimit, a buffered-channel semaphore, a fixed worker pool, or a rate limiter per remote API")
	return v
}

// smallFixedRange reports a range over a literal, an array, a count, a
// channel, or a local variable only ever assigned a literal.
func smallFixedRange(info *types.Info, fnBody *ast.BlockStmt, expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if _, ok := expr.(*ast.CompositeLit); ok {
		return true
	}
	switch under := typeUnder(info, expr).(type) {
	case *types.Basic, *types.Array, *types.Chan, *types.Signature:
		return true
	case *types.Pointer:
		if _, ok := under.Elem().Underlying().(*types.Array); ok {
			return true
		}
	case *types.Slice:
		return isFuncType(under.Elem())
	case *types.Map:
		return isFuncType(under.Elem())
	}
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	variable, ok := info.Uses[ident].(*types.Var)
	if !ok || variable.Pkg() == nil || variable.Parent() == variable.Pkg().Scope() {
		return false
	}
	return onlyLiteralAssigned(info, fnBody, variable)
}

// isFuncType reports a function type: a collection of them is a set of tasks
// the code registers, not data.
func isFuncType(t types.Type) bool {
	_, ok := t.Underlying().(*types.Signature)
	return ok
}

// onlyLiteralAssigned reports a local variable whose every assignment in the
// function is a composite literal.
func onlyLiteralAssigned(info *types.Info, body *ast.BlockStmt, variable *types.Var) bool {
	literal, other := false, false
	record := func(value ast.Expr) {
		if _, ok := ast.Unparen(value).(*ast.CompositeLit); ok {
			literal = true
		} else {
			other = true
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				ident, ok := ast.Unparen(lhs).(*ast.Ident)
				if !ok || (info.Defs[ident] != variable && info.Uses[ident] != variable) {
					continue
				}
				if len(node.Rhs) == len(node.Lhs) && node.Tok != token.ADD_ASSIGN {
					record(node.Rhs[i])
				} else {
					other = true
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if info.Defs[name] != variable {
					continue
				}
				if i < len(node.Values) {
					record(node.Values[i])
				} else {
					other = true // declared empty and filled later
				}
			}
		}
		return true
	})
	return literal && !other
}

// unboundedSpawn returns the statement starting a goroutine per element of
// the loop, nil when there is none or something bounds it. Nested loops are
// judged on their own.
func unboundedSpawn(info *types.Info, fnBody, body *ast.BlockStmt) ast.Node {
	var spawn ast.Node
	waited, bounded, callsOut := false, false, false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.RangeStmt, *ast.ForStmt, *ast.FuncLit:
			return false
		case *ast.SendStmt:
			if semaphoreSend(info, node) {
				bounded = true
			}
		case *ast.GoStmt:
			if spawn == nil {
				spawn = node
			}
			bounded = bounded || boundsInside(info, node.Call)
			callsOut = callsOut || passesContext(info, node.Call)
			return false
		case *ast.CallExpr:
			switch {
			case boundingCall(info, node):
				bounded = true
			case waitGroupCall(info, node, "Add"):
				waited = true
			case waitGroupCall(info, node, "Go"), errgroupGo(info, node):
				if spawn == nil {
					spawn = node
				}
				waited = true
				bounded = bounded || boundsInside(info, node) || errgroupLimited(info, fnBody, node)
				callsOut = callsOut || passesContext(info, node)
				return false
			}
		}
		return true
	})
	if spawn == nil || !waited || bounded || !callsOut {
		return nil
	}
	return spawn
}

// boundsInside reports a semaphore or limiter inside the spawned code.
func boundsInside(info *types.Info, call *ast.CallExpr) bool {
	found := false
	ast.Inspect(call, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SendStmt:
			found = found || semaphoreSend(info, node)
		case *ast.CallExpr:
			found = found || boundingCall(info, node)
		}
		return !found
	})
	return found
}

// passesContext reports a call, in the spawned code, that hands a
// context.Context on: the goroutine reaches out of the process.
func passesContext(info *types.Info, call *ast.CallExpr) bool {
	found := false
	ast.Inspect(call, func(n ast.Node) bool {
		inner, ok := n.(*ast.CallExpr)
		if !ok {
			return !found
		}
		for _, arg := range inner.Args {
			if isNamedType(info.TypeOf(arg), "context", "Context") {
				found = true
			}
		}
		return !found
	})
	return found
}

// semaphoreSend reports a send of a token into a channel of struct{}.
func semaphoreSend(info *types.Info, send *ast.SendStmt) bool {
	ch, ok := typeUnder(info, send.Chan).(*types.Chan)
	if !ok {
		return false
	}
	elem, ok := ch.Elem().Underlying().(*types.Struct)
	return ok && elem.NumFields() == 0
}

// boundingCall reports an Acquire (semaphore) or a Wait with arguments (rate
// limiter).
func boundingCall(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Acquire", "TryAcquire":
		return true
	case "Wait", "WaitN":
		return len(call.Args) > 0 && isNamedType(info.TypeOf(call.Args[0]), "context", "Context")
	}
	return false
}

// waitGroupCall reports a call of the named sync.WaitGroup method.
func waitGroupCall(info *types.Info, call *ast.CallExpr, method string) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return false
	}
	t := info.TypeOf(sel.X)
	return isNamedType(t, "sync", "WaitGroup") || isPointerToNamedType(t, "sync", "WaitGroup")
}

// errgroupGo reports a call of errgroup.Group.Go.
func errgroupGo(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Go" {
		return false
	}
	t := info.TypeOf(sel.X)
	return isNamedType(t, errgroupPath, "Group") || isPointerToNamedType(t, errgroupPath, "Group")
}

const errgroupPath = "golang.org/x/sync/errgroup"

// errgroupLimited reports a SetLimit call on the group of g.Go(...) in the
// same function.
func errgroupLimited(info *types.Info, fnBody *ast.BlockStmt, goCall *ast.CallExpr) bool {
	sel, ok := ast.Unparen(goCall.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	group := types.ExprString(sel.X)
	found := false
	ast.Inspect(fnBody, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !found
		}
		if limit, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && limit.Sel.Name == "SetLimit" && types.ExprString(limit.X) == group {
			found = true
		}
		return !found
	})
	return found
}
