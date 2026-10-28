package concurrencyrules

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewDatedEntryEveryTickRule())
}

// datedEntryDepth bounds how deep the calls of a tick are followed to the
// write of a dated entry.
const datedEntryDepth = 3

// NewDatedEntryEveryTickRule creates dated-entry-every-tick: an entry dated
// today - a fee, an accrual, a daily snapshot, sized for one period - written
// from a polling loop is written on every tick, several times a day, unless
// something checks that today's entry is already there:
//
//	for range ticker.C {                 // every 5 minutes
//		s.runSnapshots()                 // -> fees.Accrue -> RecordEntry(&Entry{Date: today, ...})
//	}
//
// A path that compares something with today's date (the latest entry's date,
// a lookup by it) on the way to the write is guarded and not reported.
func NewDatedEntryEveryTickRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"dated-entry-every-tick",
			"patterns",
			"Detects an entry dated today written from a polling loop with no check that today's entry exists — a per-period amount is booked on every tick",
			core.SeverityMedium,
		),
		Suggestion: "Write the entry once per period: check the latest entry's date (or upsert on the date key) before writing",
	}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		var findings []patternkit.FuncFinding
		forEachTickBody(fn.Body, func(tick *ast.BlockStmt) {
			if comparesToday(scope.Info, patternkit.SingleDefinitions(scope.Info, fn.Body), tick) {
				return
			}
			ast.Inspect(tick, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				decl, ok := scope.Callee(call)
				if !ok {
					return true
				}
				if writer := datedWriteReached(scope, decl, 1, map[*ast.FuncDecl]bool{}); writer != "" {
					findings = append(findings, patternkit.FuncFinding{Node: call, Message: "Every tick of the polling loop reaches " + writer + ", which writes an entry dated today with no check that today's entry exists — a per-period amount is booked on every tick"})
				}
				return true
			})
		})
		return findings
	}
	return r
}

// forEachTickBody calls visit with the body of each tick of a polling loop:
// a range over a ticker channel, a select case receiving from one.
func forEachTickBody(body *ast.BlockStmt, visit func(*ast.BlockStmt)) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.RangeStmt:
			if tickerChannel(node.X) {
				visit(node.Body)
			}
		case *ast.CommClause:
			if tickReceive(node.Comm) {
				visit(&ast.BlockStmt{List: node.Body})
			}
		}
		return true
	})
}

// tickReceive reports a select case receiving from a ticker channel.
func tickReceive(comm ast.Stmt) bool {
	var expr ast.Expr
	switch c := comm.(type) {
	case *ast.ExprStmt:
		expr = c.X
	case *ast.AssignStmt:
		if len(c.Rhs) == 1 {
			expr = c.Rhs[0]
		}
	}
	unary, ok := ast.Unparen(expr).(*ast.UnaryExpr)
	return ok && unary.Op == token.ARROW && tickerChannel(unary.X)
}

// datedWriteReached returns the function a call reaches, within
// datedEntryDepth calls, that writes an entry dated today with no check of
// today's date on the way; "" for none.
func datedWriteReached(scope patternkit.FuncScope, decl patternkit.TypedFuncDecl, depth int, seen map[*ast.FuncDecl]bool) string {
	if seen[decl.Decl] {
		return ""
	}
	seen[decl.Decl] = true
	defs := patternkit.SingleDefinitions(decl.Info, decl.Decl.Body)
	if comparesToday(decl.Info, defs, decl.Decl.Body) {
		return ""
	}
	if writesDatedEntry(decl.Info, defs, decl.Decl.Body) {
		return decl.Decl.Name.Name
	}
	if depth >= datedEntryDepth {
		return ""
	}
	found := ""
	inner := patternkit.FuncScope{Info: decl.Info, Decls: scope.Decls}
	ast.Inspect(decl.Decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != "" {
			return found == ""
		}
		if callee, ok := inner.Callee(call); ok {
			found = datedWriteReached(scope, callee, depth+1, seen)
		}
		return found == ""
	})
	return found
}

// writesDatedEntry reports a write call handed an entry whose date field is
// today: RecordEntry(&Entry{Date: today}), or a variable holding one.
func writesDatedEntry(info *types.Info, defs map[types.Object]ast.Expr, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found || !helpers.IsWriteName(helpers.CalleeName(call)) {
			return !found
		}
		for _, arg := range call.Args {
			if ident, ok := ast.Unparen(arg).(*ast.Ident); ok {
				if def, ok := defs[info.ObjectOf(ident)]; ok {
					arg = def
				}
			}
			found = found || datedToday(info, defs, arg)
		}
		return !found
	})
	return found
}

// datedToday reports a composite literal (or its address) with a ...Date
// field set to today.
func datedToday(info *types.Info, defs map[types.Object]ast.Expr, expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = ast.Unparen(unary.X)
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		words := helpers.IdentifierWords(key.Name)
		if len(words) > 0 && words[len(words)-1] == "date" && todayValue(info, defs, kv.Value, 0) {
			return true
		}
	}
	return false
}

// todayValue reports a date formatted from the clock: time.Now() through
// UTC, In, Add or AddDate, then Format; a local variable is followed to its
// only definition.
func todayValue(info *types.Info, defs map[types.Object]ast.Expr, expr ast.Expr, depth int) bool {
	if depth > 4 {
		return false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		def, ok := defs[info.ObjectOf(e)]
		return ok && todayValue(info, defs, def, depth+1)
	case *ast.CallExpr:
		sel, ok := ast.Unparen(e.Fun).(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Format" && patternkit.FromClock(info, sel.X)
	}
	return false
}

// comparesToday reports an if whose condition reads today's date: the guard
// that lets one entry a day through.
func comparesToday(info *types.Info, defs map[types.Object]ast.Expr, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		check, ok := n.(*ast.IfStmt)
		if !ok || found {
			return !found
		}
		ast.Inspect(check.Cond, func(m ast.Node) bool {
			if expr, ok := m.(ast.Expr); ok && todayValue(info, defs, expr, 0) {
				found = true
			}
			return !found
		})
		return !found
	})
	return found
}
