package patterns

import (
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
	rules.Register(NewDeliveryRecordedBeforeAttemptRule())
}

// deliveryWords name a record of how a message was delivered.
var deliveryWords = []string{"delivery", "delivered", "deliveries"}

// NewDeliveryRecordedBeforeAttemptRule creates delivery-recorded-before-attempt:
// a function that records a channel as the delivery of a message and returns
// false, so that its caller then tries that channel, has recorded an outcome
// that has not happened:
//
//	s.setDelivery(journalID, "email", 0)
//	return false
//	// caller: if !s.dispatch(...) { return s.sendEmail(...) }
//
// When the email fails too, the record still says the message went by email,
// and whatever suppresses repeats by the record drops the next one.
func NewDeliveryRecordedBeforeAttemptRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"delivery-recorded-before-attempt",
			"patterns",
			"Detects a delivery channel recorded for a message before the caller attempts that channel — when the attempt fails the record still says the message was delivered",
			core.SeverityMedium,
		),
		suggestion: "Record the channel after the attempt with its real outcome, and report an undelivered message to the caller",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil || !returnsBoolOnly(scope.info, fn) {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, stmt := range block.List {
				record, channel := deliveryRecord(scope.info, stmt)
				if record == nil || !returnsFalseAfter(block.List[i+1:], channel) {
					continue
				}
				if caller := callerAttempts(scope, fn, channel); caller != "" {
					findings = append(findings, funcFinding{node: record, message: callName(record) + " records \"" + channel + "\" as the delivery before " + caller + " attempts it — when that send fails, the record still says the message was delivered"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// returnsBoolOnly reports a function whose only result is a bool.
func returnsBoolOnly(info *types.Info, fn *ast.FuncDecl) bool {
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok {
		return false
	}
	results := sig.Results()
	return results.Len() == 1 && types.Identical(results.At(0).Type(), types.Typ[types.Bool])
}

// deliveryRecord returns a bare call recording a delivery (setDelivery,
// RecordDelivered) and the channel it is handed as a string constant.
func deliveryRecord(info *types.Info, stmt ast.Stmt) (*ast.CallExpr, string) {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return nil, ""
	}
	call, ok := ast.Unparen(expr.X).(*ast.CallExpr)
	if !ok {
		return nil, ""
	}
	words := helpers.IdentifierWords(callName(call))
	if !slices.ContainsFunc(words, func(w string) bool { return slices.Contains(deliveryWords, w) }) {
		return nil, ""
	}
	for _, arg := range call.Args {
		if tv, ok := info.Types[arg]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
			if channel := constant.StringVal(tv.Value); channel != "" && !strings.ContainsAny(channel, " %") {
				return call, channel
			}
		}
	}
	return nil, ""
}

// returnsFalseAfter reports statements that reach return false without a
// call naming the channel: the attempt is left to the caller.
func returnsFalseAfter(stmts []ast.Stmt, channel string) bool {
	for _, stmt := range stmts {
		if namesChannel(stmt, channel) {
			return false
		}
		if ret, ok := stmt.(*ast.ReturnStmt); ok {
			return len(ret.Results) == 1 && isIdentNamed(ast.Unparen(ret.Results[0]), "false")
		}
	}
	return false
}

// namesChannel reports a node calling something whose name holds the
// channel (sendEmail for "email").
func namesChannel(node ast.Node, channel string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && strings.Contains(strings.ToLower(callName(call)), strings.ToLower(channel)) {
			found = true
		}
		return !found
	})
	return found
}

// callerAttempts returns the name of a caller of fn that, on fn's false,
// goes on to a call naming the channel: if fn(...) { return }; sendEmail(...).
func callerAttempts(scope funcScope, fn *ast.FuncDecl, channel string) string {
	obj, ok := scope.info.Defs[fn.Name].(*types.Func)
	if !ok {
		return ""
	}
	for _, site := range scope.callers[obj.Origin()] {
		found := ""
		ast.Inspect(site.caller.decl.Body, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok || found != "" {
				return found == ""
			}
			for i, stmt := range block.List {
				check, ok := stmt.(*ast.IfStmt)
				if !ok || !containsNode(check.Cond, site.call) || !blockLeaves(check.Body) || negated(check.Cond, site.call) {
					continue
				}
				for _, later := range block.List[i+1:] {
					if namesChannel(later, channel) {
						found = site.caller.decl.Name.Name
					}
				}
			}
			return found == ""
		})
		if found != "" {
			return found
		}
	}
	return ""
}

// negated reports !call in cond: the branch is taken on false.
func negated(cond ast.Expr, call *ast.CallExpr) bool {
	not, ok := ast.Unparen(cond).(*ast.UnaryExpr)
	return ok && not.Op == token.NOT && ast.Unparen(not.X) == call
}
