package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewPerUserSubscriptionsUnboundedRule())
}

// subscriberOwnerWords name a key that is a client of the service.
var subscriberOwnerWords = []string{"user", "client", "customer", "account", "owner", "session", "member"}

// NewPerUserSubscriptionsUnboundedRule creates per-user-subscriptions-unbounded:
// a Subscribe method that appends a long-lived subscriber (one holding a
// channel) to the list of a user with no cap on the list lets one client
// hold any number of streams, each with its channel and goroutine:
//
//	func (m *Events) Subscribe(ctx context.Context, userID string) (*Subscriber, error) {
//		...
//		m.subscribers[userID] = append(m.subscribers[userID], sub) // no len check
//
// A cap per user (and an error the handler answers with 429) bounds what one
// client can open.
func NewPerUserSubscriptionsUnboundedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"per-user-subscriptions-unbounded",
			"patterns",
			"Detects a Subscribe that appends a subscriber holding a channel to a user's list with no cap on the list — one client can open any number of streams, each holding a channel and a goroutine",
			core.SeverityMedium,
		),
		suggestion: "Cap the subscriptions of one user (len(m.subscribers[userID]) >= max → an error the handler answers with 429)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil || fn.Recv == nil || !slices.Contains(helpers.IdentifierWords(fn.Name.Name), "subscribe") {
			return nil
		}
		owners := ownerParams(scope.info, fn)
		if len(owners) == 0 {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}
			index, ok := assign.Lhs[0].(*ast.IndexExpr)
			if !ok || !rootedInParam(scope.info, index.Index, owners) {
				return true
			}
			call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
			if !ok || !isIdentNamed(call.Fun, "append") || len(call.Args) != 2 || !holdsChannel(scope.info.TypeOf(call.Args[1])) {
				return true
			}
			if !countsList(fn.Body, index) {
				findings = append(findings, funcFinding{node: assign, message: "A subscriber holding a channel is appended to the user's list with no cap on its length — one client can open any number of streams, each holding a channel and a goroutine"})
			}
			return true
		})
		return findings
	}
	return r
}

// ownerParams returns the parameters of fn named for a client of the
// service: userID, clientID, accountID.
func ownerParams(info *types.Info, fn *ast.FuncDecl) map[types.Object]bool {
	owners := make(map[types.Object]bool)
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			words := helpers.IdentifierWords(name.Name)
			if slices.ContainsFunc(words, func(w string) bool { return slices.Contains(subscriberOwnerWords, w) }) {
				owners[info.ObjectOf(name)] = true
			}
		}
	}
	return owners
}

// holdsChannel reports a channel, or a struct (through a pointer) with a
// channel field.
func holdsChannel(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	switch u := t.Underlying().(type) {
	case *types.Chan:
		return true
	case *types.Struct:
		for i := range u.NumFields() {
			if _, ok := u.Field(i).Type().Underlying().(*types.Chan); ok {
				return true
			}
		}
	}
	return false
}

// countsList reports a body comparing the length of the list the append
// grows with a limit: len(m.subscribers[userID]) >= max. A length only
// logged caps nothing.
func countsList(body *ast.BlockStmt, list *ast.IndexExpr) bool {
	want := types.ExprString(list)
	isLen := func(expr ast.Expr) bool {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		return ok && isIdentNamed(call.Fun, "len") && len(call.Args) == 1 && types.ExprString(call.Args[0]) == want
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if bin, ok := n.(*ast.BinaryExpr); ok && (isLen(bin.X) || isLen(bin.Y)) {
			switch bin.Op {
			case token.LSS, token.GTR, token.LEQ, token.GEQ, token.EQL:
				found = true
			}
		}
		return !found
	})
	return found
}
