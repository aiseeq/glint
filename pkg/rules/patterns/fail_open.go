package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewFailOpenRule())
}

// FailOpenRule detects checks that answer "yes" when they could not be made:
//
//	func (m *Monitor) isActiveDeployment() bool {
//	    data, err := os.ReadFile(statePath)
//	    if err != nil {
//	        m.logger.Warn("state unreadable, assuming active")
//	        return true // two instances now both act as the active one
//	    }
//	    ...
//	}
//
// A permissive predicate (is active, valid, allowed, exists) that returns
// true on an error or on a missing dependency; a middleware that passes the
// request on when its own check failed; an error branch that answers with a
// success response. The gate opens exactly when the check is broken, and the
// log line, if any, does not close it. A middleware that passes a request
// without the restricting context value on unchecked, or runs its check only
// when the body was read and decoded, opens the same gate.
type FailOpenRule struct {
	*rules.BaseRule
}

// NewFailOpenRule creates the rule
func NewFailOpenRule() *FailOpenRule {
	return &FailOpenRule{
		BaseRule: rules.NewBaseRule(
			"fail-open",
			"patterns",
			"Detects checks that answer yes, pass the request on or report success when the check itself failed",
			core.SeverityHigh,
		),
	}
}

// restrictiveWords name predicates whose true is the cautious answer: a
// blocklist that cannot be read reports everyone blocked. Retry predicates
// answer true on an error by contract.
var restrictiveWords = []string{"block", "ban", "expire", "revoke", "lock", "deny", "denied", "disable", "suspend",
	"invalid", "forbid", "limit", "throttle", "stale", "duplicate", "fraud", "retry", "retryable", "transient",
	"error", "fail", "missing", "empty", "zero", "closed", "stop", "abort", "skip", "ignore"}

// gateVerbs start the names of checks whose true lets something through.
var gateVerbs = []string{"Can", "May", "Allow", "Validate", "Verify", "Authorize", "Permit"}

// gateWords, inside a predicate name, say what its true grants: IsActive,
// userExists, isHealthy. A predicate that classifies (isBuiltinCall,
// hasSuffix) grants nothing.
var gateWords = []string{"active", "valid", "allow", "authoriz", "authentic", "enabled", "exist", "verified",
	"healthy", "permit", "available", "ready", "trusted", "eligible", "approved", "owner", "admin", "member",
	"staff", "access", "leader", "primary", "online", "alive", "live"}

// AnalyzeFile checks every function for fail-open error branches.
func (r *FailOpenRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	receivers := make(map[*ast.BlockStmt]string)
	for _, decl := range ctx.GoAST.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && fn.Recv != nil && len(fn.Recv.List) == 1 && len(fn.Recv.List[0].Names) == 1 {
			receivers[fn.Body] = fn.Recv.List[0].Names[0].Name
		}
	}
	var violations []*core.Violation
	forEachFunction(ctx.GoAST, func(name string, ftype *ast.FuncType, body *ast.BlockStmt) {
		permissive := returnsSingleBool(ftype) && isPermissivePredicate(name)
		receiver := receivers[body]
		violations = append(violations, r.middlewareChecks(ctx, body)...)
		forEachOwnStatement(body, func(stmt ast.Stmt) {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				return
			}
			errBranch := errNilCheckName(ifStmt.Cond) != ""
			if permissive && (errBranch || isMissingDependencyCheck(ifStmt.Cond, receiver)) {
				if ret := trueReturnAfterLogs(ifStmt.Body); ret != nil {
					violations = append(violations, r.violation(ctx, ret,
						"The check could not be made and answers yes - the gate opens exactly when the check is broken"))
				}
			}
			if !errBranch {
				return
			}
			if call := passOnCall(ifStmt.Body); call != nil {
				violations = append(violations, r.violation(ctx, call,
					"The check failed and the request is passed on as if it had passed"))
			}
			if call := successResponseCall(ifStmt.Body); call != nil {
				violations = append(violations, r.violation(ctx, call,
					"The call failed and the error branch answers with success"))
			}
		})
	})
	return violations
}

func (r *FailOpenRule) violation(ctx *core.FileContext, node ast.Node, message string) *core.Violation {
	pos := ctx.PositionFor(node)
	v := r.CreateViolation(ctx.RelPath, pos.Line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
	v.WithSuggestion("Fail closed: return the error, deny the request, or answer with an error status")
	return v
}

func returnsSingleBool(ftype *ast.FuncType) bool {
	if ftype == nil || ftype.Results == nil || len(ftype.Results.List) != 1 || len(ftype.Results.List[0].Names) > 1 {
		return false
	}
	ident, ok := ftype.Results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == "bool"
}

// isPermissivePredicate reports a check whose true lets something through:
// named by a gate verb, or a predicate naming what it grants, and holding no
// restrictive word.
func isPermissivePredicate(name string) bool {
	lower := strings.ToLower(name)
	for _, word := range restrictiveWords {
		if strings.Contains(lower, word) {
			return false
		}
	}
	for _, verb := range gateVerbs {
		if helpers.HasLeadingWord(name, verb) {
			return true
		}
	}
	if !isPredicateName(name) {
		return false
	}
	for _, word := range gateWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// isMissingDependencyCheck reports a condition testing a field of the
// receiver for nil, alone or in a disjunction: s.users == nil || id == "".
// A field of a parameter is data, not a dependency.
func isMissingDependencyCheck(cond ast.Expr, receiver string) bool {
	if receiver == "" {
		return false
	}
	for _, operand := range flattenOr(cond) {
		bin, ok := ast.Unparen(operand).(*ast.BinaryExpr)
		if !ok || bin.Op != token.EQL || !isNilIdent(bin.Y) {
			continue
		}
		sel, ok := ast.Unparen(bin.X).(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if base, ok := sel.X.(*ast.Ident); ok && base.Name == receiver {
			return true
		}
	}
	return false
}

// trueReturnAfterLogs returns the `return true` of a branch that holds nothing
// else but log lines.
func trueReturnAfterLogs(body *ast.BlockStmt) *ast.ReturnStmt {
	for i, stmt := range body.List {
		if ret, ok := stmt.(*ast.ReturnStmt); ok {
			if i != len(body.List)-1 || len(ret.Results) != 1 {
				return nil
			}
			if ident, ok := ast.Unparen(ret.Results[0]).(*ast.Ident); ok && ident.Name == "true" {
				return ret
			}
			return nil
		}
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return nil
		}
		if call, ok := exprStmt.X.(*ast.CallExpr); !ok || !isReportCall(call) {
			return nil
		}
	}
	return nil
}

// passOnCall returns a next.ServeHTTP(w, r) call in the branch.
func passOnCall(body *ast.BlockStmt) *ast.CallExpr {
	var found *ast.CallExpr
	forEachOwnStatement(body, func(stmt ast.Stmt) {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok || found != nil {
			return
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			return
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ServeHTTP" {
			found = call
		}
	})
	return found
}

// successResponseCall returns a call in the branch that answers with success:
// a responder named for success (SendSuccess, RespondSuccess, writeSuccess).
func successResponseCall(body *ast.BlockStmt) *ast.CallExpr {
	var found *ast.CallExpr
	forEachOwnStatement(body, func(stmt ast.Stmt) {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok || found != nil {
			return
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok || !hasResponseWriterArg(call) {
			return
		}
		var name string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if strings.Contains(strings.ToLower(name), "success") && !answersNo(call) {
			found = call
		}
	})
	return found
}

// answersNo reports a response whose payload says no: a field set to false
// (Authenticated: false, Available: false) is an answer, not a fake success.
func answersNo(call *ast.CallExpr) bool {
	found := false
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if kv, ok := n.(*ast.KeyValueExpr); ok {
				if ident, ok := ast.Unparen(kv.Value).(*ast.Ident); ok && ident.Name == "false" {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

// hasResponseWriterArg reports a call whose first argument is named like a
// response writer (w, rw, writer).
func hasResponseWriterArg(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	ident, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
	return ok && (ident.Name == "w" || ident.Name == "rw" || ident.Name == "writer" || ident.Name == "resp")
}
