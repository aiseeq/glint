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
	rules.Register(NewNilDependencySkipsRejectionRule())
}

// NilDependencySkipsRejectionRule detects a rejection that runs only while an
// optional dependency is set:
//
//	if p.registry != nil && p.registry.IsContract(addr) {
//	    return fmt.Errorf("address %s is a contract", addr)
//	}
//
// With the dependency missing — a wiring that forgot it, a test setup copied
// into production — the condition is false and the value the check exists to
// stop goes through. A check that guards something must fail when it cannot
// run: require the dependency (return an error when it is nil) or make it
// mandatory in the constructor.
type NilDependencySkipsRejectionRule struct {
	*rules.BaseRule
}

// NewNilDependencySkipsRejectionRule creates the rule
func NewNilDependencySkipsRejectionRule() *NilDependencySkipsRejectionRule {
	return &NilDependencySkipsRejectionRule{BaseRule: rules.NewBaseRule(
		"nil-dependency-skips-rejection",
		"patterns",
		"Detects a rejection guarded by dep != nil && dep.Check(...) — with the dependency missing the check is skipped and the value passes",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports the rejections of a file that a nil dependency skips.
func (r *NilDependencySkipsRejectionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		dep, found := optionalDependencyCheck(stmt.Cond)
		if !found || !rejectsRequest(stmt.Body) {
			return true
		}
		line := ctx.LineFor(stmt)
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, line, "The rejection runs only while "+dep+
			" is set — with it nil the check is skipped and the value goes through")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Fail when the dependency is missing (if " + dep + " == nil { return error }), or make it mandatory at construction")
		violations = append(violations, v)
		return true
	})
	return violations
}

// optionalDependencyCheck matches dep != nil && <call on dep> and returns
// dep.
func optionalDependencyCheck(cond ast.Expr) (string, bool) {
	and, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || and.Op != token.LAND {
		return "", false
	}
	present, ok := ast.Unparen(and.X).(*ast.BinaryExpr)
	if !ok || present.Op != token.NEQ {
		return "", false
	}
	if nilIdent, ok := present.Y.(*ast.Ident); !ok || nilIdent.Name != "nil" {
		return "", false
	}
	// A dependency is a variable or a field named as one (registry,
	// configService); a value that may be absent (an optional actor, the
	// package of a function) is checked for nil as part of its meaning.
	var dep ast.Expr
	switch subject := ast.Unparen(present.X).(type) {
	case *ast.Ident:
		dep = subject
		if !checkingDependencyName(subject.Name) {
			return "", false
		}
	case *ast.SelectorExpr:
		dep = subject
		if !checkingDependencyName(subject.Sel.Name) {
			return "", false
		}
	default:
		return "", false
	}
	depText := types.ExprString(dep)
	called := false
	ast.Inspect(and.Y, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !called
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && types.ExprString(sel.X) == depText {
			called = true
		}
		return !called
	})
	return depText, called
}

// checkerWords name the dependencies whose job is to refuse something.
var checkerWords = map[string]bool{
	"checker": true, "verifier": true, "registry": true, "guard": true, "policy": true,
	"resolver": true, "detector": true, "limiter": true, "blocklist": true, "allowlist": true,
}

// checkingDependencyName reports a name of a dependency: one nil-di knows
// (service, repo, client, ...) or a checker (registry, verifier, limiter).
func checkingDependencyName(name string) bool {
	if isDependencyName(name) {
		return true
	}
	for _, word := range identifierWords(name) {
		if checkerWords[word] {
			return true
		}
	}
	return false
}

// rejectsRequest reports a branch whose own statements return a non-nil
// error or answer the request with an HTTP error; a failure of nested work
// (if err != nil { return err }) is not the branch rejecting.
func rejectsRequest(body *ast.BlockStmt) bool {
	found := false
	for _, stmt := range body.List {
		found = found || rejectingStatement(stmt)
	}
	return found
}

// rejectingStatement reports a return of a non-nil error or an http.Error
// call.
func rejectingStatement(stmt ast.Stmt) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit, *ast.BlockStmt, *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) > 0 {
				last := ast.Unparen(node.Results[len(node.Results)-1])
				if ident, ok := last.(*ast.Ident); !ok || ident.Name == "err" || strings.HasPrefix(ident.Name, "Err") {
					_, literal := last.(*ast.BasicLit)
					found = found || (!literal && !isTrueLiteral(last) && !isFalseLiteral(last))
				}
			}
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
