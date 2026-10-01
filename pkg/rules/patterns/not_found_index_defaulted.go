package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNotFoundIndexDefaultedRule())
}

// NotFoundIndexDefaultedRule detects a lookup's "not found" answer replaced
// with a valid index:
//
//	index := FindAccountIndex(address)
//	if index == -1 {
//		index = 0 // "a safe index"
//	}
//
// The lookup said the item is not there; the code goes on with the first
// item, which is some other one — another user's account, another network.
// Return an error when the item is missing.
//
// Lookups of the project are judged; the standard library's strings.Index
// and the like are left alone, where -1 replaced by a bound is how a cut is
// written.
type NotFoundIndexDefaultedRule struct {
	*rules.BaseRule
}

// NewNotFoundIndexDefaultedRule creates the rule
func NewNotFoundIndexDefaultedRule() *NotFoundIndexDefaultedRule {
	return &NotFoundIndexDefaultedRule{BaseRule: rules.NewBaseRule(
		"not-found-index-defaulted",
		"patterns",
		"Detects a lookup's -1 (not found) replaced with a literal index — the code goes on with some other item",
		core.SeverityHigh,
	)}
}

// lookupName names a function that answers with an index or -1.
var lookupName = regexp.MustCompile(`(?i)find|index|lookup|search|position`)

// stdlibLookupPackages answer with -1 by contract, and a bound in its place
// is the usual way to cut.
var stdlibLookupPackages = map[string]bool{"strings": true, "bytes": true, "slices": true, "sort": true, "utf8": true}

// AnalyzeFile reports the index defaults that follow a lookup.
func (r *NotFoundIndexDefaultedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	// Test helpers are checked too: a fixture looked up and defaulted to the
	// first one makes the test exercise someone else's data.
	if !ctx.HasGoAST() {
		return nil
	}
	var violations []*core.Violation
	forEachFunction(ctx.GoAST, func(_ string, _ *ast.FuncType, body *ast.BlockStmt) {
		forEachStmtList(body, func(stmts []ast.Stmt) {
			violations = append(violations, r.checkList(ctx, stmts)...)
		})
	})
	return violations
}

// checkList reports the index defaults that follow a lookup in one statement list.
func (r *NotFoundIndexDefaultedRule) checkList(ctx *core.FileContext, stmts []ast.Stmt) []*core.Violation {
	var violations []*core.Violation
	for i := 0; i+1 < len(stmts); i++ {
		name := lookupResult(stmts[i])
		if name == "" {
			continue
		}
		check, ok := stmts[i+1].(*ast.IfStmt)
		if !ok || check.Init != nil || check.Else != nil || !notFoundTest(check.Cond, name) {
			continue
		}
		assign := literalDefault(check.Body, name)
		if assign == nil {
			continue
		}
		line := ctx.PositionFor(assign).Line
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, "The lookup's not-found answer is replaced with index "+defaultLiteral(assign)+" — the code goes on with some other item")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Return an error (or stop) when the item is not found")
		violations = append(violations, v)
	}
	return violations
}

// lookupResult returns the variable a statement sets from a lookup call of
// the project: x := FindX(...), x = s.IndexOf(...).
func lookupResult(stmt ast.Stmt) string {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return ""
	}
	ident, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return ""
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return ""
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if lookupName.MatchString(fun.Name) {
			return ident.Name
		}
	case *ast.SelectorExpr:
		if pkg, ok := fun.X.(*ast.Ident); ok && stdlibLookupPackages[pkg.Name] {
			return ""
		}
		if lookupName.MatchString(fun.Sel.Name) {
			return ident.Name
		}
	}
	return ""
}

// notFoundTest reports x == -1 or x < 0.
func notFoundTest(cond ast.Expr, name string) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || !isIdentNamed(bin.X, name) {
		return false
	}
	switch bin.Op {
	case token.EQL:
		unary, ok := ast.Unparen(bin.Y).(*ast.UnaryExpr)
		return ok && unary.Op == token.SUB && isIntLiteral(ast.Unparen(unary.X), 1)
	case token.LSS:
		return isIntLiteral(ast.Unparen(bin.Y), 0)
	}
	return false
}

// literalDefault returns the only statement of body when it sets name to an
// integer literal.
func literalDefault(body *ast.BlockStmt, name string) *ast.AssignStmt {
	if len(body.List) != 1 {
		return nil
	}
	assign, ok := body.List[0].(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || !isIdentNamed(assign.Lhs[0], name) {
		return nil
	}
	if lit, ok := ast.Unparen(assign.Rhs[0]).(*ast.BasicLit); !ok || lit.Kind != token.INT {
		return nil
	}
	return assign
}

// defaultLiteral prints the literal an index default assigns.
func defaultLiteral(assign *ast.AssignStmt) string {
	lit, ok := ast.Unparen(assign.Rhs[0]).(*ast.BasicLit)
	if !ok {
		return ""
	}
	return lit.Value
}
