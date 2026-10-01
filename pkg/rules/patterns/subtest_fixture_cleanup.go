package patterns

import (
	"go/ast"
	"go/token"
	"strconv"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSubtestFixtureCleanedEarlyRule())
}

// SubtestFixtureCleanedEarlyRule detects a fixture made inside one subtest
// and used by a later sibling, when the helper that made it ties its cleanup
// to the subtest:
//
//	var user *Response
//	t.Run("prepare", func(t *testing.T) {
//	    user = CreateTestUser(t, client)   // registers t.Cleanup on the subtest
//	})
//	t.Run("login", func(t *testing.T) {
//	    login(t, client, user)             // the user is already deleted
//	})
//
// A subtest's cleanups run when it ends, before the next one starts. Make the
// fixture in the parent test, where its cleanup lasts for all subtests.
type SubtestFixtureCleanedEarlyRule struct {
	*rules.BaseRule
	// cleaners are the functions, as "package.Name", that register a cleanup
	// on the testing handle they are given.
	cleaners map[string]bool
}

// NewSubtestFixtureCleanedEarlyRule creates the rule
func NewSubtestFixtureCleanedEarlyRule() *SubtestFixtureCleanedEarlyRule {
	return &SubtestFixtureCleanedEarlyRule{BaseRule: rules.NewBaseRule(
		"subtest-fixture-cleaned-early",
		"patterns",
		"Detects a fixture made in a subtest by a helper that cleans it up with that subtest, then used by a later sibling",
		core.SeverityHigh,
	)}
}

// UseProjectFiles finds the helpers that register a cleanup on their handle,
// themselves or through a helper they hand the handle to.
func (r *SubtestFixtureCleanedEarlyRule) UseProjectFiles(files []*core.FileContext) {
	r.cleaners = make(map[string]bool)
	delegates := make(map[string][]string) // helper -> helpers it hands its handle to
	for _, ctx := range files {
		if !ctx.IsGoFile() || !ctx.HasGoAST() {
			continue
		}
		testingPkgs := testingImportNames(ctx.GoAST)
		if len(testingPkgs) == 0 {
			continue
		}
		pkg := ctx.GoAST.Name.Name
		for _, decl := range ctx.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			handles := scopeTestingHandles(nil, fn.Type.Params, testingPkgs)
			if len(handles) == 0 {
				continue
			}
			key := pkg + "." + fn.Name.Name
			if cleansUpOn(fn.Body, handles) {
				r.cleaners[key] = true
				continue
			}
			delegates[key] = handleCallees(fn.Body, handles, pkg)
		}
	}
	for changed := true; changed; {
		changed = false
		for helper, callees := range delegates {
			if r.cleaners[helper] {
				continue
			}
			for _, callee := range callees {
				if r.cleaners[callee] {
					r.cleaners[helper] = true
					changed = true
					break
				}
			}
		}
	}
}

// handleCallees returns the package functions a body passes a handle to.
func handleCallees(body *ast.BlockStmt, handles map[string]bool, pkg string) []string {
	var callees []string
	ownNodes(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !callForwardsTestingT(call, handles) {
			return true
		}
		if key := calleeKey(call, pkg); key != "" {
			callees = append(callees, key)
		}
		return true
	})
	return callees
}

// ResetState drops the helpers of the previous root.
func (r *SubtestFixtureCleanedEarlyRule) ResetState() { r.cleaners = nil }

// cleansUpOn reports a body calling Cleanup on one of the handles.
func cleansUpOn(body *ast.BlockStmt, handles map[string]bool) bool {
	found := false
	ownNodes(body, func(n ast.Node) bool {
		if stmt, ok := n.(*ast.ExprStmt); ok && cleanupRegistration(stmt, handles) {
			found = true
		}
		return !found
	})
	return found
}

// AnalyzeFile reports the subtest fixtures a later sibling uses.
func (r *SubtestFixtureCleanedEarlyRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if len(r.cleaners) == 0 || !goTestFile(ctx) {
		return nil
	}
	pkg := ctx.GoAST.Name.Name
	var violations []*core.Violation
	for _, tb := range testingBodies(ctx.GoAST) {
		forEachOwnStatementList(tb.body, func(list []ast.Stmt) {
			for i, stmt := range list {
				lit, param := subtestLiteral(stmt, tb.handles)
				if lit == nil {
					continue
				}
				for _, assign := range r.fixtureAssignments(lit, param, pkg) {
					target, ok := assign.Lhs[0].(*ast.Ident)
					if !ok {
						continue
					}
					name := target.Name
					user := laterSubtestUsing(list[i+1:], tb.handles, name)
					if user == nil {
						continue
					}
					line := ctx.LineFor(assign)
					if !ctx.IsSuppressed(line, r.Name()) {
						violations = append(violations, testReport(r.BaseRule, ctx, line,
							name+" is made in a subtest whose cleanup deletes it when the subtest ends — the sibling at line "+strconv.Itoa(ctx.LineFor(user))+" uses what is already gone",
							"Make the fixture in the parent test (pass the parent's t), so its cleanup runs after all subtests"))
					}
				}
			}
		})
	}
	return violations
}

// subtestLiteral returns the literal of <handle>.Run(name, func(p *testing.T) {...})
// and the name of its handle.
func subtestLiteral(stmt ast.Stmt, handles map[string]bool) (*ast.FuncLit, string) {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return nil, ""
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return nil, ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Run" {
		return nil, ""
	}
	if receiver, ok := sel.X.(*ast.Ident); !ok || !handles[receiver.Name] {
		return nil, ""
	}
	lit, ok := call.Args[1].(*ast.FuncLit)
	if !ok || lit.Type.Params == nil || len(lit.Type.Params.List) != 1 || len(lit.Type.Params.List[0].Names) != 1 {
		return nil, ""
	}
	return lit, lit.Type.Params.List[0].Names[0].Name
}

// fixtureAssignments returns the assignments in the subtest of an outer
// variable from a cleaning helper given the subtest's handle.
func (r *SubtestFixtureCleanedEarlyRule) fixtureAssignments(lit *ast.FuncLit, param, pkg string) []*ast.AssignStmt {
	declared := localNames(lit.Body)
	var found []*ast.AssignStmt
	ownNodes(lit.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		target, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || declared[target.Name] {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if ok && r.cleaners[calleeKey(call, pkg)] && passesIdent(call, param) {
			found = append(found, assign)
		}
		return true
	})
	return found
}

// calleeKey is "package.Name" of a call to a package function.
func calleeKey(call *ast.CallExpr, pkg string) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return pkg + "." + fun.Name
	case *ast.SelectorExpr:
		if qualifier, ok := fun.X.(*ast.Ident); ok {
			return qualifier.Name + "." + fun.Sel.Name
		}
	}
	return ""
}

func passesIdent(call *ast.CallExpr, name string) bool {
	for _, arg := range call.Args {
		if isIdentNamed(arg, name) {
			return true
		}
	}
	return false
}

// localNames returns the names a body declares itself.
func localNames(body *ast.BlockStmt) map[string]bool {
	names := make(map[string]bool)
	ownNodes(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						names[ident.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, ident := range node.Names {
				names[ident.Name] = true
			}
		}
		return true
	})
	return names
}

// laterSubtestUsing returns a later sibling subtest that reads the variable.
func laterSubtestUsing(list []ast.Stmt, handles map[string]bool, name string) ast.Stmt {
	for _, stmt := range list {
		lit, _ := subtestLiteral(stmt, handles)
		if lit == nil || localNames(lit.Body)[name] {
			continue
		}
		used := false
		ast.Inspect(lit.Body, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
				used = true
			}
			return !used
		})
		if used {
			return stmt
		}
	}
	return nil
}
