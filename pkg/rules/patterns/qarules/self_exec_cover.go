package qarules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strings"
)

// A start of the own executable as the fallback of an environment variable,
// or from a package variable, starts something else where the test sets the
// variable first. That counts only on the path to the start: a statement
// that sets it whenever it runs - t.Setenv, os.Setenv, an assignment, a call
// of a test file function that does so - before the call, in a block around
// it; or TestMain before m.Run.

// selfExecSetter is a statement that sets labels whenever it runs, with the
// block it runs in.
type selfExecSetter struct {
	labels []string
	end    token.Pos
	block  [2]token.Pos
}

// setters returns the statements of a body that set labels.
func (a *selfExecAnalysis) setters(b *selfExecBody) []selfExecSetter {
	if setters, ok := a.setterOf[b]; ok {
		return setters
	}
	setters := []selfExecSetter{}
	a.setterOf[b] = setters
	if b.decl == nil {
		return setters
	}
	ast.Inspect(b.decl.Body, func(n ast.Node) bool {
		var list []ast.Stmt
		switch node := n.(type) {
		case *ast.BlockStmt:
			list = node.List
		case *ast.CaseClause:
			list = node.Body
		case *ast.CommClause:
			list = node.Body
		}
		for _, stmt := range list {
			if labels := a.stmtSets(b, stmt); len(labels) > 0 {
				setters = append(setters, selfExecSetter{labels: labels, end: stmt.End(), block: [2]token.Pos{n.Pos(), n.End()}})
			}
		}
		return true
	})
	a.setterOf[b] = setters
	return setters
}

// covers returns the labels a body sets before a position whenever it gets
// there.
func (a *selfExecAnalysis) covers(b *selfExecBody, pos token.Pos) []string {
	var labels []string
	for _, setter := range a.setters(b) {
		if setter.end <= pos && setter.block[0] <= pos && pos < setter.block[1] {
			labels = selfExecUnion(labels, setter.labels)
		}
	}
	return labels
}

// stmtSets returns the labels a statement sets whenever it runs: a Setenv
// of a constant name to a value, an assignment of a package variable to
// what is not the own path, a call of a test file function that does so in
// its own body.
func (a *selfExecAnalysis) stmtSets(b *selfExecBody, stmt ast.Stmt) []string {
	var node ast.Node
	switch s := stmt.(type) {
	case *ast.ExprStmt, *ast.AssignStmt:
		node = s
	case *ast.IfStmt:
		node = s.Init
	}
	if node == nil {
		return nil
	}
	var labels []string
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if name, ok := a.setenvName(b, x); ok {
				labels = selfExecUnion(labels, []string{name})
			}
			for _, callee := range a.resolve(b, x) {
				if callee.tests != nil {
					labels = selfExecUnion(labels, a.helperSets(callee))
				}
			}
		case *ast.AssignStmt:
			if x.Tok != token.ASSIGN || len(x.Lhs) != len(x.Rhs) {
				return true
			}
			for i, lhs := range x.Lhs {
				if _, label, ok := a.packageVar(b, lhs); ok && !a.restores(b, x.Rhs[i]) {
					labels = selfExecUnion(labels, []string{label})
				}
			}
		}
		return true
	})
	return labels
}

// restores reports a value that puts back what a package variable held:
// the own path, or exec.Command or exec.CommandContext.
func (a *selfExecAnalysis) restores(b *selfExecBody, value ast.Expr) bool {
	if a.origin(b, value).self {
		return true
	}
	sel, ok := ast.Unparen(value).(*ast.SelectorExpr)
	return ok && (sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") && selfExecMember(b.file, b.info, sel, "os/exec")
}

// helperSets returns the labels a test file function sets in its own body
// whenever it runs.
func (a *selfExecAnalysis) helperSets(b *selfExecBody) []string {
	if labels, ok := a.setsOf[b]; ok {
		return labels
	}
	a.setsOf[b] = nil
	var labels []string
	for _, stmt := range b.decl.Body.List {
		labels = selfExecUnion(labels, a.stmtSets(b, stmt))
	}
	a.setsOf[b] = labels
	return labels
}

// mainSets returns the labels the TestMain of a directory sets before
// m.Run.
func (a *selfExecAnalysis) mainSets(dir string) []string {
	main := a.index.mains[dir]
	if main == nil {
		return nil
	}
	m := ""
	if params := main.decl.Type.Params.List; len(params) == 1 && len(params[0].Names) == 1 {
		m = params[0].Names[0].Name
	}
	var labels []string
	for _, stmt := range main.decl.Body.List {
		if selfExecRunsSuite(stmt, m) {
			break
		}
		labels = selfExecUnion(labels, a.stmtSets(main, stmt))
	}
	return labels
}

// selfExecRunSets returns the environment variables a run has set to a
// value that is never empty.
func selfExecRunSets(run *selfExecRun) []string {
	var labels []string
	for name, value := range run.env {
		if value.s != "" || value.more {
			labels = append(labels, name)
		}
	}
	slices.Sort(labels)
	return labels
}

// setenvName returns the variable a Setenv call sets to a value the
// analysis proves is not empty: a constant, a value with a part that is
// never empty, the result of a call checked for its error that is never
// empty then. A value that may be empty (an unchecked exec.LookPath,
// another variable of the environment) sets nothing.
func (a *selfExecAnalysis) setenvName(b *selfExecBody, call *ast.CallExpr) (string, bool) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Setenv" || len(call.Args) != 2 {
		return "", false
	}
	if value := a.str(b, call.Args[1], 0); value.s == "" && !value.more {
		return "", false
	}
	return selfExecString(b, call.Args[0])
}

// packageVar returns the key and the label of the package variable an
// expression names: by its object in typed code; in a test file a variable
// of the test files, or of a package of the module by its name or selector.
func (a *selfExecAnalysis) packageVar(b *selfExecBody, expr ast.Expr) (any, string, bool) {
	expr = ast.Unparen(expr)
	if b.info != nil {
		var id *ast.Ident
		switch node := expr.(type) {
		case *ast.Ident:
			id = node
		case *ast.SelectorExpr:
			id = node.Sel
		default:
			return nil, "", false
		}
		v, ok := b.info.ObjectOf(id).(*types.Var)
		if !ok || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
			return nil, "", false
		}
		return v, selfExecVarLabel(v), true
	}
	if b.tests == nil {
		return nil, "", false
	}
	idx := b.tests.idx
	switch node := expr.(type) {
	case *ast.Ident:
		if b.decl != nil && b.declaresAt(node.Name, node.Pos()) {
			return nil, "", false
		}
		if b.tests.vars[node.Name] {
			return selfExecTestVar{b.tests, node.Name}, "var:" + b.tests.dir + "#" + node.Name, true
		}
		if b.tests.internal() {
			if v := idx.pkgVar(idx.pkgOfDir[b.tests.dir], node.Name); v != nil {
				return v, selfExecVarLabel(v), true
			}
		}
	case *ast.SelectorExpr:
		if importPath, ok := idx.qualifier(b, node); ok {
			if v := idx.pkgVar(importPath, node.Sel.Name); v != nil {
				return v, selfExecVarLabel(v), true
			}
		}
	}
	return nil, "", false
}

// qualifier returns the import path a selector of a test file names a
// member of.
func (idx *selfExecIndex) qualifier(b *selfExecBody, sel *ast.SelectorExpr) (string, bool) {
	q, ok := sel.X.(*ast.Ident)
	if !ok || b.file == nil || (b.decl != nil && b.declaresAt(q.Name, q.Pos())) {
		return "", false
	}
	return idx.importPath(b.file, q.Name)
}

// constOf returns the value of a string constant of a module package.
func (idx *selfExecIndex) constOf(pkgPath, name string) (string, bool) {
	pkg := idx.pkgTypes[pkgPath]
	if pkg == nil {
		return "", false
	}
	c, ok := pkg.Scope().Lookup(name).(*types.Const)
	if !ok {
		return "", false
	}
	value, ok := selfExecConstString(c)
	return value, ok
}

// selfExecConstString returns the value of a string constant.
func selfExecConstString(c *types.Const) (string, bool) {
	if c.Val().Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(c.Val()), true
}

// pkgVar returns a package variable of a module package.
func (idx *selfExecIndex) pkgVar(pkgPath, name string) *types.Var {
	pkg := idx.pkgTypes[pkgPath]
	if pkg == nil {
		return nil
	}
	v, _ := pkg.Scope().Lookup(name).(*types.Var)
	return v
}

// relevantBodies finds the bodies that start the own executable or call
// one that does, and the labels of the starts.
func (a *selfExecAnalysis) relevantBodies() {
	a.relevant, a.labels = map[*selfExecBody]bool{}, map[string]bool{}
	callers := map[*selfExecBody][]*selfExecBody{}
	var stack []*selfExecBody
	for _, b := range a.bodies {
		if points := a.points(b); len(points) > 0 {
			a.relevant[b] = true
			stack = append(stack, b)
			for _, point := range points {
				for _, label := range point.env {
					a.labels[label] = true
				}
			}
		}
		for _, call := range a.facts(b).calls {
			for _, callee := range a.resolve(b, call) {
				callers[callee] = append(callers[callee], b)
			}
		}
	}
	// The callers of a relevant body are relevant; the order does not matter.
	for len(stack) > 0 {
		last := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, caller := range callers[last] {
			if !a.relevant[caller] {
				a.relevant[caller] = true
				stack = append(stack, caller)
			}
		}
	}
}

// coveredAt returns the labels set on the path to a position of a node:
// those of the node and those its body sets before the position.
func (a *selfExecAnalysis) coveredAt(node selfExecNode, pos token.Pos) string {
	var labels []string
	if node.covered != "" {
		labels = strings.Split(node.covered, "\x00")
	}
	for _, label := range a.covers(node.body, pos) {
		if a.labels[label] {
			labels = selfExecUnion(labels, []string{label})
		}
	}
	slices.Sort(labels)
	return strings.Join(labels, "\x00")
}

// labelSet encodes labels, those of interest, as a node holds them.
func (a *selfExecAnalysis) labelSet(labels []string) string {
	var kept []string
	for _, label := range labels {
		if a.labels[label] {
			kept = selfExecUnion(kept, []string{label})
		}
	}
	slices.Sort(kept)
	return strings.Join(kept, "\x00")
}
