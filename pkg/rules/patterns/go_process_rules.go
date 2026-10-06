package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewAuthHeaderSentToResponseURLRule())
	rules.Register(NewProcessKilledWithoutWaitRule())
	rules.Register(NewRemoveBeforeFailedReplacementRule())
}

// NewAuthHeaderSentToResponseURLRule reports a loop that follows a URL taken
// from a response through a call that always attaches the credentials:
//
//	for path != "" {
//	    if err := c.Get(path, &p); err != nil { ... }  // sets Authorization
//	    path = p.Next                                    // the server names the next URL
//	}
//
// A pager or a redirect from a compromised or misconfigured server then
// receives the token: the header goes to whatever host the answer names.
func NewAuthHeaderSentToResponseURLRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule("auth-header-sent-to-response-url", "security",
			"Detects a loop that follows a URL from a decoded response (next, href, url) through a call that always sets the Authorization header — the token goes to any host the server names",
			core.SeverityHigh),
		suggestion: "Set the credentials only for the API's own host (compare the scheme and host of the request URL), or refuse a next URL outside it",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		senders := authSenders(decls)
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			return responseURLLoops(scope.info, fn, senders)
		}
	}
	return r
}

// authSenders returns the functions that attach credentials to every request
// they make: a Header.Set/Add of Authorization or a SetBasicAuth outside any
// if, directly or through such a function of the project.
func authSenders(decls map[*types.Func]typedFuncDecl) map[*types.Func]bool {
	senders := map[*types.Func]bool{}
	for fn, decl := range decls {
		if setsAuthUnconditionally(decl.decl.Body) {
			senders[fn] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for fn, decl := range decls {
			if senders[fn] {
				continue
			}
			if callsUnconditionally(decl.decl.Body, decl.info, senders) {
				senders[fn] = true
				changed = true
			}
		}
	}
	return senders
}

// walkUnconditional visits the nodes of a body outside if statements and
// function literals.
func walkUnconditional(body *ast.BlockStmt, visit func(ast.Node) bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.IfStmt, *ast.FuncLit, *ast.SwitchStmt, *ast.TypeSwitchStmt:
			return false
		}
		return n == nil || visit(n)
	})
}

func setsAuthUnconditionally(body *ast.BlockStmt) bool {
	found := false
	walkUnconditional(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !found
		}
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return !found
		}
		switch selector.Sel.Name {
		case "SetBasicAuth":
			found = true
		case "Set", "Add":
			if len(call.Args) == 2 && strings.HasSuffix(types.ExprString(selector.X), "Header") && isAuthorizationName(call.Args[0]) {
				found = true
			}
		}
		return !found
	})
	return found
}

func isAuthorizationName(expr ast.Expr) bool {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	value := constant.StringVal(constant.MakeFromLiteral(lit.Value, lit.Kind, 0))
	return strings.EqualFold(value, "Authorization")
}

func callsUnconditionally(body *ast.BlockStmt, info *types.Info, senders map[*types.Func]bool) bool {
	found := false
	walkUnconditional(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if fn := staticFunc(info, call); fn != nil && senders[fn.Origin()] {
				found = true
			}
		}
		return !found
	})
	return found
}

// urlFieldWords name a field of a response that carries a URL to follow.
var urlFieldWords = []string{"next", "url", "href", "link", "location", "redirect"}

// responseURLLoops reports the credential-sending calls of loops that feed
// them a URL read back from a decoded response.
func responseURLLoops(info *types.Info, fn *ast.FuncDecl, senders map[*types.Func]bool) []funcFinding {
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch loop := n.(type) {
		case *ast.ForStmt:
			body = loop.Body
		case *ast.RangeStmt:
			body = loop.Body
		default:
			return true
		}
		followed := followedURLs(body, info)
		if len(followed) == 0 {
			return true
		}
		ast.Inspect(body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := staticFunc(info, call)
			if callee == nil || !senders[callee.Origin()] {
				return true
			}
			for _, arg := range call.Args {
				if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && followed[info.ObjectOf(ident)] {
					found = append(found, funcFinding{call, callee.Name() + " always sends the Authorization header, and the loop feeds it " + ident.Name + ", a URL read from the server's answer — the token goes to any host the answer names"})
				}
			}
			return true
		})
		return true
	})
	return found
}

// followedURLs returns the variables the loop body sets from a URL field of a
// value it decodes into: path = p.Next, where &p went to a call.
func followedURLs(body *ast.BlockStmt, info *types.Info) map[types.Object]bool {
	decoded := map[types.Object]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if unary, ok := n.(*ast.UnaryExpr); ok && unary.Op == token.AND {
			if ident, ok := ast.Unparen(unary.X).(*ast.Ident); ok {
				decoded[info.ObjectOf(ident)] = true
			}
		}
		return true
	})
	followed := map[types.Object]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			selector, ok := ast.Unparen(rhs).(*ast.SelectorExpr)
			if !ok || !isURLFieldName(selector.Sel.Name) {
				continue
			}
			root := rootIdent(selector)
			target, ok := assign.Lhs[i].(*ast.Ident)
			if root == nil || !ok || !decoded[info.ObjectOf(root)] || !isStringType(info.TypeOf(selector)) {
				continue
			}
			followed[info.ObjectOf(target)] = true
		}
		return true
	})
	return followed
}

func isURLFieldName(name string) bool {
	lower := strings.ToLower(name)
	for _, word := range urlFieldWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// NewProcessKilledWithoutWaitRule reports a child process killed on a path
// that then returns without waiting for it:
//
//	if err != nil {
//	    killProcess(cmd)   // cmd.Process.Kill()
//	    return nil, err    // no cmd.Wait(): a zombie, open pipes
//	}
//
// Kill only sends the signal; Wait reaps the process and releases its pipes
// and the goroutines copying its output.
func NewProcessKilledWithoutWaitRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule("process-killed-without-wait", "patterns",
			"Detects an exec.Cmd killed on a path that returns without Wait — the process stays a zombie and its pipes stay open",
			core.SeverityMedium),
		suggestion: "Call cmd.Wait() after Kill on that path, or use the stop function the starter returned (it kills and waits)",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		killers := processKillers(decls)
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			return killedWithoutWait(scope.info, fn, killers)
		}
	}
	return r
}

// processKillers returns the functions that kill the exec.Cmd parameter at
// the returned index and never wait for it.
func processKillers(decls map[*types.Func]typedFuncDecl) map[*types.Func]int {
	killers := map[*types.Func]int{}
	for fn, decl := range decls {
		params := fn.Signature().Params()
		for i := 0; i < params.Len(); i++ {
			param := params.At(i)
			if !isExecCmd(param.Type()) {
				continue
			}
			if killsProcess(decl.decl.Body, param, decl.info) && !waitsFor(decl.decl.Body, param, decl.info) {
				killers[fn] = i
			}
		}
	}
	return killers
}

func isExecCmd(t types.Type) bool {
	pointer, ok := t.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "os/exec" && named.Obj().Name() == "Cmd"
}

// killsProcess reports whether the node calls cmd.Process.Kill().
func killsProcess(node ast.Node, cmd types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isProcessKill(call, cmd, info) {
			found = true
		}
		return !found
	})
	return found
}

func isProcessKill(call *ast.CallExpr, cmd types.Object, info *types.Info) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Kill" {
		return false
	}
	process, ok := ast.Unparen(selector.X).(*ast.SelectorExpr)
	if !ok || process.Sel.Name != "Process" {
		return false
	}
	ident, ok := ast.Unparen(process.X).(*ast.Ident)
	return ok && info.ObjectOf(ident) == cmd
}

// waitsFor reports whether the node calls cmd.Wait().
func waitsFor(node ast.Node, cmd types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isMethodOn(call, cmd, info, "Wait") {
			found = true
		}
		return !found
	})
	return found
}

// killedWithoutWait reports a kill in a block that ends in a return with no
// Wait after the kill and no deferred Wait in the function.
func killedWithoutWait(info *types.Info, fn *ast.FuncDecl, killers map[*types.Func]int) []funcFinding {
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok || len(block.List) == 0 {
			return true
		}
		ret, ok := block.List[len(block.List)-1].(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List[:len(block.List)-1] {
			call, cmd := killCall(stmt, info, killers)
			if call == nil {
				continue
			}
			rest := &ast.BlockStmt{List: block.List[i+1:]}
			if waitsFor(rest, cmd, info) || returnsObject(ret, cmd, info) || defersWait(fn.Body, cmd, info) {
				continue
			}
			found = append(found, funcFinding{call, "Process " + cmd.Name() + " is killed and the function returns without Wait — the process stays a zombie and its pipes stay open"})
		}
		return true
	})
	return found
}

// killCall returns the kill a statement makes and the command it kills:
// cmd.Process.Kill() or a call of a killer function.
func killCall(stmt ast.Stmt, info *types.Info, killers map[*types.Func]int) (*ast.CallExpr, types.Object) {
	var expr ast.Expr
	switch node := stmt.(type) {
	case *ast.ExprStmt:
		expr = node.X
	case *ast.AssignStmt:
		if len(node.Rhs) == 1 {
			expr = node.Rhs[0]
		}
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return nil, nil
	}
	if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && selector.Sel.Name == "Kill" {
		if process, ok := ast.Unparen(selector.X).(*ast.SelectorExpr); ok && process.Sel.Name == "Process" {
			if ident, ok := ast.Unparen(process.X).(*ast.Ident); ok && isExecCmd(info.TypeOf(ident)) {
				return call, info.ObjectOf(ident)
			}
		}
	}
	callee := staticFunc(info, call)
	if callee == nil {
		return nil, nil
	}
	index, ok := killers[callee.Origin()]
	if !ok || index >= len(call.Args) {
		return nil, nil
	}
	if ident, ok := ast.Unparen(call.Args[index]).(*ast.Ident); ok {
		return call, info.ObjectOf(ident)
	}
	return nil, nil
}

func returnsObject(ret *ast.ReturnStmt, obj types.Object, info *types.Info) bool {
	for _, result := range ret.Results {
		if ident, ok := ast.Unparen(result).(*ast.Ident); ok && info.ObjectOf(ident) == obj {
			return true
		}
	}
	return false
}

func defersWait(body *ast.BlockStmt, cmd types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if stmt, ok := n.(*ast.DeferStmt); ok && waitsFor(stmt, cmd, info) {
			found = true
		}
		return !found
	})
	return found
}

// NewRemoveBeforeFailedReplacementRule reports a file removed before its
// replacement is fetched, when a failed fetch is only logged:
//
//	os.Remove(dst)
//	if _, err := c.Download(u, dst); err != nil {
//	    slog.Warn("download", "err", err)
//	    return nil
//	}
//
// The old copy is gone, the new one never came, and the caller hears success.
func NewRemoveBeforeFailedReplacementRule() *typedFuncRule {
	return &typedFuncRule{
		BaseRule: rules.NewBaseRule("remove-before-failed-replacement", "patterns",
			"Detects a file removed before its replacement is written into the same path, where a failed write is only logged — the old copy is lost and the caller hears success",
			core.SeverityMedium),
		suggestion: "Write the replacement into a temporary file next to it and rename it into place, or return the error of the failed write",
		check:      removeBeforeFailedReplacement,
	}
}

func removeBeforeFailedReplacement(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List {
			remove := removeCall(stmt, info)
			if remove == nil || len(remove.Args) != 1 {
				continue
			}
			path := types.ExprString(remove.Args[0])
			if replacementFailureLogged(block.List[i+1:], path, info) {
				found = append(found, funcFinding{remove, path + " is removed before its replacement is written, and a failed write is only logged — the old copy is lost and the caller hears success"})
			}
		}
		return true
	})
	return found
}

// removeCall returns os.Remove/RemoveAll of a statement, in an if init too.
func removeCall(stmt ast.Stmt, info *types.Info) *ast.CallExpr {
	var expr ast.Expr
	switch node := stmt.(type) {
	case *ast.ExprStmt:
		expr = node.X
	case *ast.AssignStmt:
		if len(node.Rhs) == 1 {
			expr = node.Rhs[0]
		}
	case *ast.IfStmt:
		if init, ok := node.Init.(*ast.AssignStmt); ok && len(init.Rhs) == 1 {
			expr = init.Rhs[0]
		}
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || !calleeIn(call, info, "os", "Remove", "RemoveAll") {
		return nil
	}
	return call
}

// replacementFailureLogged reports a later call handed the path whose error
// branch does not return an error: it logs, and returns nil or nothing.
func replacementFailureLogged(stmts []ast.Stmt, path string, info *types.Info) bool {
	for i, stmt := range stmts {
		call, errObj := errorCall(stmt, info)
		if call == nil || !argsSpell(call.Args, path) {
			continue
		}
		branch := replacementErrBranch(stmt, stmts[i+1:], errObj, info)
		return branch != nil && !returnsNonNilError(branch)
	}
	return false
}

// errorCall returns a call whose error result the statement stores, and the
// error variable.
func errorCall(stmt ast.Stmt, info *types.Info) (*ast.CallExpr, types.Object) {
	assign, ok := stmt.(*ast.AssignStmt)
	if ifStmt, isIf := stmt.(*ast.IfStmt); isIf {
		assign, ok = ifStmt.Init.(*ast.AssignStmt)
	}
	if !ok || len(assign.Rhs) != 1 {
		return nil, nil
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return nil, nil
	}
	last, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
	if !ok || !isErrorType(info.TypeOf(last)) {
		return nil, nil
	}
	return call, info.ObjectOf(last)
}

func argsSpell(args []ast.Expr, path string) bool {
	for _, arg := range args {
		if types.ExprString(arg) == path {
			return true
		}
	}
	return false
}

// replacementErrBranch returns the body of the if err != nil that handles the error: the
// statement's own if, or the next statement.
func replacementErrBranch(stmt ast.Stmt, next []ast.Stmt, errObj types.Object, info *types.Info) *ast.BlockStmt {
	ifStmt, ok := stmt.(*ast.IfStmt)
	if !ok && len(next) > 0 {
		ifStmt, ok = next[0].(*ast.IfStmt)
	}
	if !ok || errorNotNilObj(ifStmt.Cond, info) != errObj {
		return nil
	}
	return ifStmt.Body
}

// returnsNonNilError reports whether the branch returns something other than
// nil as its last result, or panics or exits.
func returnsNonNilError(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) > 0 && !isNilIdent(node.Results[len(node.Results)-1]) {
				found = true
			}
		case *ast.CallExpr:
			if isIdent(node.Fun, "panic") || strings.HasSuffix(types.ExprString(node.Fun), "Exit") || strings.HasSuffix(types.ExprString(node.Fun), "Fatal") {
				found = true
			}
		}
		return !found
	})
	return found
}
