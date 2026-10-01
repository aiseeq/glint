package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewHandlerCounterRaceRule())
}

// HandlerCounterRaceRule detects a counter shared by all requests that request
// code bumps with ++ or += without a mutex or sync/atomic:
//
//	func (m *SizeLimit) check(r *http.Request) bool {
//	    if r.ContentLength > m.max {
//	        m.violations++   // every request runs this concurrently
//	        ...
//
// net/http serves each request on its own goroutine, so the receiver of a
// handler, a middleware or one of their request-taking helpers is shared: the
// unsynchronized read-modify-write loses updates and is a data race.
//
// Request code is a function or literal that takes an http.ResponseWriter or
// an *http.Request, and the literals (goroutines, callbacks) inside one. The
// counter is a numeric field reached from the method's receiver, or a
// package-level numeric variable. Code that takes a lock in the same function,
// and methods named …Locked, …NoLock, …Unsafe (called with the lock held by
// convention), are not reported, and neither are test doubles: packages named
// …test, …testutil, …testing and files with fake or mock in the name.
type HandlerCounterRaceRule struct {
	*rules.BaseRule
}

// NewHandlerCounterRaceRule creates the rule.
func NewHandlerCounterRaceRule() *HandlerCounterRaceRule {
	return &HandlerCounterRaceRule{
		BaseRule: rules.NewBaseRule(
			"handler-counter-race",
			"patterns",
			"Detects a shared counter bumped with ++ or += in HTTP request code without a mutex or sync/atomic — a data race that loses counts",
			core.SeverityHigh,
		),
	}
}

// RequiresSSA reports that typed syntax is enough.
func (r *HandlerCounterRaceRule) RequiresSSA() bool { return false }

// AnalyzeFile is a no-op: the counter's type and owner need type information.
func (r *HandlerCounterRaceRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// AnalyzeGoProject reports the unsynchronized counters of request code.
func (r *HandlerCounterRaceRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if testDoubleFile(file) {
			return nil
		}
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || hasLockedName(fn.Name.Name) {
				continue
			}
			check := &counterRaceCheck{rule: r, file: file, info: info, receiver: receiverObject(fn, info)}
			check.scope(fn.Type, fn.Body, false, false)
			violations = append(violations, check.violations...)
		}
		return violations
	})
}

// testDoubleFile reports a file of a test double: a package named …test,
// …testutil or …testing (the httptest convention), or a file with fake or
// mock in its name. A double serves the test that starts it, not traffic.
func testDoubleFile(file *core.FileContext) bool {
	pkg := file.GoAST.Name.Name
	for _, suffix := range []string{"test", "testutil", "testing"} {
		if strings.HasSuffix(pkg, suffix) {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(file.RelPath))
	return strings.Contains(base, "fake") || strings.Contains(base, "mock")
}

// counterRaceCheck walks one declared function and its literals.
type counterRaceCheck struct {
	rule       *HandlerCounterRaceRule
	file       *core.FileContext
	info       *types.Info
	receiver   types.Object
	violations []*core.Violation
}

// scope checks one function body. A literal inherits being request code and
// holding a lock from the function it is written in.
func (c *counterRaceCheck) scope(ftype *ast.FuncType, body *ast.BlockStmt, requestPath, locked bool) {
	requestPath = requestPath || servesRequest(c.info, ftype)
	locked = locked || takesLock(body)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			c.scope(node.Type, node.Body, requestPath, locked)
			return false
		case *ast.IncDecStmt:
			if requestPath && !locked {
				c.bumped(node, node.X)
			}
		case *ast.AssignStmt:
			if requestPath && !locked && (node.Tok == token.ADD_ASSIGN || node.Tok == token.SUB_ASSIGN) && len(node.Lhs) == 1 {
				c.bumped(node, node.Lhs[0])
			}
		}
		return true
	})
}

// bumped reports the statement when its target is a shared numeric counter.
func (c *counterRaceCheck) bumped(stmt ast.Stmt, target ast.Expr) {
	basic, ok := typeUnder(c.info, target).(*types.Basic)
	if !ok || basic.Info()&types.IsNumeric == 0 {
		return
	}
	name, shared := c.sharedCounter(target)
	if !shared {
		return
	}
	line := c.file.LineFor(stmt)
	if c.file.IsSuppressed(line, c.rule.Name()) {
		return
	}
	v := c.rule.CreateViolation(c.file.RelPath, line,
		"Counter '"+name+"' is shared by all requests and updated without a mutex or sync/atomic — concurrent requests race on it and lose counts")
	v.WithCode(strings.TrimSpace(c.file.GetLine(line)))
	v.WithSuggestion("Make the field an atomic.Int64 (or use atomic.AddInt64), or update it under the struct's mutex")
	v.WithContext("counter", name)
	c.violations = append(c.violations, v)
}

// sharedCounter reports a field chain rooted at the method's receiver or a
// package-level variable, with its source text.
func (c *counterRaceCheck) sharedCounter(target ast.Expr) (string, bool) {
	root := ast.Unparen(target)
	for {
		sel, ok := root.(*ast.SelectorExpr)
		if !ok {
			break
		}
		root = ast.Unparen(sel.X)
	}
	ident, ok := root.(*ast.Ident)
	if !ok {
		return "", false
	}
	obj := c.info.Uses[ident]
	if obj == nil {
		return "", false
	}
	text := types.ExprString(target)
	if _, field := ast.Unparen(target).(*ast.SelectorExpr); field && c.receiver != nil && obj == c.receiver {
		return text, true
	}
	variable, ok := obj.(*types.Var)
	return text, ok && variable.Pkg() != nil && variable.Parent() == variable.Pkg().Scope()
}

// receiverObject returns the named receiver of a method, nil otherwise.
func receiverObject(fn *ast.FuncDecl, info *types.Info) types.Object {
	if fn.Recv == nil || len(fn.Recv.List) == 0 || len(fn.Recv.List[0].Names) == 0 {
		return nil
	}
	return info.Defs[fn.Recv.List[0].Names[0]]
}

// servesRequest reports a signature taking an http.ResponseWriter or an
// *http.Request.
func servesRequest(info *types.Info, ftype *ast.FuncType) bool {
	if ftype == nil || ftype.Params == nil {
		return false
	}
	for _, param := range ftype.Params.List {
		t := info.TypeOf(param.Type)
		if isNamedType(t, "net/http", "ResponseWriter") || isPointerToNamedType(t, "net/http", "Request") {
			return true
		}
	}
	return false
}

// takesLock reports a body that calls Lock or RLock on something, outside
// nested literals.
func takesLock(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if sel, ok := ast.Unparen(node.Fun).(*ast.SelectorExpr); ok && (sel.Sel.Name == "Lock" || sel.Sel.Name == "RLock") {
				found = true
			}
		}
		return true
	})
	return found
}
