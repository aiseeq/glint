package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/types/typeutil"
)

func init() {
	rules.Register(NewUnboundedRequestBodyReadRule())
}

// UnboundedRequestBodyReadRule detects a handler that reads the request body
// whole (json.NewDecoder, io.ReadAll, io.Copy) without http.MaxBytesReader, in
// a project whose other handlers do limit their bodies and that has no global
// body-limit middleware:
//
//	func (c *Codes) validate(w http.ResponseWriter, req *http.Request) {
//	    var request codeRequest
//	    json.NewDecoder(req.Body).Decode(&request)   // any size, held in memory
//
// The limit set by hand in some handlers shows the project relies on it; the
// handler that forgot it lets a client stream as much as the proxy in front
// allows, and a public endpoint does so without authentication. A project
// that limits nowhere has another policy (a proxy cap) and is not judged. A
// global limit is a middleware assigning MaxBytesReader to the body and
// calling the next handler, http.MaxBytesHandler, or a framework's body-limit
// middleware (chi RequestSize, echo BodyLimit).
type UnboundedRequestBodyReadRule struct {
	*rules.BaseRule
}

// NewUnboundedRequestBodyReadRule creates the rule.
func NewUnboundedRequestBodyReadRule() *UnboundedRequestBodyReadRule {
	return &UnboundedRequestBodyReadRule{
		BaseRule: rules.NewBaseRule(
			"unbounded-request-body-read",
			"patterns",
			"Detects a handler reading the request body without http.MaxBytesReader in a project whose other handlers set one and that has no global body-limit middleware",
			core.SeverityMedium,
		),
	}
}

// RequiresSSA reports that typed syntax is enough.
func (r *UnboundedRequestBodyReadRule) RequiresSSA() bool { return false }

// AnalyzeFile is a no-op: the project's limiting policy decides.
func (r *UnboundedRequestBodyReadRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// AnalyzeGoProject reports unlimited body reads when the project limits
// bodies per handler and not globally.
func (r *UnboundedRequestBodyReadRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	perHandler, global := bodyLimitPolicy(ctx)
	if !perHandler || global {
		return nil, nil
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		check := &bodyReadCheck{rule: r, file: file, info: info}
		for _, decl := range file.GoAST.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				check.scope(fn.Type, fn.Body, false, nil)
			}
		}
		return check.violations
	})
}

// bodyLimitMiddlewares are the framework functions, by package path suffix,
// that limit every request body.
var bodyLimitMiddlewares = map[string]string{
	"go-chi/chi/middleware":    "RequestSize",
	"go-chi/chi/v5/middleware": "RequestSize",
	"labstack/echo/middleware": "BodyLimit",
	"echo/v4/middleware":       "BodyLimit",
}

// bodyLimitPolicy reports whether some handler limits its own body and
// whether a middleware limits all of them.
func bodyLimitPolicy(ctx *core.GoProjectContext) (perHandler, global bool) {
	if ctx == nil {
		return false, false
	}
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		info := pkgCtx.Package.TypesInfo
		for _, file := range pkgCtx.Package.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				var body *ast.BlockStmt
				switch node := n.(type) {
				case *ast.FuncDecl:
					body = node.Body
				case *ast.FuncLit:
					body = node.Body
				case *ast.CallExpr:
					if globalLimitCall(file, info, node) {
						global = true
					}
					return true
				default:
					return true
				}
				if body == nil || !limitsBody(file, info, body) {
					return true
				}
				if callsServeHTTP(body) {
					global = true
				} else {
					perHandler = true
				}
				return true
			})
		}
	}
	return perHandler, global
}

// globalLimitCall reports http.MaxBytesHandler or a framework body limit.
func globalLimitCall(file *ast.File, info *types.Info, call *ast.CallExpr) bool {
	if isPackageFuncCall(file, info, call, "net/http", "MaxBytesHandler") {
		return true
	}
	fn := typeutil.Callee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	for suffix, name := range bodyLimitMiddlewares {
		if strings.HasSuffix(fn.Pkg().Path(), suffix) && fn.Name() == name {
			return true
		}
	}
	return false
}

// limitsBody reports a body, outside nested literals, that wraps a request
// body in http.MaxBytesReader.
func limitsBody(file *ast.File, info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if isPackageFuncCall(file, info, node, "net/http", "MaxBytesReader") && len(node.Args) == 3 && requestBody(info, node.Args[1]) != "" {
				found = true
			}
		}
		return !found
	})
	return found
}

// callsServeHTTP reports a body passing the request on to a next handler.
func callsServeHTTP(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "ServeHTTP" {
				found = true
			}
		}
		return !found
	})
	return found
}

// requestBody returns the source of the request expression when expr is
// <request>.Body of an *http.Request, "" otherwise.
func requestBody(info *types.Info, expr ast.Expr) string {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Body" || !isPointerToNamedType(info.TypeOf(sel.X), "net/http", "Request") {
		return ""
	}
	return types.ExprString(sel.X)
}

// bodyReadCheck walks one declared function and its literals.
type bodyReadCheck struct {
	rule       *UnboundedRequestBodyReadRule
	file       *core.FileContext
	info       *types.Info
	violations []*core.Violation
}

// scope checks a function body. A literal inherits being a handler and the
// bodies already replaced from the function it is written in.
func (c *bodyReadCheck) scope(ftype *ast.FuncType, body *ast.BlockStmt, handler bool, replaced map[string]bool) {
	handler = handler || servesIncomingRequest(c.info, ftype)
	own := map[string]bool{}
	for request := range replaced {
		own[request] = true
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if request := requestBody(c.info, lhs); request != "" {
					own[request] = true
				}
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			c.scope(node.Type, node.Body, handler, own)
			return false
		case *ast.CallExpr:
			if !handler {
				return true
			}
			if request := c.wholeBodyRead(node); request != "" && !own[request] {
				c.report(node)
			}
		}
		return true
	})
}

// wholeBodyRead returns the request whose body the call reads to the end.
func (c *bodyReadCheck) wholeBodyRead(call *ast.CallExpr) string {
	file := c.file.GoAST
	switch {
	case isPackageFuncCall(file, c.info, call, "encoding/json", "NewDecoder"),
		isPackageFuncCall(file, c.info, call, "encoding/xml", "NewDecoder"),
		isPackageFuncCall(file, c.info, call, "io", "ReadAll"),
		isPackageFuncCall(file, c.info, call, "io/ioutil", "ReadAll"):
		if len(call.Args) == 1 {
			return requestBody(c.info, call.Args[0])
		}
	case isPackageFuncCall(file, c.info, call, "io", "Copy", "CopyBuffer"):
		if len(call.Args) >= 2 {
			return requestBody(c.info, call.Args[1])
		}
	}
	return ""
}

func (c *bodyReadCheck) report(call *ast.CallExpr) {
	line := c.file.LineFor(call)
	if c.file.IsSuppressed(line, c.rule.Name()) {
		return
	}
	v := c.rule.CreateViolation(c.file.RelPath, line,
		"Request body read without http.MaxBytesReader, while other handlers of the project limit theirs and no middleware limits all — a client can send a body of any size and the handler holds it in memory")
	v.WithCode(strings.TrimSpace(c.file.GetLine(line)))
	v.WithSuggestion("Wrap the body first (r.Body = http.MaxBytesReader(w, r.Body, limit)), or limit every body in one middleware")
	c.violations = append(c.violations, v)
}

// servesIncomingRequest reports a handler signature: it takes an
// http.ResponseWriter, or an *http.Request without returning an
// *http.Response (a RoundTripper reads its own outgoing request).
func servesIncomingRequest(info *types.Info, ftype *ast.FuncType) bool {
	if ftype == nil || ftype.Params == nil {
		return false
	}
	request := false
	for _, param := range ftype.Params.List {
		t := info.TypeOf(param.Type)
		if isNamedType(t, "net/http", "ResponseWriter") {
			return true
		}
		request = request || isPointerToNamedType(t, "net/http", "Request")
	}
	if !request {
		return false
	}
	if ftype.Results != nil {
		for _, result := range ftype.Results.List {
			if isPointerToNamedType(info.TypeOf(result.Type), "net/http", "Response") {
				return false
			}
		}
	}
	return true
}
