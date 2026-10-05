package patterns

import (
	"go/ast"
	"go/token"
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
// that limits nowhere may rely on a proxy cap: there only a raw read of the
// whole body (io.ReadAll, io.Copy) is reported, the copy a signature check or
// a webhook makes of everything the client sent, while a decoder that stops
// at the first malformed byte is left alone. A global limit is a middleware assigning MaxBytesReader to the body and
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
	if global {
		return nil, nil
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		check := &bodyReadCheck{rule: r, file: file, info: info, rawOnly: !perHandler}
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
	rawOnly    bool // the project limits nowhere: only raw whole-body reads count
	violations []*core.Violation
}

// scope checks a function body. A literal inherits being a handler and the
// bodies already replaced from the function it is written in. A body counts
// as replaced for the reads after the assignment to it: a handler that
// restores the body it has just read (r.Body = io.NopCloser(...)) did not
// limit that read.
func (c *bodyReadCheck) scope(ftype *ast.FuncType, body *ast.BlockStmt, handler bool, replaced map[string]token.Pos) {
	handler = handler || servesIncomingRequest(c.info, ftype)
	own := map[string]token.Pos{}
	for request, pos := range replaced {
		own[request] = pos
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if request := requestBody(c.info, lhs); request != "" {
					if pos, seen := own[request]; !seen || assign.Pos() < pos {
						own[request] = assign.Pos()
					}
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
			request, raw := c.wholeBodyRead(node)
			if request == "" || (!raw && c.rawOnly) {
				return true
			}
			if pos, seen := own[request]; !seen || pos > node.Pos() {
				c.report(node)
			}
		}
		return true
	})
}

// wholeBodyRead returns the request whose body the call reads to the end,
// and whether it copies the raw bytes rather than decoding them.
func (c *bodyReadCheck) wholeBodyRead(call *ast.CallExpr) (request string, raw bool) {
	file := c.file.GoAST
	switch {
	case isPackageFuncCall(file, c.info, call, "encoding/json", "NewDecoder"),
		isPackageFuncCall(file, c.info, call, "encoding/xml", "NewDecoder"):
		if len(call.Args) == 1 {
			return requestBody(c.info, call.Args[0]), false
		}
	case isPackageFuncCall(file, c.info, call, "io", "ReadAll"),
		isPackageFuncCall(file, c.info, call, "io/ioutil", "ReadAll"):
		if len(call.Args) == 1 {
			return requestBody(c.info, call.Args[0]), true
		}
	case isPackageFuncCall(file, c.info, call, "io", "Copy", "CopyBuffer"):
		if len(call.Args) >= 2 {
			return requestBody(c.info, call.Args[1]), true
		}
	}
	return "", false
}

func (c *bodyReadCheck) report(call *ast.CallExpr) {
	line := c.file.LineFor(call)
	if c.file.IsSuppressed(line, c.rule.Name()) {
		return
	}
	message := "Request body read without http.MaxBytesReader, while other handlers of the project limit theirs and no middleware limits all — a client can send a body of any size and the handler holds it in memory"
	if c.rawOnly {
		message = "Whole request body copied without http.MaxBytesReader, and nothing in the project limits bodies — a client can send a body of any size and the handler holds it in memory"
	}
	v := c.rule.CreateViolation(c.file.RelPath, line, message)
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
