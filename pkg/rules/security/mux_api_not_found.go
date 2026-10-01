package security

import (
	"go/ast"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewMuxAPIDefaultNotFoundRule())
}

// MuxAPIDefaultNotFoundRule detects a gorilla/mux router serving /api/ routes
// in a project that never sets NotFoundHandler:
//
//	router := mux.NewRouter()
//	router.HandleFunc("/api/users", listUsers).Methods("GET")
//
// An unknown /api/ path, or a known one with a typo, gets mux's default
// text/plain "404 page not found". A client that parses every answer as the
// API's JSON envelope reports a parse failure, not "no such method", and the
// error tracking groups it with real breakages. Set router.NotFoundHandler
// (and MethodNotAllowedHandler), or route PathPrefix("/api/") last to a
// handler, to answer in the envelope.
type MuxAPIDefaultNotFoundRule struct {
	*rules.BaseRule
	handled bool // some production file of the root sets NotFoundHandler
}

// NewMuxAPIDefaultNotFoundRule creates the rule
func NewMuxAPIDefaultNotFoundRule() *MuxAPIDefaultNotFoundRule {
	return &MuxAPIDefaultNotFoundRule{BaseRule: rules.NewBaseRule(
		"mux-api-default-not-found",
		"patterns",
		"Detects a gorilla/mux router with /api/ routes in a project that never sets NotFoundHandler — unknown API paths get text/plain, not the JSON envelope",
		core.SeverityLow,
	)}
}

const gorillaMuxPath = "github.com/gorilla/mux"

// UseProjectFiles finds whether the root sets a NotFoundHandler anywhere.
func (r *MuxAPIDefaultNotFoundRule) UseProjectFiles(files []*core.FileContext) {
	r.handled = false
	for _, ctx := range files {
		if !ctx.HasGoAST() || ctx.IsTestFile() {
			continue
		}
		ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "NotFoundHandler" {
						r.handled = true
					}
				}
			case *ast.CallExpr:
				r.handled = r.handled || apiCatchAll(node)
			}
			return !r.handled
		})
		if r.handled {
			return
		}
	}
}

// ResetState forgets the previous root.
func (r *MuxAPIDefaultNotFoundRule) ResetState() { r.handled = false }

// AnalyzeFile reports the routers of a file that registers /api/ routes.
func (r *MuxAPIDefaultNotFoundRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if r.handled || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	aliases := helpers.PackageAliases(ctx.GoAST, strconv.Quote(gorillaMuxPath), "mux")
	if len(aliases) == 0 || !registersAPIRoute(ctx.GoAST) {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && callName(call) == "NewRouter" {
			if pkg, ok := callPackage(call); ok && aliases[pkg] {
				lr.report(call, "Router serves /api/ routes with mux's default NotFoundHandler — an unknown API path is answered in text/plain, not the JSON envelope",
					"Set router.NotFoundHandler (and MethodNotAllowedHandler) to answer /api/ paths in the API's error envelope", "mux_api_default_not_found")
			}
		}
		return true
	})
	return lr.violations
}

// apiCatchAll reports router.PathPrefix("/api/").Handler(...): a handler of
// its own for every /api/ path no other route takes.
func apiCatchAll(call *ast.CallExpr) bool {
	if name := callName(call); name != "Handler" && name != "HandlerFunc" {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	prefix, ok := sel.X.(*ast.CallExpr)
	if !ok || callName(prefix) != "PathPrefix" || len(prefix.Args) != 1 {
		return false
	}
	path := stringLiteral(prefix.Args[0])
	return path == "/api" || path == "/api/"
}

// registersAPIRoute reports a route registration with a path under /api.
func registersAPIRoute(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return !found
		}
		switch callName(call) {
		case "HandleFunc", "Handle", "Path", "PathPrefix":
			if strings.HasPrefix(stringLiteral(call.Args[0]), "/api") {
				found = true
			}
		}
		return !found
	})
	return found
}
