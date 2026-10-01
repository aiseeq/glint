package patterns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewMuxRouteShadowedRule())
}

// MuxRouteShadowedRule detects a gorilla/mux route registered after a route
// of the same router that already matches every request it would serve:
//
//	router.HandleFunc("/api/orders/{id}", getOrder).Methods("GET")
//	router.HandleFunc("/api/orders/summary", getSummary).Methods("GET")
//
// mux tries routes in the order they were added and serves the first match:
// "summary" is a fine {id}, so the summary handler never runs and the order
// handler answers with "not found" or a 500 on a malformed id. A catch-all
// PathPrefix("/") does the same to everything registered after it. Register
// the specific route first. Only routes of one function on the same router
// expression are compared; a route with a host, header, query or custom
// matcher may let requests through, and is not taken as shadowing.
type MuxRouteShadowedRule struct {
	*rules.BaseRule
}

// NewMuxRouteShadowedRule creates the rule
func NewMuxRouteShadowedRule() *MuxRouteShadowedRule {
	return &MuxRouteShadowedRule{BaseRule: rules.NewBaseRule(
		"mux-route-shadowed",
		"patterns",
		"Detects a gorilla/mux route registered after a route of the same router that already matches it — mux serves the first match, so the later handler never runs",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the project run checks every file, with the
// router's type where the package has it.
func (r *MuxRouteShadowedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *MuxRouteShadowedRule) RequiresSSA() bool { return false }

const gorillaMuxPath = "github.com/gorilla/mux"

// muxRoute is one route registration: router.Handle(...).Methods(...).
type muxRoute struct {
	router      string
	path        string // a full path template
	prefix      string
	isPrefix    bool     // a PathPrefix route: prefix holds its template
	methods     []string // upper case; empty matches every method
	conditional bool     // a host, header, query or custom matcher narrows it
	subrouter   bool
	line        int
}

// AnalyzeGoProject reports the shadowed routes of every function.
func (r *MuxRouteShadowedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if file.IsTestFile() || (info == nil && !importsGorillaMux(file.GoAST)) {
			return nil
		}
		var violations []*core.Violation
		for _, body := range functionBodies(file.GoAST) {
			var earlier []muxRoute
			for _, route := range muxRoutes(file, info, body) {
				if shadow, ok := shadowingRoute(earlier, route); ok && !file.IsSuppressed(route.line, r.Name()) {
					violations = append(violations, r.report(file, route, shadow))
				}
				earlier = append(earlier, route)
			}
		}
		return violations
	})
}

func (r *MuxRouteShadowedRule) report(file *core.FileContext, route, shadow muxRoute) *core.Violation {
	what := route.path
	if route.isPrefix {
		what = route.prefix + "*"
	}
	by := shadow.path
	if shadow.isPrefix {
		by = "the prefix " + shadow.prefix
	}
	v := r.CreateViolation(file.RelPath, route.line, fmt.Sprintf(
		"Route %s is registered after %s (line %d), which already matches it — mux serves the first matching route, so this handler never runs",
		what, by, shadow.line))
	v.WithCode(strings.TrimSpace(file.GetLine(route.line)))
	v.WithSuggestion("Register the specific route before the template or prefix that also matches it")
	return v
}

// muxRoutes returns the route registrations of a body in source order,
// leaving out the ones inside nested function literals.
func muxRoutes(file *core.FileContext, info *types.Info, body *ast.BlockStmt) []muxRoute {
	var routes []muxRoute
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		var expr ast.Expr
		switch stmt := n.(type) {
		case *ast.ExprStmt:
			expr = stmt.X
		case *ast.AssignStmt:
			if len(stmt.Rhs) == 1 {
				expr = stmt.Rhs[0]
			}
		default:
			return true
		}
		if route, ok := muxRouteOf(info, expr); ok {
			route.line = file.LineFor(expr)
			routes = append(routes, route)
		}
		return true
	})
	return routes
}

// muxRouteOf reads a call chain rooted at a *mux.Router.
func muxRouteOf(info *types.Info, expr ast.Expr) (muxRoute, bool) {
	var route muxRoute
	known := false
	for {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		if !ok {
			break
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return route, false
		}
		switch sel.Sel.Name {
		case "Handle", "HandleFunc", "Path":
			if len(call.Args) == 0 {
				return route, false
			}
			text, ok := stringConstant(info, call.Args[0])
			if !ok {
				return route, false
			}
			route.path, known = text, true
		case "PathPrefix":
			if len(call.Args) == 0 {
				return route, false
			}
			text, ok := stringConstant(info, call.Args[0])
			if !ok {
				return route, false
			}
			route.prefix, route.isPrefix, known = text, true, true
		case "Methods":
			for _, arg := range call.Args {
				text, ok := stringConstant(info, arg)
				if !ok {
					return route, false
				}
				route.methods = append(route.methods, strings.ToUpper(text))
			}
		case "Subrouter":
			route.subrouter = true
		case "Host", "Headers", "HeadersRegexp", "Queries", "Schemes", "MatcherFunc":
			route.conditional = true
		}
		expr = sel.X
	}
	// Without type information the file's import of gorilla/mux stands for
	// the router's type.
	if !known || (info != nil && !isPointerToNamedType(info.TypeOf(expr), gorillaMuxPath, "Router")) {
		return route, false
	}
	route.router = types.ExprString(expr)
	return route, true
}

// importsGorillaMux reports a file importing gorilla/mux.
func importsGorillaMux(file *ast.File) bool {
	return len(helpers.PackageAliases(file, strconv.Quote(gorillaMuxPath), "mux")) > 0
}

// stringConstant returns the value of a constant string expression; without
// type information, of a string literal.
func stringConstant(info *types.Info, expr ast.Expr) (string, bool) {
	if info == nil {
		lit, ok := ast.Unparen(expr).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}
		text, err := strconv.Unquote(lit.Value)
		return text, err == nil
	}
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

// shadowingRoute returns the first earlier route that serves every request
// the route would.
func shadowingRoute(earlier []muxRoute, route muxRoute) (muxRoute, bool) {
	for _, prior := range earlier {
		if prior.router != route.router || prior.conditional || prior.subrouter {
			continue
		}
		if len(prior.methods) > 0 && (len(route.methods) == 0 || !subsetOf(route.methods, prior.methods)) {
			continue
		}
		if prior.isPrefix {
			if strings.Contains(prior.prefix, "{") {
				continue
			}
			target := route.path
			if route.isPrefix {
				target = route.prefix
			}
			if strings.HasPrefix(target, prior.prefix) {
				return prior, true
			}
			continue
		}
		if !route.isPrefix && templateMatches(prior.path, route.path) {
			return prior, true
		}
	}
	return muxRoute{}, false
}

func subsetOf(items, set []string) bool {
	for _, item := range items {
		if !slices.Contains(set, item) {
			return false
		}
	}
	return true
}

var muxVariable = regexp.MustCompile(`^\{([A-Za-z_][A-Za-z0-9_]*)(?::(.+))?\}$`)

// templateMatches reports whether the template serves the path: the same
// segments, each one equal or a variable whose pattern takes the path's
// literal segment. A path segment that is itself a variable is matched only
// by the same text — the routes are then duplicates.
func templateMatches(template, path string) bool {
	tSegs, pSegs := strings.Split(template, "/"), strings.Split(path, "/")
	if len(tSegs) != len(pSegs) {
		return false
	}
	for i, seg := range tSegs {
		if seg == pSegs[i] {
			continue
		}
		m := muxVariable.FindStringSubmatch(seg)
		if m == nil || strings.Contains(pSegs[i], "{") {
			return false
		}
		pattern := `[^/]+`
		if m[2] != "" {
			pattern = m[2]
		}
		re, err := regexp.Compile(`^(?:` + pattern + `)$`)
		if err != nil || !re.MatchString(pSegs[i]) {
			return false
		}
	}
	return true
}
