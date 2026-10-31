package frontendrules

import (
	"encoding/json"
	"go/ast"
	"go/constant"
	"go/types"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() { rules.Register(NewTSPathNotRoutedRule()) }

// TSPathNotRoutedRule detects TypeScript API paths that have no gorilla/mux route.
//
//	// Go: router.HandleFunc("/api/admin/stats", handler)
//	// TypeScript: fetch('/api/admin/analytics') // reported
//	// TypeScript: fetch('/api/admin/stats') // Not flagged
type TSPathNotRoutedRule struct {
	*rules.BaseRule
	routes []muxEndpoint
}

type muxEndpoint struct {
	Path    string
	Line    int
	Prefix  bool
	Unknown bool
}

// NewTSPathNotRoutedRule creates the rule.
func NewTSPathNotRoutedRule() *TSPathNotRoutedRule {
	return &TSPathNotRoutedRule{BaseRule: rules.NewBaseRule(
		"ts-path-not-routed", "patterns",
		"Detects TypeScript API paths with no matching gorilla/mux route",
		core.SeverityMedium,
	)}
}

// UseProjectFiles collects gorilla/mux routes and TypeScript files share a project root.
func (r *TSPathNotRoutedRule) UseProjectFiles(files []*core.FileContext) {
	r.routes = nil
	for _, file := range files {
		if file.GoAST == nil {
			continue
		}
		r.routes = append(r.routes, muxEndpointsInFile(file)...)
	}
}

// ResetState drops the route map of the previous root.
func (r *TSPathNotRoutedRule) ResetState() { r.routes = nil }

// CacheProjectFiles returns the route index for the Go inputs in the project cache.
func (r *TSPathNotRoutedRule) CacheProjectFiles() ([]byte, error) {
	return json.Marshal(r.routes)
}

// RestoreProjectFiles restores the route index from the project cache.
func (r *TSPathNotRoutedRule) RestoreProjectFiles(data []byte) error {
	return json.Unmarshal(data, &r.routes)
}

// NeedsTypedGoProject asks the runner to attach Go type information when this
// root includes files analyzed by the rule.
func (r *TSPathNotRoutedRule) NeedsTypedGoProject(files []*core.FileContext) bool {
	hasMuxImport := false
	hasAnalyzedFrontend := false
	for _, file := range files {
		if file.IsGoFile() {
			hasMuxImport = hasMuxImport || slices.Contains(file.GoImports, "github.com/gorilla/mux")
		}
		if (file.IsTypeScriptFile() || file.IsJavaScriptFile()) && !strings.HasSuffix(file.RelPath, ".d.ts") && !isUnitTestPath(file.RelPath) {
			hasAnalyzedFrontend = true
		}
	}
	return hasAnalyzedFrontend && hasMuxImport
}

// TypedGoProjectImports lists imports used to decide whether this rule needs Go types.
func (r *TSPathNotRoutedRule) TypedGoProjectImports() []string {
	return []string{"github.com/gorilla/mux"}
}

// AnalyzeFile reports API paths that do not match a collected route.
func (r *TSPathNotRoutedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || len(r.routes) == 0 || strings.HasSuffix(ctx.RelPath, ".d.ts") || isUnitTestPath(ctx.RelPath) {
		return nil
	}
	text := helpers.FileJSText(ctx)
	apiBasePath := declaredAPIBasePath(text)
	var out []*core.Violation
	for lineNo, line := range text {
		for _, candidate := range apiPathsWithBase(line, apiBasePath) {

			if routeCovers(r.routes, candidate.path, candidate.unknownPrefix) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, lineNo+1, "No backend route for "+candidate.display)
			v.WithCode(strings.TrimSpace(ctx.Lines[lineNo]))
			v.WithSuggestion("Add the backend route or update the client path")
			out = append(out, v)
		}
	}
	return out
}

type tsAPIPath struct {
	path          string
	display       string
	unknownPrefix bool
}

var (
	tsPathToken   = regexp.MustCompile("`[^`]*`|'[^'\\n]*'|\"[^\"\\n]*\"")
	tsPathMatcher = regexp.MustCompile(`(?:startsWith|includes|endsWith)\s*\(\s*$|page\.goto\s*\([^)]*$`)
	tsPropertyKey = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*:\s*$`)
	tsAPIBasePath = regexp.MustCompile(`(?m)\b(?:const|let|var)\s+API_BASE_PATH\s*=\s*(?:'(/[^']*)'|"(/[^\"]*)")`)
)
var (
	tsInterpolation = regexp.MustCompile(`\$\{[^}]+\}`)
	routeVariable   = regexp.MustCompile(`\{[^}]+\}`)
)

func apiPaths(line string) []tsAPIPath {
	return apiPathsWithBase(line, "")
}

func apiPathsWithBase(line, apiBasePath string) []tsAPIPath {
	var paths []tsAPIPath
	for _, match := range tsPathToken.FindAllStringIndex(line, -1) {
		token := line[match[0]:match[1]]
		if tsPathMatcher.MatchString(line[:match[0]]) {
			continue
		}
		valueToken := token
		if token[0] == '\'' {
			valueToken = "\"" + token[1:len(token)-1] + "\""
		}
		value, err := strconv.Unquote(valueToken)
		if token[0] == '`' {
			value, err = token[1:len(token)-1], nil
		}
		if err != nil || strings.Contains(value, "://") {
			continue
		}
		if strings.Contains(value, "?") {
			value = strings.SplitN(value, "?", 2)[0]
		}
		if query := strings.Index(value, "${query}"); query >= 0 {
			value = value[:query]
		}
		if strings.HasSuffix(value, "/") {
			continue
		}
		if isAPINamespaceProperty(line, match[0], value) {
			continue
		}
		unknown := false
		if strings.HasPrefix(value, "${") {
			end := strings.Index(value, "}/")
			if end < 0 {
				continue
			}
			base := value[2:end]
			if !knownAPIBase(base) {
				continue
			}
			if strings.HasPrefix(base, "E2E_URLS.") && strings.HasSuffix(base, "_APP") {
				continue
			}
			if base == "API_BASE_PATH" && apiBasePath != "" {
				value = path.Clean(apiBasePath + value[end+1:])
				unknown = false
			} else {
				value = value[end+1:]
				unknown = !strings.HasPrefix(value, "/api/")
			}
		}
		if !strings.HasPrefix(value, "/api/") && !unknown {
			continue
		}
		if !strings.HasPrefix(value, "/") {
			continue
		}
		value = tsInterpolation.ReplaceAllString(value, "*")
		paths = append(paths, tsAPIPath{path: path.Clean(value), display: value, unknownPrefix: unknown})
	}
	return paths
}

func declaredAPIBasePath(lines []string) string {
	for _, line := range lines {
		match := tsAPIBasePath.FindStringSubmatch(line)
		if len(match) == 3 && match[1] != "" {
			return match[1]
		}
		if len(match) == 3 && match[2] != "" {
			return match[2]
		}
	}
	return ""
}

func isAPINamespaceProperty(line string, tokenStart int, value string) bool {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	if len(parts) != 2 || parts[0] != "api" {
		return false
	}
	property := tsPropertyKey.FindStringSubmatch(line[:tokenStart])
	return len(property) == 2 && property[1] == parts[1]
}

func knownAPIBase(base string) bool {
	base = strings.TrimSpace(base)
	return base == "BASE_API_URL" || base == "API_BASE" || base == "API_BASE_PATH" || base == "baseURL" || strings.HasPrefix(base, "E2E_URLS.")
}

func isUnitTestPath(relPath string) bool {
	base := path.Base(relPath)
	return strings.Contains("/"+relPath, "/__tests__/") || strings.HasSuffix(base, ".test.ts") || strings.HasSuffix(base, ".test.tsx")
}

func routeCovers(routes []muxEndpoint, candidate string, unknownPrefix bool) bool {
	for _, route := range routes {
		if route.Prefix {
			if route.Path != "/" && !strings.Contains(route.Path, "{") && strings.HasPrefix(candidate, route.Path) {
				return true
			}
			continue
		}
		if routePathMatches(route.Path, candidate) {
			return true
		}
		if route.Unknown && routeSuffixMatches(route.Path, candidate) {
			return true
		}
		if unknownPrefix && routeSuffixMatches(candidate, route.Path) {
			return true
		}
		if unknownPrefix && routeSuffixMatches(route.Path, candidate) {
			return true
		}
	}
	return false
}

func routeSuffixMatches(route, candidate string) bool {
	routeParts := strings.Split(strings.Trim(route, "/"), "/")
	candidateParts := strings.Split(strings.Trim(candidate, "/"), "/")
	if len(routeParts) <= len(candidateParts) {
		candidateSuffix := "/" + strings.Join(candidateParts[len(candidateParts)-len(routeParts):], "/")
		return routePathMatches(route, candidateSuffix)
	}
	routeSuffix := "/" + strings.Join(routeParts[len(routeParts)-len(candidateParts):], "/")
	return routePathMatches(routeSuffix, candidate)
}

func routePathMatches(route, candidate string) bool {
	routeParts := strings.Split(strings.Trim(route, "/"), "/")
	candidateParts := strings.Split(strings.Trim(candidate, "/"), "/")
	if len(routeParts) != len(candidateParts) {
		return false
	}
	for i := range routeParts {
		if routeSegmentMatches(routeParts[i], candidateParts[i]) {
			continue
		}
		return false
	}
	return true
}

func routeSegmentMatches(route, candidate string) bool {
	if route == "*" {
		return true
	}
	if routeVariable.MatchString(route) {
		matched, err := path.Match(routeVariable.ReplaceAllString(route, "*"), candidate)
		return err == nil && matched
	}
	return route == candidate
}

func muxEndpointsInFile(file *core.FileContext) []muxEndpoint {
	if file.GoAST == nil || file.GoTypesInfo == nil {
		return nil
	}
	var endpoints []muxEndpoint
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Body != nil {
			endpoints = append(endpoints, muxEndpointsInFunction(fn, file.GoTypesInfo)...)
		}
	}
	return endpoints
}

type routerBase struct {
	path    string
	unknown bool
}

func muxEndpointsInFunction(fn *ast.FuncDecl, info *types.Info) []muxEndpoint {
	bases := map[string]routerBase{}
	var endpoints []muxEndpoint
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		subrouter, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !isMethod(subrouter, "Subrouter") {
			return true
		}
		selector, ok := subrouter.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		prefixCall, ok := selector.X.(*ast.CallExpr)
		if !ok || !isMethod(prefixCall, "PathPrefix") || len(prefixCall.Args) == 0 {
			return true
		}
		prefix, ok := constString(info, prefixCall.Args)
		if !ok || prefix == "/" {
			return true
		}
		base := receiverBase(prefixCall, bases)
		base.path = joinRoute(base.path, prefix)
		bases[id.Name] = base
		return true
	})
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		method := selector.Sel.Name
		if method != "HandleFunc" && method != "Handle" && method != "Path" && method != "PathPrefix" {
			return true
		}
		if !validRouteReceiver(selector.X, method, info) {
			return true
		}
		if method == "PathPrefix" && isSubrouterPrefix(call, fn.Body, info) {
			return true
		}
		route, ok := constString(info, call.Args)
		if !ok || (method == "PathPrefix" && route == "/") {
			return true
		}
		base := receiverBaseFromType(selector.X, bases)
		full := joinRoute(base.path, route)
		unknown := base.unknown || !strings.HasPrefix(full, "/api/")
		endpoints = append(endpoints, muxEndpoint{Path: full, Prefix: method == "PathPrefix", Unknown: unknown})
		return true
	})
	return endpoints
}

func isSubrouterPrefix(call *ast.CallExpr, body *ast.BlockStmt, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		parent, ok := n.(*ast.CallExpr)
		if !ok || !isMethod(parent, "Subrouter") {
			return true
		}
		if selector, ok := parent.Fun.(*ast.SelectorExpr); ok && selector.X == call {
			found = true
		}
		return !found
	})
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return found && ok && validRouteReceiver(selector.X, "PathPrefix", info)
}

func isMethod(call *ast.CallExpr, name string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == name
}

func validRouteReceiver(expr ast.Expr, method string, info *types.Info) bool {
	t := info.TypeOf(expr)
	if t == nil {
		return false
	}
	if pointer, ok := t.(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	pkg, name := named.Obj().Pkg().Path(), named.Obj().Name()
	if pkg == "github.com/gorilla/mux" {
		return name == "Router" || name == "Route"
	}
	return pkg == "net/http" && name == "ServeMux" && (method == "HandleFunc" || method == "Handle")
}

func constString(info *types.Info, args []ast.Expr) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	tv, ok := info.Types[args[0]]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

func receiverBase(expr ast.Expr, bases map[string]routerBase) routerBase {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return receiverBaseFromType(expr, bases)
	}
	return receiverBaseFromType(selector.X, bases)
}

func receiverBaseFromType(expr ast.Expr, bases map[string]routerBase) routerBase {
	if id, ok := expr.(*ast.Ident); ok {
		if base, exists := bases[id.Name]; exists {
			return base
		}
	}
	return routerBase{unknown: true}
}

func joinRoute(prefix, route string) string {
	if prefix == "" {
		return path.Clean("/" + strings.TrimPrefix(route, "/"))
	}
	return path.Clean(strings.TrimSuffix(prefix, "/") + "/" + strings.TrimPrefix(route, "/"))
}
