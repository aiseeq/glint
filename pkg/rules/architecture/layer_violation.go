package architecture

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewLayerViolationRule())
}

// LayerViolationRule detects architecture violations (Handler→Service→Repository):
// SQL in the handler and service layers, HTTP response handling in the
// repository layer.
//
// A call is judged by the type of what it calls: a Query/Exec method of a
// database handle (database/sql, sqlx, pgx), an HTTP operation of net/http —
// however the variable or field holding the handle is named. A method that
// merely shares a name (a getter HTTPTimeout, a cache's Query) is not one. A
// constant connectivity probe (SELECT 1, SELECT NOW()) reads no data and is
// not reported. A file without type information keeps the SQL-text check,
// which needs no types, and is silent about calls.
type LayerViolationRule struct {
	*rules.BaseRule
}

// NewLayerViolationRule creates the rule
func NewLayerViolationRule() *LayerViolationRule {
	return &LayerViolationRule{
		BaseRule: rules.NewBaseRule(
			"layer-violation",
			"architecture",
			"Detects violations of layered architecture (Handler→Service→Repository)",
			core.SeverityCritical,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback for
// files no type-checked package covers.
func (r *LayerViolationRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *LayerViolationRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every Go file, typed where the project allows.
func (r *LayerViolationRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks one file. info is nil for a file without type information.
func (r *LayerViolationRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var layerName string
	switch determineLayerFromPath(ctx.RelPath) {
	case HandlerLayer:
		layerName = "Handler"
	case ServiceLayer:
		layerName = "Service"
	case RepositoryLayer:
		return r.checkRepositoryViolations(ctx, info)
	default:
		return nil
	}

	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if v := r.checkDirectSQLCall(ctx, info, node, layerName); v != nil {
				violations = append(violations, v)
			}
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				if v := r.checkSQLString(ctx, node, layerName); v != nil {
					violations = append(violations, v)
				}
			}
		}
		return true
	})
	return violations
}

// checkRepositoryViolations checks for violations in repository layer
func (r *LayerViolationRule) checkRepositoryViolations(ctx *core.FileContext, info *types.Info) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if v := r.checkHTTPCall(ctx, info, call); v != nil {
				violations = append(violations, v)
			}
		}
		return true
	})

	return violations
}

// sqlPackages are the packages whose handles run SQL. A subpackage counts
// (pgx/v5/pgxpool).
var sqlPackages = []string{"database/sql", "github.com/jmoiron/sqlx", "github.com/jackc/pgx"}

// httpOperations are the net/http functions and methods that handle a
// request or a response.
var httpOperations = []string{"WriteHeader", "ServeHTTP", "Redirect", "ParseForm", "Cookie", "SetCookie"}

// probeQuery matches a connectivity probe: a SELECT of a literal or of the
// server clock or version. It reads no table and calls no function of the
// schema, so there is nothing a repository would own.
var probeQuery = regexp.MustCompile(`(?i)^\s*SELECT\s+(?:\d+|TRUE|NOW\(\)|CURRENT_TIMESTAMP|CURRENT_DATE|VERSION\(\))\s*;?\s*$`)

// checkDirectSQLCall reports a SQL method called on a database handle, unless
// the query is a constant connectivity probe.
func (r *LayerViolationRule) checkDirectSQLCall(ctx *core.FileContext, info *types.Info, call *ast.CallExpr, layer string) *core.Violation {
	sel, fn, ok := calledMethod(info, call)
	if !ok || !slices.Contains(helpers.SQLMethods, fn.Name()) || !inPackages(fn, sqlPackages) {
		return nil
	}
	if query, known := constantQuery(info, fn, call); known && probeQuery.MatchString(query) {
		return nil
	}

	pos := ctx.PositionFor(call)
	v := r.CreateViolation(ctx.RelPath, pos.Line,
		layer+" contains direct SQL call: "+types.ExprString(sel.X)+"."+sel.Sel.Name)
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Move SQL operations to Repository layer")
	v.WithContext("layer", layer)
	v.WithContext("pattern", "direct_sql_call")

	return v
}

// checkHTTPCall reports an HTTP operation of net/http called from the
// repository layer.
func (r *LayerViolationRule) checkHTTPCall(ctx *core.FileContext, info *types.Info, call *ast.CallExpr) *core.Violation {
	sel, fn, ok := calledMethod(info, call)
	if !ok || !slices.Contains(httpOperations, fn.Name()) || !inPackages(fn, []string{"net/http"}) {
		return nil
	}

	pos := ctx.PositionFor(call)
	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"Repository contains HTTP operation: "+sel.Sel.Name)
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Repository should only handle data access, move HTTP logic to Service/Handler")
	v.WithContext("layer", "Repository")
	v.WithContext("pattern", "http_in_repo")

	return v
}

// calledMethod resolves a call of the form x.f(...) to the function or
// method it invokes. Without type information nothing is resolved.
func calledMethod(info *types.Info, call *ast.CallExpr) (*ast.SelectorExpr, *types.Func, bool) {
	if info == nil {
		return nil, nil, false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return nil, nil, false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return nil, nil, false
	}
	return sel, fn, true
}

// sqlQueryParams are the names database/sql, sqlx and pgx give the query
// parameter.
var sqlQueryParams = []string{"query", "sql"}

// constantQuery returns the text of the query a SQL method is called with,
// when that argument is a compile-time constant string.
func constantQuery(info *types.Info, fn *types.Func, call *ast.CallExpr) (string, bool) {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return "", false
	}
	params := sig.Params()
	for i := 0; i < params.Len() && i < len(call.Args); i++ {
		if sig.Variadic() && i == params.Len()-1 {
			break
		}
		if !slices.Contains(sqlQueryParams, params.At(i).Name()) {
			continue
		}
		value := info.Types[call.Args[i]].Value
		if value == nil || value.Kind() != constant.String {
			return "", false
		}
		return constant.StringVal(value), true
	}
	return "", false
}

// inPackages reports whether fn is declared in one of the packages or below
// one of them.
func inPackages(fn *types.Func, paths []string) bool {
	pkgPath := fn.Pkg().Path()
	for _, path := range paths {
		if pkgPath == path || strings.HasPrefix(pkgPath, path+"/") {
			return true
		}
	}
	return false
}

// checkSQLString checks for SQL strings in non-repository layers
func (r *LayerViolationRule) checkSQLString(ctx *core.FileContext, lit *ast.BasicLit, layer string) *core.Violation {
	value := strings.Trim(lit.Value, `"'`+"`")

	if !r.isSQLString(value) {
		return nil
	}

	pos := ctx.PositionFor(lit)
	truncated := value
	if len(truncated) > 50 {
		cut := 50
		for cut > 0 && !utf8.RuneStart(truncated[cut]) {
			cut-- // a query may hold non-ASCII text; keep the message valid UTF-8
		}
		truncated = truncated[:cut] + "..."
	}

	v := r.CreateViolation(ctx.RelPath, pos.Line,
		layer+" contains SQL query: "+truncated)
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Move SQL queries to Repository layer")
	v.WithContext("layer", layer)
	v.WithContext("pattern", "sql_string")

	return v
}

// SQL patterns for detection
var sqlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^SELECT\s+.+\s+FROM\s+\w+`),
	regexp.MustCompile(`(?i)^INSERT\s+INTO\s+\w+`),
	regexp.MustCompile(`(?i)^UPDATE\s+\w+\s+SET\s+`),
	regexp.MustCompile(`(?i)^DELETE\s+FROM\s+\w+`),
	regexp.MustCompile(`(?i)^CREATE\s+(TABLE|INDEX|DATABASE)`),
	regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+`),
	regexp.MustCompile(`(?i)^DROP\s+(TABLE|INDEX|DATABASE)`),
}

// isSQLString checks if a string looks like a SQL query
func (r *LayerViolationRule) isSQLString(value string) bool {
	if len(value) < 10 {
		return false
	}

	trimmed := strings.TrimSpace(value)

	// Exclude error messages and descriptions
	upper := strings.ToUpper(trimmed)
	excludePatterns := []string{
		"ERROR", "FAILED", "INVALID", "NOT FOUND",
		"UNAUTHORIZED", "FORBIDDEN", "TIMEOUT",
		"METHOD NOT", "NOT IMPLEMENTED",
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(upper, pattern) {
			return false
		}
	}

	// Check SQL patterns
	for _, pattern := range sqlPatterns {
		if pattern.MatchString(trimmed) {
			return true
		}
	}

	return false
}
