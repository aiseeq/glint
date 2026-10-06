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
	rules.Register(NewQueryValueFallsBackToDefaultRule())
}

// QueryValueFallsBackToDefaultRule detects a value from the request's query
// mapped by a switch whose default returns a preset, from a function that
// cannot return an error:
//
//	func ParsePeriod(period string) (time.Time, string) {
//		switch period {
//		case "7d": ...
//		case "30d": ...
//		default:
//			return time.Time{}, "all"
//		}
//	}
//	since, period := ParsePeriod(r.URL.Query().Get("period"))
//
// An unknown value — a typo, a value the client supports and the server does
// not — is answered as if the client asked for the preset: the screen shows
// "all time" under the label of the period it asked for. Refuse a value
// outside the cases with an error (400); an empty value may still mean the
// preset, as its own case. The value is followed from url.Values.Get through
// the parameters of the functions it is handed to.
type QueryValueFallsBackToDefaultRule struct {
	*rules.BaseRule
}

// NewQueryValueFallsBackToDefaultRule creates the rule
func NewQueryValueFallsBackToDefaultRule() *QueryValueFallsBackToDefaultRule {
	return &QueryValueFallsBackToDefaultRule{BaseRule: rules.NewBaseRule(
		"query-value-falls-back-to-default",
		"patterns",
		"Detects a query parameter mapped by a switch whose default returns a preset with no error — an unknown value is answered as the preset instead of refused",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the value is followed across the project.
func (r *QueryValueFallsBackToDefaultRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *QueryValueFallsBackToDefaultRule) RequiresSSA() bool { return false }

// queryFedParam is a parameter of a function that receives a query value.
type queryFedParam struct {
	fn    *types.Func
	index int
}

// AnalyzeGoProject reports the switch defaults of the functions that map a
// query value.
func (r *QueryValueFallsBackToDefaultRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	fed := queryFedParams(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || returnsErrorResult(info, fn) {
				continue
			}
			obj, ok := info.Defs[fn.Name].(*types.Func)
			if !ok {
				continue
			}
			for i, param := range paramObjects(typedFuncDecl{decl: fn, info: info}) {
				if !fed[queryFedParam{obj, i}] {
					continue
				}
				ret := presetDefault(fn.Body, param, info)
				if ret == nil {
					continue
				}
				line := file.LineFor(ret)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, "A query value outside the cases falls back to a preset — the client gets the preset under the label of what it asked for")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Return an error for a value outside the cases and answer 400; keep the preset for the empty value only")
				violations = append(violations, v)
			}
		}
		return violations
	})
}

// queryFedParams returns the parameters that receive a value of url.Values
// Get, directly or through a parameter of another function.
func queryFedParams(ctx *core.GoProjectContext) map[queryFedParam]bool {
	fed := make(map[queryFedParam]bool)
	type passing struct {
		from queryFedParam
		to   queryFedParam
	}
	var passings []passing
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				caller, _ := info.Defs[fn.Name].(*types.Func)
				params := make(map[types.Object]int)
				for i, p := range paramObjects(typedFuncDecl{decl: fn, info: info}) {
					if p != nil {
						params[p] = i
					}
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					callee, ok := typeutil.Callee(info, call).(*types.Func)
					if !ok {
						return true
					}
					callee = callee.Origin()
					for i, arg := range call.Args {
						if isQueryGet(arg, info) {
							fed[queryFedParam{callee, i}] = true
						}
						if id, ok := ast.Unparen(arg).(*ast.Ident); ok && caller != nil {
							if from, ok := params[info.Uses[id]]; ok {
								passings = append(passings, passing{queryFedParam{caller, from}, queryFedParam{callee, i}})
							}
						}
					}
					return true
				})
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, p := range passings {
			if fed[p.from] && !fed[p.to] {
				fed[p.to] = true
				changed = true
			}
		}
	}
	return fed
}

// isQueryGet reports X.Get(...) on a url.Values: r.URL.Query().Get("period").
func isQueryGet(expr ast.Expr, info *types.Info) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Get" {
		return false
	}
	return isNamedType(info.TypeOf(sel.X), "net/url", "Values")
}

// presetDefault returns the return statement of the default clause of a
// switch on the parameter whose cases are string literals, when the default
// returns rather than fails.
func presetDefault(body *ast.BlockStmt, param *types.Var, info *types.Info) *ast.ReturnStmt {
	var found *ast.ReturnStmt
	ast.Inspect(body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || found != nil {
			return found == nil
		}
		tag, ok := ast.Unparen(sw.Tag).(*ast.Ident)
		if !ok || param == nil || info.Uses[tag] != param {
			return true
		}
		literalCases := 0
		var def *ast.CaseClause
		for _, stmt := range sw.Body.List {
			clause, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			if clause.List == nil {
				def = clause
				continue
			}
			for _, expr := range clause.List {
				if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					literalCases++
				}
			}
		}
		if def == nil || literalCases < 2 || len(def.Body) == 0 {
			return true
		}
		if ret, ok := def.Body[len(def.Body)-1].(*ast.ReturnStmt); ok && len(ret.Results) > 0 {
			found = ret
		}
		return true
	})
	return found
}
