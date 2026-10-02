package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// checkSwitchDefaultMember reports a switch over a parameter whose cases name
// constants and whose default answers with what one of the cases returns, in
// a function without an error result:
//
//	switch frequency {
//	case FrequencyMonthly:
//	    return 12
//	...
//	default:
//	    return 1 // the annual divisor: an unknown frequency passes for annual
//	}
//
// The unknown value is indistinguishable from a valid one. A default with a
// value of its own ("unknown") is a visible fallback and is left alone.
func (r *ErrorMaskingRule) checkSwitchDefaultMember(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	if !hasNonErrorResults(fn.Type.Results) {
		return nil
	}
	// A plain string or int parameter: a named enum type maps its own
	// members, and its default (Unhealthy, 500) is a decision about the type.
	params := make(map[string]bool)
	for _, field := range fn.Type.Params.List {
		typ, ok := field.Type.(*ast.Ident)
		if !ok || typ.Name != "string" && typ.Name != "int" && typ.Name != "int64" {
			continue
		}
		for _, name := range field.Names {
			params[name.Name] = true
		}
	}
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || sw.Init != nil {
			return true
		}
		if tag, ok := sw.Tag.(*ast.Ident); !ok || !params[tag.Name] {
			return true
		}
		if clause := defaultReturningMember(sw); clause != nil {
			pos := ctx.PositionFor(clause)
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Switch default returns what a valid case returns - an unknown value passes for that case")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Return an error for an unknown value: change the signature to (T, error)")
			v.WithContext("pattern", "switch_default_member")
			violations = append(violations, v)
		}
		return true
	})
	return violations
}

// defaultReturningMember returns the default clause of a switch whose cases
// list only named constants, when the default is a single return equal to a
// return of one of the cases.
func defaultReturningMember(sw *ast.SwitchStmt) *ast.CaseClause {
	var def *ast.CaseClause
	members := make(map[string]bool)
	for _, stmt := range sw.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			return nil
		}
		if clause.List == nil {
			def = clause
			continue
		}
		for _, expr := range clause.List {
			if !isNamedConstant(expr) {
				return nil
			}
		}
		if len(clause.Body) == 0 {
			continue
		}
		if ret, ok := clause.Body[len(clause.Body)-1].(*ast.ReturnStmt); ok {
			members[returnText(ret)] = true
		}
	}
	if def == nil || len(def.Body) != 1 {
		return nil
	}
	ret, ok := def.Body[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) == 0 || !members[returnText(ret)] {
		return nil
	}
	return def
}

// isNamedConstant reports a case value spelled as a name (FrequencyMonthly,
// pkg.FrequencyMonthly) rather than a literal.
func isNamedConstant(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name != "nil" && e.Name != "true" && e.Name != "false"
	case *ast.SelectorExpr:
		_, ok := e.X.(*ast.Ident)
		return ok
	}
	return false
}

func returnText(ret *ast.ReturnStmt) string {
	return exprListText(ret.Results)
}

// exprListText spells a list of expressions as one comparable text.
func exprListText(list []ast.Expr) string {
	texts := make([]string, len(list))
	for i, expr := range list {
		texts[i] = types.ExprString(expr)
	}
	return strings.Join(texts, ",")
}

// checkParseHelperDefaults reports a parse helper that answers an unparsable
// input with its default parameter, when the file calls it on a value the
// client sent:
//
//	func parseInt(s string, defaultValue int) int {
//	    if val, err := strconv.Atoi(s); err == nil {
//	        return val
//	    }
//	    return defaultValue
//	}
//	...
//	limit := parseInt(req.URL.Query().Get("limit"), 50)
//
// limit=abc is a client error, and the answer with 50 rows hides it.
func (r *ErrorMaskingRule) checkParseHelperDefaults(ctx *core.FileContext) []*core.Violation {
	helpers := make(map[string]*ast.IfStmt)
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Recv != nil {
			continue
		}
		if guard := parseWithDefaultGuard(fn); guard != nil {
			helpers[fn.Name.Name] = guard
		}
	}
	if len(helpers) == 0 {
		return nil
	}
	reported := make(map[string]bool)
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || helpers[ident.Name] == nil || reported[ident.Name] || len(call.Args) == 0 {
				return true
			}
			if !isRequestValue(fn.Body, call.Args[0], 2) {
				return true
			}
			reported[ident.Name] = true
			pos := ctx.PositionFor(helpers[ident.Name])
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				ident.Name+" answers an unparsable request parameter with its default - the client's error passes for a valid request")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Return an error for an unparsable value and answer the request with 400; use the default only when the parameter is absent")
			v.WithContext("pattern", "parse_helper_default")
			violations = append(violations, v)
			return true
		})
	}
	return violations
}

// parseWithDefaultGuard returns the guard of a function shaped
// `if v, err := parse(input); err == nil { return v }; return def`, where
// input and def are parameters.
func parseWithDefaultGuard(fn *ast.FuncDecl) *ast.IfStmt {
	if len(fn.Body.List) != 2 || fn.Type.Params == nil {
		return nil
	}
	guard, ok := fn.Body.List[0].(*ast.IfStmt)
	if !ok || guard.Else != nil || len(guard.Body.List) != 1 {
		return nil
	}
	ret, ok := fn.Body.List[1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil
	}
	def, ok := ret.Results[0].(*ast.Ident)
	if !ok || !fieldListsContainName(def.Name, fn.Type.Params) {
		return nil
	}
	errName, ok := successGuardErrName(guard.Cond)
	if !ok {
		return nil
	}
	assign, ok := guard.Init.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE || len(assign.Rhs) != 1 || !assignsName(assign, errName) {
		return nil
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok || !isParseCall(call) || len(call.Args) == 0 {
		return nil
	}
	input, ok := call.Args[0].(*ast.Ident)
	if !ok || !fieldListsContainName(input.Name, fn.Type.Params) {
		return nil
	}
	return guard
}
