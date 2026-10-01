package security

import (
	"go/ast"
	"go/token"
	"regexp"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPaginationLimitUncappedRule())
}

// PaginationLimitUncappedRule detects a page size taken from the request
// with no upper bound:
//
//	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
//	    limit = v
//	}
//	rows, err := repo.List(ctx, limit, offset)
//
// limit=10000000 loads the whole table into memory and into the response:
// one request is enough to slow the database and the server for everyone. A
// comparison of the parsed value (or a variable it went into) with anything
// but 0 or 1, or min(), counts as a bound.
type PaginationLimitUncappedRule struct {
	*rules.BaseRule
}

// NewPaginationLimitUncappedRule creates the rule
func NewPaginationLimitUncappedRule() *PaginationLimitUncappedRule {
	return &PaginationLimitUncappedRule{BaseRule: rules.NewBaseRule(
		"pagination-limit-uncapped",
		"security",
		"Detects a page size (limit, page_size, per_page) parsed from the request with no upper bound — one request loads the whole table",
		core.SeverityMedium,
	)}
}

var pageSizeParam = regexp.MustCompile(`(?i)^(?:limit|page_?size|per_?page|max_?results|take)$`)

// AnalyzeFile reports page sizes parsed from requests and never capped.
func (r *PaginationLimitUncappedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		r.checkFunction(fn.Body, lr)
	}
	return lr.violations
}

func (r *PaginationLimitUncappedRule) checkFunction(body *ast.BlockStmt, lr *lineReporter) {
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !isIntParse(call) || len(call.Args) == 0 || !pageSizeSource(body, call.Args[0]) {
			return true
		}
		parsed, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || parsed.Name == "_" {
			return true
		}
		if !bounded(body, receivers(body, parsed.Name)) {
			lr.report(call, "Page size from the request has no upper bound — limit=10000000 loads the whole table into memory and the response",
				"Cap it (if limit > maxLimit { limit = maxLimit }) or reject values above the maximum", "pagination_limit_uncapped")
		}
		return true
	})
}

// lastAssigned returns the value a function last assigns to name before pos.
func lastAssigned(body *ast.BlockStmt, name string, pos token.Pos) ast.Expr {
	var value ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.End() > pos || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name == name {
				value = assign.Rhs[i]
			}
		}
		return true
	})
	return value
}

// pageSizeQuery reports X.Get("limit") or X.FormValue("limit").
func pageSizeQuery(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	name := callName(call)
	return (name == "Get" || name == "FormValue" || name == "PostFormValue") && pageSizeParam.MatchString(stringLiteral(call.Args[0]))
}

// pageSizeSource reports a parse argument that is a page-size query value,
// or a variable last assigned one.
func pageSizeSource(body *ast.BlockStmt, arg ast.Expr) bool {
	if ident, ok := ast.Unparen(arg).(*ast.Ident); ok {
		value := lastAssigned(body, ident.Name, arg.Pos())
		return value != nil && pageSizeQuery(value)
	}
	return pageSizeQuery(arg)
}

// isIntParse reports strconv.Atoi, ParseInt or ParseUint.
func isIntParse(call *ast.CallExpr) bool {
	pkg, ok := callPackage(call)
	name := callName(call)
	return ok && pkg == "strconv" && (name == "Atoi" || name == "ParseInt" || name == "ParseUint")
}

// receivers returns the parsed variable and the variables it is assigned to,
// directly or through a conversion.
func receivers(body *ast.BlockStmt, parsed string) map[string]bool {
	names := map[string]bool{parsed: true}
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != len(assign.Rhs) {
				return true
			}
			for i, rhs := range assign.Rhs {
				lhs, ok := assign.Lhs[i].(*ast.Ident)
				if ok && !names[lhs.Name] && mentionsAny(rhs, names) {
					names[lhs.Name] = true
					changed = true
				}
			}
			return true
		})
	}
	return names
}

// bounded reports a comparison of one of the names with a value other than
// 0 or 1, or a min() over one of them.
func bounded(body *ast.BlockStmt, names map[string]bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			switch node.Op {
			case token.GTR, token.GEQ, token.LSS, token.LEQ:
				if (mentionsAny(node.X, names) && !lowBound(node.Y)) || (mentionsAny(node.Y, names) && !lowBound(node.X)) {
					found = true
				}
			}
		case *ast.CallExpr:
			if name := callName(node); (name == "min" || name == "Min") && mentionsAny(node, names) {
				found = true
			}
		}
		return !found
	})
	return found
}

// lowBound reports the literal 0 or 1 a positivity check compares with.
func lowBound(expr ast.Expr) bool {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	return ok && lit.Kind == token.INT && (lit.Value == "0" || lit.Value == "1")
}

// mentionsAny reports an expression naming one of the identifiers.
func mentionsAny(expr ast.Node, names map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && names[ident.Name] {
			found = true
		}
		return !found
	})
	return found
}
