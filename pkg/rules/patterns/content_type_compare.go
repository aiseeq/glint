package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewContentTypeExactCompareRule())
}

// ContentTypeExactCompareRule detects a Content-Type header compared with a
// media type as a whole string:
//
//	if req.Header.Get("Content-Type") == "application/json" { parse(body) }
//
// The header carries parameters: a client sending
// "application/json; charset=utf-8" is not JSON to this comparison, and the
// body is skipped - or the request rejected - without a word. Compare the
// media type alone: mime.ParseMediaType, or strings.HasPrefix for a quick
// check. A comparison with "" (is the header set) is not reported.
type ContentTypeExactCompareRule struct {
	*rules.BaseRule
}

// NewContentTypeExactCompareRule creates the rule
func NewContentTypeExactCompareRule() *ContentTypeExactCompareRule {
	return &ContentTypeExactCompareRule{BaseRule: rules.NewBaseRule(
		"content-type-exact-compare",
		"patterns",
		"Detects a Content-Type header compared with == or switch to a media type — a header with parameters (; charset=utf-8) does not match",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the exact comparisons of a file's Content-Type reads.
func (r *ContentTypeExactCompareRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	report := func(node ast.Node) {
		line := ctx.LineFor(node)
		if ctx.IsSuppressed(line, r.Name()) {
			return
		}
		v := r.CreateViolation(ctx.RelPath, line, "Content-Type compared as a whole string — \"application/json; charset=utf-8\" does not match, and the body is skipped or refused")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Compare the media type: mt, _, err := mime.ParseMediaType(header); or strings.HasPrefix(header, \"application/json\")")
		violations = append(violations, v)
	}
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		headers := contentTypeVariables(fn.Body)
		isHeader := func(expr ast.Expr) bool {
			if ident, ok := expr.(*ast.Ident); ok {
				return headers[ident.Name]
			}
			return readsContentType(expr)
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BinaryExpr:
				if node.Op != token.EQL && node.Op != token.NEQ {
					return true
				}
				if (isHeader(node.X) && mediaTypeLiteral(node.Y)) || (isHeader(node.Y) && mediaTypeLiteral(node.X)) {
					report(node)
				}
			case *ast.SwitchStmt:
				if node.Tag == nil || !isHeader(node.Tag) {
					return true
				}
				for _, stmt := range node.Body.List {
					clause, ok := stmt.(*ast.CaseClause)
					if !ok {
						continue
					}
					for _, value := range clause.List {
						if mediaTypeLiteral(value) {
							report(clause)
							break
						}
					}
				}
			}
			return true
		})
	}
	return violations
}

// contentTypeVariables returns the local variables a function assigns a
// Content-Type read to (ct := r.Header.Get("Content-Type")).
func contentTypeVariables(body *ast.BlockStmt) map[string]bool {
	vars := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			if ident, ok := assign.Lhs[i].(*ast.Ident); ok && readsContentType(rhs) {
				vars[ident.Name] = true
			}
		}
		return true
	})
	return vars
}

// readsContentType reports a call <header>.Get("Content-Type"), the key in
// any case.
func readsContentType(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Get" {
		return false
	}
	key, ok := literalText(call.Args[0])
	return ok && strings.EqualFold(key, "Content-Type")
}

// mediaTypeLiteral reports a string literal holding a media type (type/subtype).
func mediaTypeLiteral(expr ast.Expr) bool {
	text, ok := literalText(expr)
	return ok && strings.Contains(text, "/")
}

// literalText returns the value of a string literal expression.
func literalText(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return "", false
	}
	return goStringLiteral(lit)
}
