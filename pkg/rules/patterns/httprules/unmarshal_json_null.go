package httprules

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewUnmarshalJSONRejectsNullRule())
}

// UnmarshalJSONRejectsNullRule detects an UnmarshalJSON of a string value
// that fails on JSON null:
//
//	func (s *Status) UnmarshalJSON(data []byte) error {
//		var raw string
//		if err := json.Unmarshal(data, &raw); err != nil { ... }
//		if v, ok := statusByName[strings.ToLower(raw)]; ok { *s = v; return nil }
//		return fmt.Errorf("unknown status %q", raw)
//	}
//
// encoding/json hands a null value to the method as the bytes null, and by
// its convention an Unmarshaler treats them as a no-op. Here null decodes to
// "" and is rejected as an unknown value - or, with strconv.Unquote, fails
// outright - so one field sent as null fails the whole document. Reported
// when the method never looks at null or at the empty string.
type UnmarshalJSONRejectsNullRule struct {
	*rules.BaseRule
}

// NewUnmarshalJSONRejectsNullRule creates the rule
func NewUnmarshalJSONRejectsNullRule() *UnmarshalJSONRejectsNullRule {
	return &UnmarshalJSONRejectsNullRule{BaseRule: rules.NewBaseRule(
		"unmarshal-json-rejects-null",
		"patterns",
		"Detects an UnmarshalJSON of a string value that fails on JSON null instead of leaving the value as it is",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the UnmarshalJSON methods of a file that reject null.
func (r *UnmarshalJSONRejectsNullRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !patternkit.ProductionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil || fn.Name.Name != "UnmarshalJSON" {
			continue
		}
		data := patternkit.UnmarshalDataParam(fn)
		if data == "" || mentionsNullOrEmpty(fn.Body) || !rejectsNull(fn.Body, data) {
			continue
		}
		line := ctx.LineFor(fn.Name)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, "UnmarshalJSON fails on null — encoding/json passes a null field to it, and the whole document fails to decode")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion(`Return nil first when string(data) == "null", leaving the value as it is`)
		violations = append(violations, v)
	}
	return violations
}

// mentionsNullOrEmpty reports a "null" or "" literal: the method handles
// null itself or lets an empty value through.
func mentionsNullOrEmpty(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if lit.Value == `""` || lit.Value == "``" || strings.Contains(lit.Value, "null") {
				found = true
			}
		}
		return !found
	})
	return found
}

// rejectsNull reports a method that unquotes the data (null is no quoted
// string) or decodes it into a string and then returns an error outside the
// check of the decoding's own error.
func rejectsNull(body *ast.BlockStmt, data string) bool {
	stringVars := patternkit.StringLocals(body)
	decodes := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case patternkit.IsSelectorCall(call, "strconv", "Unquote") && len(call.Args) == 1 && convertsIdent(call.Args[0], data):
			decodes = true
		case patternkit.IsSelectorCall(call, "json", "Unmarshal") && len(call.Args) == 2 && helpers.IsIdentNamed(call.Args[0], data):
			if unary, ok := call.Args[1].(*ast.UnaryExpr); ok && unary.Op == token.AND {
				if id, ok := unary.X.(*ast.Ident); ok && stringVars[id.Name] {
					decodes = patternkit.FailsOutsideErrCheck(body)
				}
			}
		}
		return true
	})
	return decodes
}

// convertsIdent reports string(name).
func convertsIdent(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	return ok && len(call.Args) == 1 && helpers.IsIdentNamed(call.Fun, "string") && helpers.IsIdentNamed(call.Args[0], name)
}
