package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil || fn.Name.Name != "UnmarshalJSON" {
			continue
		}
		data := unmarshalDataParam(fn)
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

// unmarshalDataParam returns the name of the []byte parameter.
func unmarshalDataParam(fn *ast.FuncDecl) string {
	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 {
		return ""
	}
	return params[0].Names[0].Name
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
	stringVars := stringLocals(body)
	decodes := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case isSelectorCall(call, "strconv", "Unquote") && len(call.Args) == 1 && convertsIdent(call.Args[0], data):
			decodes = true
		case isSelectorCall(call, "json", "Unmarshal") && len(call.Args) == 2 && isIdentNamed(call.Args[0], data):
			if unary, ok := call.Args[1].(*ast.UnaryExpr); ok && unary.Op == token.AND {
				if id, ok := unary.X.(*ast.Ident); ok && stringVars[id.Name] {
					decodes = failsOutsideErrCheck(body)
				}
			}
		}
		return true
	})
	return decodes
}

// stringLocals returns the names declared as var x string.
func stringLocals(body *ast.BlockStmt) map[string]bool {
	names := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Values) != 0 {
			return true
		}
		if typ, ok := spec.Type.(*ast.Ident); ok && typ.Name == "string" {
			for _, name := range spec.Names {
				names[name.Name] = true
			}
		}
		return true
	})
	return names
}

// failsOutsideErrCheck reports a return of a non-nil error that is not
// inside an if err != nil branch: a rejection of the decoded value.
func failsOutsideErrCheck(body *ast.BlockStmt) bool {
	found := false
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			if isErrNotNil(node.Cond) {
				if node.Init != nil {
					ast.Inspect(node.Init, walk)
				}
				if node.Else != nil {
					ast.Inspect(node.Else, walk)
				}
				return false
			}
		case *ast.ReturnStmt:
			if len(node.Results) == 1 && !isIdentNamed(node.Results[0], "nil") {
				found = true
			}
		}
		return true
	}
	ast.Inspect(body, walk)
	return found
}

// isErrNotNil reports a condition err != nil.
func isErrNotNil(cond ast.Expr) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ || !isIdentNamed(bin.Y, "nil") {
		return false
	}
	id, ok := bin.X.(*ast.Ident)
	return ok && strings.HasPrefix(strings.ToLower(id.Name), "err")
}

// isSelectorCall reports pkg.name(...) by the spelling of the call.
func isSelectorCall(call *ast.CallExpr, pkg, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == name && isIdentNamed(sel.X, pkg)
}

// convertsIdent reports string(name).
func convertsIdent(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	return ok && len(call.Args) == 1 && isIdentNamed(call.Fun, "string") && isIdentNamed(call.Args[0], name)
}
