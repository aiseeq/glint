package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewEnumUnmarshalAcceptsEmptyRule())
}

// EnumUnmarshalAcceptsEmptyRule detects an UnmarshalJSON of a value with a
// set of constants that rejects unknown values but returns nil on the empty
// string:
//
//	var raw string
//	if err := json.Unmarshal(data, &raw); err != nil { return err }
//	if raw == "" { return nil }
//	if v, ok := statusByName[raw]; ok { *s = v; return nil }
//	return fmt.Errorf("unknown status %q", raw)
//
// The method checks the value against its set, yet "" leaves the zero value:
// a message whose status came empty decodes as one with no status and goes on
// to processing, where code switching on the constants takes it for a known
// case or skips it silently. Reject "" like any value outside the set. A set
// that holds "" among its constants decodes it as a member and is not
// reported; null is the decoder's no-op and is left to
// unmarshal-json-rejects-null.
type EnumUnmarshalAcceptsEmptyRule struct {
	*rules.BaseRule
}

// NewEnumUnmarshalAcceptsEmptyRule creates the rule
func NewEnumUnmarshalAcceptsEmptyRule() *EnumUnmarshalAcceptsEmptyRule {
	return &EnumUnmarshalAcceptsEmptyRule{BaseRule: rules.NewBaseRule(
		"enum-unmarshal-accepts-empty",
		"patterns",
		"Detects an UnmarshalJSON that rejects values outside a set of constants but lets the empty string through as the zero value",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the empty-string exits of the enum UnmarshalJSON
// methods of a file.
func (r *EnumUnmarshalAcceptsEmptyRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	consts := constValuesByType(ctx.GoAST)
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil || fn.Name.Name != "UnmarshalJSON" {
			continue
		}
		values := consts[receiverTypeName(fn.Recv)]
		if len(values) < 2 || values[`""`] {
			continue
		}
		data := unmarshalDataParam(fn)
		if data == "" || !failsOutsideErrCheck(fn.Body) {
			continue
		}
		for _, raw := range decodedStrings(fn.Body, data) {
			check := emptyAcceptance(fn.Body, raw)
			if check == nil {
				continue
			}
			line := ctx.LineFor(check)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line, "UnmarshalJSON rejects values outside the set but lets \"\" through — an empty value decodes as the zero value and goes on to processing")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Return an error naming the value for \"\" as for any value outside the set")
			violations = append(violations, v)
		}
	}
	return violations
}

// constValuesByType returns the string literal values of the typed constants
// of a file by type name: const A Status = "a" and the specs of a block that
// repeat the type.
func constValuesByType(file *ast.File) map[string]map[string]bool {
	values := make(map[string]map[string]bool)
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			typ, ok := vs.Type.(*ast.Ident)
			if !ok {
				continue
			}
			for _, value := range vs.Values {
				lit, ok := value.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if values[typ.Name] == nil {
					values[typ.Name] = make(map[string]bool)
				}
				text := lit.Value
				if text == "``" {
					text = `""`
				}
				values[typ.Name][text] = true
			}
		}
	}
	return values
}

// decodedStrings returns the string locals the method decodes the data into:
// json.Unmarshal(data, &raw) or raw, err := strconv.Unquote(string(data)).
func decodedStrings(body *ast.BlockStmt, data string) []string {
	stringVars := stringLocals(body)
	var names []string
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if isSelectorCall(node, "json", "Unmarshal") && len(node.Args) == 2 && isIdentNamed(node.Args[0], data) {
				if unary, ok := node.Args[1].(*ast.UnaryExpr); ok && unary.Op == token.AND {
					if id, ok := unary.X.(*ast.Ident); ok && stringVars[id.Name] {
						names = append(names, id.Name)
					}
				}
			}
		case *ast.AssignStmt:
			if len(node.Rhs) == 1 && len(node.Lhs) == 2 {
				if call, ok := node.Rhs[0].(*ast.CallExpr); ok && isSelectorCall(call, "strconv", "Unquote") {
					if id, ok := node.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
						names = append(names, id.Name)
					}
				}
			}
		}
		return true
	})
	return names
}

// emptyAcceptance returns the if statement of the body that returns nil when
// the decoded value is empty: if raw == "" { return nil }.
func emptyAcceptance(body *ast.BlockStmt, raw string) *ast.IfStmt {
	for _, stmt := range body.List {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok || ifStmt.Init != nil || ifStmt.Else != nil || len(ifStmt.Body.List) != 1 {
			continue
		}
		bin, ok := ast.Unparen(ifStmt.Cond).(*ast.BinaryExpr)
		if !ok || bin.Op != token.EQL || !isIdentNamed(bin.X, raw) {
			continue
		}
		if lit, ok := bin.Y.(*ast.BasicLit); !ok || lit.Value != `""` {
			continue
		}
		ret, ok := ifStmt.Body.List[0].(*ast.ReturnStmt)
		if ok && len(ret.Results) == 1 && isIdentNamed(ret.Results[0], "nil") {
			return ifStmt
		}
	}
	return nil
}
