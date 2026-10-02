package patterns

import (
	"go/ast"
	"go/types"
	"reflect"
	"strings"
)

// foreignFloatFieldsToDecimal returns the decimal.NewFromFloat calls of the
// file whose argument reads a float money field of a JSON-tagged struct
// declared outside module: directly (pos.Attributes.Price), through a map
// field (j.Prices["USD"]), or through a local defined from either. A field
// of the module's own structs is left to the declaration check.
func foreignFloatFieldsToDecimal(file *ast.File, info *types.Info, module string) []*ast.CallExpr {
	var found []*ast.CallExpr
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// defined holds the value a local was defined from: priceF := j.Prices["USD"].
		defined := make(map[types.Object]ast.Expr)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Lhs) == len(assign.Rhs) {
				for i, lhs := range assign.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && info.Defs[id] != nil {
						defined[info.Defs[id]] = assign.Rhs[i]
					}
				}
			}
			return true
		})
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 || !isDecimalFromFloat(call, info) {
				return true
			}
			arg := ast.Unparen(call.Args[0])
			if id, ok := arg.(*ast.Ident); ok {
				if value, ok := defined[info.Uses[id]]; ok {
					arg = ast.Unparen(value)
				}
			}
			if index, ok := arg.(*ast.IndexExpr); ok {
				arg = ast.Unparen(index.X)
			}
			sel, ok := arg.(*ast.SelectorExpr)
			if ok && foreignMoneyFloatField(sel, info, module) {
				found = append(found, call)
			}
			return true
		})
	}
	return found
}

// isDecimalFromFloat reports a call of NewFromFloat or NewFromFloat32 of a
// decimal package.
func isDecimalFromFloat(call *ast.CallExpr, info *types.Info) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "NewFromFloat" && sel.Sel.Name != "NewFromFloat32") {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && strings.HasSuffix(fn.Pkg().Path(), "decimal")
}

// foreignMoneyFloatField reports a selector of a struct field, declared in a
// package outside module, that holds a float (or a map of floats), carries a
// json tag and is named as money.
func foreignMoneyFloatField(sel *ast.SelectorExpr, info *types.Info, module string) bool {
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.FieldVal {
		return false
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok || field.Pkg() == nil {
		return false
	}
	path := field.Pkg().Path()
	if path == module || strings.HasPrefix(path, module+"/") {
		return false
	}
	tag, ok := fieldTag(selection)
	if !ok {
		return false
	}
	jsonTag, ok := reflect.StructTag(tag).Lookup("json")
	if !ok {
		return false
	}
	jsonName := strings.Split(jsonTag, ",")[0]
	if jsonName == "-" || !floatOrFloatMap(field.Type()) {
		return false
	}
	name := jsonName + " " + field.Name()
	return strongFinancialName(name) || weakFinancialName(name)
}

// fieldTag returns the struct tag of the field a selection ends at, walking
// the embedded fields its index path goes through.
func fieldTag(selection *types.Selection) (string, bool) {
	typ := selection.Recv()
	tag := ""
	for _, index := range selection.Index() {
		if ptr, ok := typ.Underlying().(*types.Pointer); ok {
			typ = ptr.Elem()
		}
		st, ok := typ.Underlying().(*types.Struct)
		if !ok || index >= st.NumFields() {
			return "", false
		}
		tag = st.Tag(index)
		typ = st.Field(index).Type()
	}
	return tag, true
}

func floatOrFloatMap(typ types.Type) bool {
	if m, ok := typ.Underlying().(*types.Map); ok {
		typ = m.Elem()
	}
	basic, ok := typ.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsFloat != 0
}
