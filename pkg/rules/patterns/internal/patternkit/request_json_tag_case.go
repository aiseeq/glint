package patternkit

import (
	"go/ast"
	"go/types"
	"reflect"
	"strings"

	"golang.org/x/tools/go/types/typeutil"
)

// JsonTagName returns the explicit JSON name of a struct tag.
func JsonTagName(tag string) (string, bool) {
	value, ok := reflect.StructTag(tag).Lookup("json")
	if !ok {
		return "", false
	}
	name, _, _ := strings.Cut(value, ",")
	if name == "" || name == "-" {
		return "", false
	}
	return name, true
}

// RequestDecodeTargets returns the expressions a function decodes an
// incoming request's body into: json.NewDecoder(r.Body).Decode(&v), or
// json.Unmarshal(b, &v) with b read from r.Body.
func RequestDecodeTargets(fn TypedFunc) []ast.Expr {
	info := fn.Info
	bodies := make(map[types.Object]bool) // locals holding io.ReadAll(r.Body)
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || !isFuncOf(call, info, "ReadAll", "io", "io/ioutil") || RequestBody(info, call.Args[0]) == "" {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok {
			if obj := info.ObjectOf(id); obj != nil {
				bodies[obj] = true
			}
		}
		return true
	})

	var targets []ast.Expr
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case isFuncOf(call, info, "Decode", "encoding/json") && len(call.Args) == 1:
			sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok {
				return true
			}
			decoder, ok := ast.Unparen(sel.X).(*ast.CallExpr)
			if ok && isFuncOf(decoder, info, "NewDecoder", "encoding/json") && len(decoder.Args) == 1 && RequestBody(info, decoder.Args[0]) != "" {
				targets = append(targets, call.Args[0])
			}
		case isFuncOf(call, info, "Unmarshal", "encoding/json") && len(call.Args) == 2:
			if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); ok && bodies[info.Uses[id]] {
				targets = append(targets, call.Args[1])
			}
		}
		return true
	})
	return targets
}

// isFuncOf reports a call of a function or method named name declared in
// one of the packages.
func isFuncOf(call *ast.CallExpr, info *types.Info, name string, pkgs ...string) bool {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Name() != name {
		return false
	}
	for _, pkg := range pkgs {
		if fn.Pkg().Path() == pkg {
			return true
		}
	}
	return false
}
