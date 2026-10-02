package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewUpdateHandlerResetsOmittedFieldsRule())
}

// NewUpdateHandlerResetsOmittedFieldsRule creates
// update-handler-resets-omitted-fields: an update handler that decodes the
// body into value fields - a string, a number, a decimal: nothing tells an
// omitted field from a zero one - and builds the entity from scratch instead
// of loading the stored one, overwrites every column the request left out:
//
//	var body struct{ Name string; Amount decimal.Decimal; Status string }
//	json.NewDecoder(req.Body).Decode(&body)
//	pos := NewPosition(body.Name, body.Amount)
//	pos.ID = id
//	s.UpdatePosition(ctx, pos)        // a PUT with only "name" zeroes the amount
//
// A handler that reads the stored record first (Get*, Find*, Load*) merges
// into it and is not reported.
func NewUpdateHandlerResetsOmittedFieldsRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"update-handler-resets-omitted-fields",
			"patterns",
			"Detects an update handler that builds the entity from a body of value fields instead of loading the stored one — every field the request left out is written as zero",
			core.SeverityMedium,
		),
		suggestion: "Decode into pointer fields, load the stored record (404 when missing) and copy only the fields the request sent",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if handlerRequestParam(typedFunc{info: scope.info, decl: fn}) == nil {
			return nil
		}
		body := decodedValueBody(scope.info, fn.Body)
		if body == nil {
			return nil
		}
		built := builtFromBody(scope.info, fn.Body, body)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok || !helpers.HasLeadingWord(sel.Sel.Name, "Update") && !helpers.HasLeadingWord(sel.Sel.Name, "Replace") {
				return true
			}
			for _, arg := range call.Args {
				if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && built[scope.info.ObjectOf(ident)] && !readsStoredBefore(fn.Body, call) {
					findings = append(findings, funcFinding{node: call, message: "The update writes " + ident.Name + " built from the request body of value fields, not from the stored record — every field the request left out is written as zero"})
					return true
				}
			}
			return true
		})
		return findings
	}
	return r
}

// decodedValueBody returns the variable a handler decodes the request body
// into (Decode(&body), Unmarshal(data, &body)) when its struct has at least
// two value fields that cannot tell an omitted field from a zero one.
func decodedValueBody(info *types.Info, body *ast.BlockStmt) types.Object {
	var found types.Object
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != nil {
			return found == nil
		}
		name := strings.ToLower(callName(call))
		if !strings.Contains(name, "decode") && !strings.Contains(name, "unmarshal") && !strings.Contains(name, "bind") {
			return true
		}
		for _, arg := range call.Args {
			unary, ok := ast.Unparen(arg).(*ast.UnaryExpr)
			if !ok || unary.Op != token.AND {
				continue
			}
			ident, ok := ast.Unparen(unary.X).(*ast.Ident)
			if !ok {
				continue
			}
			if obj := info.ObjectOf(ident); obj != nil && valueFields(obj.Type()) >= 2 {
				found = obj
			}
		}
		return true
	})
	return found
}

// valueFields counts the fields of a struct that hold a value directly: no
// pointer, slice, map or interface to tell "not sent" from zero.
func valueFields(t types.Type) int {
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return 0
	}
	count := 0
	for i := range st.NumFields() {
		switch st.Field(i).Type().Underlying().(type) {
		case *types.Pointer, *types.Slice, *types.Map, *types.Interface:
		default:
			count++
		}
	}
	return count
}

// builtFromBody returns the variables a handler builds from scratch out of
// the decoded body: a constructor call (New*) or a composite literal that
// reads its fields.
func builtFromBody(info *types.Info, body *ast.BlockStmt, decoded types.Object) map[types.Object]bool {
	built := make(map[types.Object]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			ident, ok := assign.Lhs[i].(*ast.Ident)
			if !ok || !freshFromBody(info, rhs, decoded) {
				continue
			}
			if obj := info.ObjectOf(ident); obj != nil {
				built[obj] = true
			}
		}
		return true
	})
	return built
}

// freshFromBody reports New*(body.X, ...) or &T{F: body.X}.
func freshFromBody(info *types.Info, expr ast.Expr, decoded types.Object) bool {
	expr = ast.Unparen(expr)
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = ast.Unparen(unary.X)
	}
	switch e := expr.(type) {
	case *ast.CallExpr:
		if !helpers.HasLeadingWord(callName(e), "New") {
			return false
		}
	case *ast.CompositeLit:
	default:
		return false
	}
	reads := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && info.Uses[ident] == decoded {
			reads = true
		}
		return !reads
	})
	return reads
}

// readsStoredBefore reports a read of a stored record before the update:
// Get*, Find*, Load*, Fetch*.
func readsStoredBefore(body *ast.BlockStmt, update *ast.CallExpr) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found || call.Pos() >= update.Pos() {
			return !found
		}
		name := callName(call)
		for _, verb := range []string{"Get", "Find", "Load", "Fetch"} {
			if helpers.HasLeadingWord(name, verb) {
				found = true
			}
		}
		return !found
	})
	return found
}
