package patterns

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewReflectInHotFunctionRule())
}

// NewReflectInHotFunctionRule creates reflect-in-hot-function: a call into
// package reflect - reflect.ValueOf, Value.Set, FieldByName, reflect.DeepEqual,
// a method of reflect.Type - in a function marked //glint:hot. Reflection
// boxes its operands into interfaces, looks fields up by name and checks
// types at run time on every call:
//
//	reflect.ValueOf(dst).Elem().FieldByName(name).Set(reflect.ValueOf(src).Elem().FieldByName(name))
//
// The hot form names the fields in code: a bit mask of the fields and a
// switch or a plain assignment per bit. reflect.TypeFor is resolved by the
// compiler and is not reported. One finding per expression: a chain of
// reflect calls is one place to rewrite.
func NewReflectInHotFunctionRule() *hotFuncRule {
	return &hotFuncRule{
		BaseRule: rules.NewBaseRule(
			"reflect-in-hot-function",
			"patterns",
			"Detects a call into package reflect (ValueOf, Value.Set, FieldByName, DeepEqual, Type methods) in a function marked //glint:hot — reflection boxes values and looks fields up at run time on every call; name the fields in code (a bit mask and an assignment per bit)",
			core.SeverityMedium,
		),
		suggestion: "Name the fields in code: a bit mask of the fields with a switch or an assignment per bit, a typed comparison instead of reflect.DeepEqual; a lookup done once outside the tick takes // reflect-in-hot-function: safe — <reason>",
		check:      hotReflectCalls,
	}
}

// hotReflectCalls returns the outermost reflect calls of the function body,
// closures included.
func hotReflectCalls(scope hotScope, fn *ast.FuncDecl) []funcFinding {
	var findings []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := staticFunc(scope.info, call)
		if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "reflect" || callee.Name() == "TypeFor" {
			return true
		}
		findings = append(findings, funcFinding{node: call, message: "reflect." + reflectCallName(callee) + scope.in + " runs reflection on every call"})
		return false
	})
	return findings
}

// reflectCallName names a reflect function or method as Value.Set or ValueOf.
func reflectCallName(fn *types.Func) string {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return fn.Name()
	}
	recv := sig.Recv().Type()
	if ptr, isPtr := recv.(*types.Pointer); isPtr {
		recv = ptr.Elem()
	}
	if named, isNamed := types.Unalias(recv).(*types.Named); isNamed {
		return named.Obj().Name() + "." + fn.Name()
	}
	return fn.Name()
}
