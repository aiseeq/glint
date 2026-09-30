package patterns

import (
	"go/ast"
	"go/types"
	"reflect"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewResponseTypeInFunctionRule())
}

// ResponseTypeInFunctionRule detects a wire contract declared inside a function body.
//
// A struct with json tags that a function builds and hands to a response writer is an API
// contract, but declaring it in function scope hides it from every consumer: type
// generators cannot emit it, other handlers cannot reuse it, and clients end up
// hand-copying the field list. Each hand-made copy then drifts on its own.
//
// Real case (ProjectA, 2026-07-29): the dashboard response type lived inside the handler, so the
// Go→TypeScript generator never saw it and the frontend grew three hand-written copies with
// different field sets. Two screens read different copies and showed different balances under
// the same label.
//
// Only produced contracts are reported. A local struct used to decode a request body is a
// normal Go idiom: it is filled by the decoder, never composed field by field, so it does not
// match.
type ResponseTypeInFunctionRule struct {
	*rules.BaseRule
}

// NewResponseTypeInFunctionRule creates the rule
func NewResponseTypeInFunctionRule() *ResponseTypeInFunctionRule {
	return &ResponseTypeInFunctionRule{
		BaseRule: rules.NewBaseRule(
			"response-type-in-function",
			"patterns",
			"Detects API response structs declared inside a function — invisible to type generators and consumers",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks one file without type information: only a literal of the
// local type written right into a call or a return is seen.
func (r *ResponseTypeInFunctionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ResponseTypeInFunctionRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; with type information any value of the
// local type — a variable, a pointer, a slice of it — that reaches a call or a
// return counts.
func (r *ResponseTypeInFunctionRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze reports function-local structs with json tags that are sent as a response.
func (r *ResponseTypeInFunctionRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		body, name := functionBody(n)
		if body == nil {
			return true
		}

		// Порядок обхода map в Go случаен: без сортировки один и тот же файл давал бы
		// находки в разном порядке от запуска к запуску.
		locals := localJSONStructs(body)
		typeNames := make([]string, 0, len(locals))
		for typeName := range locals {
			typeNames = append(typeNames, typeName)
		}
		sort.Strings(typeNames)

		for _, typeName := range typeNames {
			spec := locals[typeName]
			sent := false
			if info == nil {
				sent = isComposedAndPassedOn(body, typeName)
			} else if obj, ok := info.Defs[spec.Name].(*types.TypeName); ok {
				sent = isComposedAndPassedOnTyped(info, body, obj.Type())
			}
			if sent {
				violations = append(violations, r.violation(ctx, spec, typeName, name))
			}
		}
		return true
	})

	return violations
}

func (r *ResponseTypeInFunctionRule) violation(ctx *core.FileContext, spec *ast.TypeSpec, typeName, funcName string) *core.Violation {
	line := ctx.LineFor(spec)
	v := r.CreateViolation(ctx.RelPath, line,
		"Response contract '"+typeName+"' is declared inside '"+funcName+"' — no generator or client can reference it")
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Move '" + typeName + "' to package scope (shared types package) so generated clients and other handlers use one definition")
	v.WithContext("pattern", "response_type_in_function")
	v.WithContext("type", typeName)
	v.WithContext("function", funcName)
	return v
}

// functionBody returns the body and name of a function or method declaration.
func functionBody(n ast.Node) (*ast.BlockStmt, string) {
	switch fn := n.(type) {
	case *ast.FuncDecl:
		if fn.Body == nil {
			return nil, ""
		}
		return fn.Body, fn.Name.Name
	case *ast.FuncLit:
		return fn.Body, "func literal"
	}
	return nil, ""
}

// localJSONStructs collects struct types declared in the body — in any of its
// blocks, but not in the function literals it holds, which are checked on
// their own — that carry json tags. A struct without json tags is an internal
// helper, not a wire contract.
func localJSONStructs(body *ast.BlockStmt) map[string]*ast.TypeSpec {
	found := map[string]*ast.TypeSpec{}

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.DeclStmt:
			gen, ok := node.Decl.(*ast.GenDecl)
			if !ok {
				return false
			}
			for _, s := range gen.Specs {
				spec, ok := s.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structType, ok := spec.Type.(*ast.StructType)
				if !ok || countJSONTaggedFields(structType) == 0 {
					continue
				}
				found[spec.Name.Name] = spec
			}
			return false
		}
		return true
	})

	return found
}

func countJSONTaggedFields(structType *ast.StructType) int {
	if structType.Fields == nil {
		return 0
	}
	count := 0
	for _, field := range structType.Fields.List {
		if field.Tag == nil {
			continue
		}
		tag := strings.Trim(field.Tag.Value, "`")
		if _, ok := reflect.StructTag(tag).Lookup("json"); ok {
			count++
		}
	}
	return count
}

// isComposedAndPassedOn reports whether the body builds a value of the type and hands it
// somewhere: as a call argument or as a return value. That is what makes it an outgoing
// contract rather than a decode target.
func isComposedAndPassedOn(body *ast.BlockStmt, typeName string) bool {
	passed := false

	ast.Inspect(body, func(n ast.Node) bool {
		if passed {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			for _, arg := range node.Args {
				if isCompositeOfType(arg, typeName) {
					passed = true
					return false
				}
			}
		case *ast.ReturnStmt:
			for _, result := range node.Results {
				if isCompositeOfType(result, typeName) {
					passed = true
					return false
				}
			}
		}
		return true
	})

	return passed
}

// isCompositeOfType unwraps &T{...} and T{...} and reports whether the literal builds typeName.
func isCompositeOfType(expr ast.Expr, typeName string) bool {
	if unary, ok := expr.(*ast.UnaryExpr); ok {
		expr = unary.X
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return false
	}
	ident, ok := lit.Type.(*ast.Ident)
	return ok && ident.Name == typeName
}

// isComposedAndPassedOnTyped reports whether the body builds a value of the
// local type t by its fields and hands a value of it — itself, a pointer, a
// slice, array or map of it — to a call or a return. Builtins (append, len)
// only move the value around inside the function and do not count.
func isComposedAndPassedOnTyped(info *types.Info, body *ast.BlockStmt, t types.Type) bool {
	composed, passed := false, false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			if types.Identical(info.TypeOf(node), t) {
				composed = true
			}
		case *ast.CallExpr:
			if isBuiltinCall(info, node) {
				return true
			}
			for _, arg := range node.Args {
				if carriesType(info.TypeOf(arg), t) {
					passed = true
				}
			}
		case *ast.ReturnStmt:
			for _, result := range node.Results {
				if carriesType(info.TypeOf(result), t) {
					passed = true
				}
			}
		}
		return !composed || !passed
	})
	return composed && passed
}

// isBuiltinCall reports whether the call is to a Go builtin.
func isBuiltinCall(info *types.Info, call *ast.CallExpr) bool {
	ident, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	_, builtin := info.Uses[ident].(*types.Builtin)
	return builtin
}

// carriesType reports whether a value of type v is t or holds it as the
// element of pointers, slices, arrays and maps.
func carriesType(v, t types.Type) bool {
	for v != nil {
		if types.Identical(v, t) {
			return true
		}
		switch container := v.(type) {
		case *types.Pointer:
			v = container.Elem()
		case *types.Slice:
			v = container.Elem()
		case *types.Array:
			v = container.Elem()
		case *types.Map:
			v = container.Elem()
		default:
			return false
		}
	}
	return false
}
