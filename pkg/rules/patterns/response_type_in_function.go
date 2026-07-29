package patterns

import (
	"go/ast"
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
// Real case (Saga, 2026-07-29): the dashboard response type lived inside the handler, so the
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

// AnalyzeFile reports function-local structs with json tags that are sent as a response.
func (r *ResponseTypeInFunctionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
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
			if !isComposedAndPassedOn(body, typeName) {
				continue
			}
			violations = append(violations, r.violation(ctx, locals[typeName], typeName, name))
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

// localJSONStructs collects struct types declared in the body that carry json tags.
// A struct without json tags is an internal helper, not a wire contract.
func localJSONStructs(body *ast.BlockStmt) map[string]*ast.TypeSpec {
	found := map[string]*ast.TypeSpec{}

	for _, stmt := range body.List {
		decl, ok := stmt.(*ast.DeclStmt)
		if !ok {
			continue
		}
		gen, ok := decl.Decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, s := range gen.Specs {
			spec, ok := s.(*ast.TypeSpec)
			if !ok {
				continue
			}
			structType, ok := spec.Type.(*ast.StructType)
			if !ok {
				continue
			}
			if countJSONTaggedFields(structType) == 0 {
				continue
			}
			found[spec.Name.Name] = spec
		}
	}

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
