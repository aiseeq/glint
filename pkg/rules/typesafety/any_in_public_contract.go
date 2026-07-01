package typesafety

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewAnyInPublicContractRule())
}

// defaultExcludedMethods are well-known contracts whose signatures are fixed
// by the standard library or a framework.
const defaultExcludedMethods = "Scan,Value,MarshalJSON,UnmarshalJSON,MarshalYAML,UnmarshalYAML,Configure"

// AnyInPublicContractRule detects untyped `any` in exported API contracts:
//
//	func (s *AdminService) BulkApprove(...) (any, error)   // caller gets a mystery
//	Metadata map[string]any                                 // in an exported request struct
//
// Public contracts must be typed: `any` erases the schema, breaks generated
// TS types, and pushes type assertions onto every caller.
//
// Not flagged: unexported symbols, comma-ok lookups (any, bool), stdlib-fixed
// signatures (Scan, MarshalJSON, ...), parameters (variadic logger-style
// ...any is idiomatic).
type AnyInPublicContractRule struct {
	*rules.BaseRule
	excludedMethods map[string]bool
}

// NewAnyInPublicContractRule creates the rule
func NewAnyInPublicContractRule() *AnyInPublicContractRule {
	r := &AnyInPublicContractRule{
		BaseRule: rules.NewBaseRule(
			"any-in-public-contract",
			"typesafety",
			"Detects bare any/interface{} in exported function results and struct fields",
			core.SeverityMedium,
		),
	}
	r.setExcludedMethods(defaultExcludedMethods)
	return r
}

// Configure reads the optional excluded_methods setting (comma-separated).
func (r *AnyInPublicContractRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.setExcludedMethods(r.GetStringSetting("excluded_methods", defaultExcludedMethods))
	return nil
}

func (r *AnyInPublicContractRule) setExcludedMethods(csv string) {
	r.excludedMethods = make(map[string]bool)
	for _, name := range strings.Split(csv, ",") {
		r.excludedMethods[strings.TrimSpace(name)] = true
	}
}

// AnalyzeFile checks exported contracts for untyped any
func (r *AnyInPublicContractRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			violations = append(violations, r.checkFuncSignature(ctx, node.Name, node.Type)...)
		case *ast.TypeSpec:
			if !node.Name.IsExported() {
				return true
			}
			switch typ := node.Type.(type) {
			case *ast.StructType:
				violations = append(violations, r.checkStructFields(ctx, typ)...)
			case *ast.InterfaceType:
				violations = append(violations, r.checkInterfaceMethods(ctx, typ)...)
			}
		}
		return true
	})

	return violations
}

// checkFuncSignature reports exported functions/methods whose results contain
// bare any (excluding comma-ok lookups and stdlib-fixed names).
func (r *AnyInPublicContractRule) checkFuncSignature(
	ctx *core.FileContext, name *ast.Ident, fnType *ast.FuncType,
) []*core.Violation {
	if name == nil || !name.IsExported() || r.excludedMethods[name.Name] {
		return nil
	}
	results := fnType.Results
	if results == nil || isCommaOkLookup(results) {
		return nil
	}

	var violations []*core.Violation
	for _, field := range results.List {
		if !typeContainsAny(field.Type) {
			continue
		}
		pos := ctx.PositionFor(field.Type)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Exported "+name.Name+" returns untyped any — callers get a contract-less value")
		v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
		v.WithSuggestion("Return a typed struct (works with generated TS types) instead of any")
		violations = append(violations, v)
	}
	return violations
}

// checkStructFields reports exported fields typed as map with any values.
func (r *AnyInPublicContractRule) checkStructFields(
	ctx *core.FileContext, structType *ast.StructType,
) []*core.Violation {
	var violations []*core.Violation
	for _, field := range structType.Fields.List {
		exported := false
		fieldName := ""
		for _, name := range field.Names {
			if name.IsExported() {
				exported = true
				fieldName = name.Name
			}
		}
		if !exported || !isMapWithAnyValue(field.Type) {
			continue
		}
		pos := ctx.PositionFor(field.Type)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Exported field "+fieldName+" is map[string]any — schema-less payload in a public contract")
		v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
		v.WithSuggestion("Define a typed struct for the payload; keep map[string]any only for genuinely external data (configurable via excluded file exceptions)")
		v.Severity = core.SeverityLow
		violations = append(violations, v)
	}
	return violations
}

// checkInterfaceMethods reports interface methods whose results contain any.
func (r *AnyInPublicContractRule) checkInterfaceMethods(
	ctx *core.FileContext, ifaceType *ast.InterfaceType,
) []*core.Violation {
	var violations []*core.Violation
	for _, method := range ifaceType.Methods.List {
		fnType, ok := method.Type.(*ast.FuncType)
		if !ok || len(method.Names) == 0 {
			continue
		}
		violations = append(violations, r.checkFuncSignature(ctx, method.Names[0], fnType)...)
	}
	return violations
}

// isCommaOkLookup matches the (any, bool) lookup contract.
func isCommaOkLookup(results *ast.FieldList) bool {
	if len(results.List) != 2 {
		return false
	}
	last, ok := results.List[1].Type.(*ast.Ident)
	return ok && last.Name == "bool" && typeContainsAny(results.List[0].Type)
}

// typeContainsAny reports whether the type expression is bare any /
// interface{} or a map of them. Slices ([]any) are deliberately excluded:
// they are the database/sql variadic-args idiom, a much weaker signal.
func typeContainsAny(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == "any"
	case *ast.InterfaceType:
		return len(t.Methods.List) == 0
	case *ast.MapType:
		return typeContainsAny(t.Value)
	}
	return false
}

// isMapWithAnyValue matches map[K]any / map[K]interface{}.
func isMapWithAnyValue(expr ast.Expr) bool {
	mapType, ok := expr.(*ast.MapType)
	return ok && typeContainsAny(mapType.Value)
}
