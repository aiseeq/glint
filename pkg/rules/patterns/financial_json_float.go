package patterns

import (
	"go/ast"
	"reflect"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFinancialJSONFloatRule())
}

// FinancialJSONFloatRule detects precision-losing floats in monetary JSON contracts.
type FinancialJSONFloatRule struct {
	*rules.BaseRule
}

// NewFinancialJSONFloatRule creates the rule.
func NewFinancialJSONFloatRule() *FinancialJSONFloatRule {
	return &FinancialJSONFloatRule{BaseRule: rules.NewBaseRule(
		"financial-json-float",
		"patterns",
		"Detects float32/float64 monetary fields in Go JSON contracts",
		core.SeverityHigh,
	)}
}

// AnalyzeFile checks JSON DTO structs while preserving financial context through anonymous fields.
func (r *FinancialJSONFloatRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	var violations []*core.Violation
	types := make(map[string]ast.Expr)
	ast.Inspect(ctx.GoAST, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if ok {
			types[typeSpec.Name.Name] = typeSpec.Type
		}
		return true
	})
	reported := make(map[tokenPos]bool)
	for typeName, expr := range types {
		if structType := resolveStructType(expr, types); structType != nil {
			allowDefaultJSON := explicitJSONContractName(typeName) || structHasJSONTag(structType)
			violations = append(violations, r.inspectJSONStruct(ctx, structType, false, financialContextName(typeName), allowDefaultJSON, types, map[string]bool{typeName: true}, reported)...)
		}
	}
	return violations
}

type tokenPos = int

func (r *FinancialJSONFloatRule) inspectJSONStruct(ctx *core.FileContext, structType *ast.StructType, inheritedFinancial, typeFinancial, allowDefaultJSON bool, types map[string]ast.Expr, seen map[string]bool, reported map[tokenPos]bool) []*core.Violation {
	var violations []*core.Violation
	for _, field := range structType.Fields.List {
		jsonName, serialized := jsonFieldName(field, allowDefaultJSON)
		if !serialized || jsonName == "-" {
			continue
		}
		fieldName := jsonName
		if len(field.Names) > 0 {
			fieldName += " " + field.Names[0].Name
		}
		financial := inheritedFinancial || strongFinancialName(fieldName)
		if !financial && weakFinancialName(fieldName) {
			financial = typeFinancial || financialContextName(exprTypeName(field.Type))
		}
		if financial && containsFloatType(field.Type, types, map[string]bool{}) && !reported[int(field.Pos())] {
			reported[int(field.Pos())] = true
			line := ctx.GoFileSet.Position(field.Pos()).Line
			v := r.CreateViolation(ctx.RelPath, line, "monetary JSON field '"+jsonName+"' uses float32/float64 and can lose precision")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Decode monetary JSON values into decimal.Decimal, SafeDecimal, an integer smallest-unit type, or an exact numeric string")
			v.WithContext("pattern", "financial_json_float")
			violations = append(violations, v)
		}
		typeName := exprTypeName(field.Type)
		if nested := resolveStructType(field.Type, types); nested != nil && !seen[typeName] {
			nextSeen := make(map[string]bool, len(seen)+1)
			for name := range seen {
				nextSeen[name] = true
			}
			if typeName != "" {
				nextSeen[typeName] = true
			}
			violations = append(violations, r.inspectJSONStruct(ctx, nested, inheritedFinancial || financialContainerName(fieldName), financialContextName(typeName), true, types, nextSeen, reported)...)
		}
	}
	return violations
}

func jsonFieldName(field *ast.Field, allowDefault bool) (string, bool) {
	if field.Tag == nil {
		if !allowDefault || len(field.Names) == 0 || !field.Names[0].IsExported() {
			return "", false
		}
		return field.Names[0].Name, true
	}
	tag := strings.Trim(field.Tag.Value, "`")
	jsonTag, ok := reflect.StructTag(tag).Lookup("json")
	if !ok {
		return "", false
	}
	return strings.Split(jsonTag, ",")[0], true
}

func structHasJSONTag(structType *ast.StructType) bool {
	for _, field := range structType.Fields.List {
		if field.Tag != nil {
			tag := strings.Trim(field.Tag.Value, "`")
			if _, ok := reflect.StructTag(tag).Lookup("json"); ok {
				return true
			}
		}
	}
	return false
}

func explicitJSONContractName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, "dto") || strings.HasSuffix(lower, "payload") || strings.HasSuffix(lower, "request") || strings.HasSuffix(lower, "response")
}

func containsFloatType(expr ast.Expr, types map[string]ast.Expr, seen map[string]bool) bool {
	switch node := expr.(type) {
	case *ast.Ident:
		if node.Name == "float32" || node.Name == "float64" {
			return true
		}
		if seen[node.Name] {
			return false
		}
		seen[node.Name] = true
		return types[node.Name] != nil && containsFloatType(types[node.Name], types, seen)
	case *ast.ArrayType:
		return containsFloatType(node.Elt, types, seen)
	case *ast.MapType:
		return containsFloatType(node.Value, types, seen)
	case *ast.StarExpr:
		return containsFloatType(node.X, types, seen)
	default:
		return false
	}
}

func resolveStructType(expr ast.Expr, types map[string]ast.Expr) *ast.StructType {
	if pointer, ok := expr.(*ast.StarExpr); ok {
		expr = pointer.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		expr = types[ident.Name]
	}
	structType, _ := expr.(*ast.StructType)
	return structType
}

func exprTypeName(expr ast.Expr) string {
	if pointer, ok := expr.(*ast.StarExpr); ok {
		expr = pointer.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

func strongFinancialName(name string) bool {
	financialTokens := map[string]bool{
		"amount": true, "amounts": true, "balance": true, "balances": true,
		"cost": true, "costs": true, "fee": true, "fees": true,
		"price": true, "prices": true, "profit": true, "profits": true,
		"revenue": true, "revenues": true,
		"tvl": true, "usd": true,
		"valuation": true, "valuations": true,
		"yield": true, "yields": true,
	}
	for _, token := range identifierTokens(name) {
		if financialTokens[token] {
			return true
		}
	}
	return false
}

func weakFinancialName(name string) bool {
	for _, token := range identifierTokens(name) {
		if token == "value" || token == "values" || token == "quantity" || token == "quantities" {
			return true
		}
	}
	return false
}

func financialContainerName(name string) bool {
	return strongFinancialName(name) && !strings.Contains(strings.ToLower(name), "yield")
}

func financialContextName(name string) bool {
	for _, token := range identifierTokens(name) {
		switch token {
		case "asset", "assets", "fee", "fees", "market", "money", "payment", "payments", "portfolio", "token", "tokens", "transaction", "transactions", "transfer", "transfers", "wallet":
			return true
		}
	}
	return strongFinancialName(name)
}

func identifierTokens(name string) []string {
	var tokens []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			tokens = append(tokens, strings.ToLower(string(current)))
			current = nil
		}
	}
	var previous rune
	for _, char := range name {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
			flush()
			previous = 0
			continue
		}
		if len(current) > 0 && unicode.IsUpper(char) && unicode.IsLower(previous) {
			flush()
		}
		current = append(current, char)
		previous = char
	}
	flush()
	return tokens
}
