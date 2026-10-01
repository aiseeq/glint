package patterns

import (
	"go/ast"
	"maps"
	"reflect"
	"slices"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFinancialJSONFloatRule())
}

// FinancialJSONFloatRule detects precision-losing floats in monetary JSON
// contracts: a float field of a monetary DTO, and a decimal type's
// UnmarshalJSON that decodes a JSON number into a float before building the
// decimal from it:
//
//	var f float64
//	if err := json.Unmarshal(data, &f); err == nil {
//		a.Decimal = decimal.NewFromFloat(f)   // 12345678901234567.891 arrives as 12345678901234568
//	}
type FinancialJSONFloatRule struct {
	*rules.BaseRule
}

// NewFinancialJSONFloatRule creates the rule.
func NewFinancialJSONFloatRule() *FinancialJSONFloatRule {
	return &FinancialJSONFloatRule{BaseRule: rules.NewBaseRule(
		"financial-json-float",
		"patterns",
		"Detects float32/float64 monetary fields in Go JSON contracts, and a decimal UnmarshalJSON that decodes the number through a float",
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
	for _, typeName := range slices.Sorted(maps.Keys(types)) {
		expr := types[typeName]
		if structType := resolveStructType(expr, types); structType != nil {
			allowDefaultJSON := explicitJSONContractName(typeName) || structHasJSONTag(structType)
			violations = append(violations, r.inspectJSONStruct(ctx, structType, false, financialContextName(typeName), allowDefaultJSON, types, map[string]bool{typeName: true}, reported)...)
		}
	}
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil || fn.Name.Name != "UnmarshalJSON" {
			continue
		}
		if call := decimalDecodedThroughFloat(fn.Body); call != nil {
			line := ctx.GoFileSet.Position(call.Pos()).Line
			v := r.CreateViolation(ctx.RelPath, line, "UnmarshalJSON decodes the JSON number into a float before building the decimal — a long amount loses its last digits")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Decode into json.Number or a string and parse it with decimal.NewFromString, or delegate to the decimal type's own UnmarshalJSON")
			v.WithContext("pattern", "decimal_unmarshal_via_float")
			violations = append(violations, v)
		}
	}
	return violations
}

// decimalDecodedThroughFloat returns the json.Unmarshal call of the body that
// fills a float variable later handed to NewFromFloat, nil when there is none.
func decimalDecodedThroughFloat(body *ast.BlockStmt) *ast.CallExpr {
	floats := make(map[string]bool)
	converted := make(map[string]bool)
	var decodes []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			if id, ok := node.Type.(*ast.Ident); ok && (id.Name == "float64" || id.Name == "float32") {
				for _, name := range node.Names {
					floats[name.Name] = true
				}
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Unmarshal":
				if len(node.Args) == 2 {
					decodes = append(decodes, node)
				}
			case "NewFromFloat", "NewFromFloat32":
				if len(node.Args) == 1 {
					if id, ok := node.Args[0].(*ast.Ident); ok {
						converted[id.Name] = true
					}
				}
			}
		}
		return true
	})
	for _, call := range decodes {
		addr, ok := call.Args[1].(*ast.UnaryExpr)
		if !ok {
			continue
		}
		if id, ok := addr.X.(*ast.Ident); ok && floats[id.Name] && converted[id.Name] {
			return call
		}
	}
	return nil
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
		if !financial && contextualMarketFinancialName(fieldName) {
			financial = typeFinancial
		}
		if !financial && weakFinancialName(fieldName) {
			financial = typeFinancial || financialContextName(exprTypeName(field.Type))
		}
		if financial && containsFloatType(field.Type, types, map[string]bool{}) && !reported[int(field.Pos())] {
			reported[int(field.Pos())] = true
			line := ctx.GoFileSet.Position(field.Pos()).Line
			v := r.CreateViolation(ctx.RelPath, line, "monetary JSON field '"+jsonName+"' uses float32/float64 and can lose precision")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Decode monetary JSON values into decimal.Decimal, a decimal wrapper type, an integer smallest-unit type, or an exact numeric string")
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
			violations = append(violations, r.inspectJSONStruct(ctx, nested, inheritedFinancial || financialContainerName(fieldName), typeFinancial || financialContextName(typeName), true, types, nextSeen, reported)...)
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
	return resolveStructTypeSeen(expr, types, make(map[string]bool))
}

func resolveStructTypeSeen(expr ast.Expr, types map[string]ast.Expr, seen map[string]bool) *ast.StructType {
	switch node := expr.(type) {
	case *ast.StarExpr:
		return resolveStructTypeSeen(node.X, types, seen)
	case *ast.ArrayType:
		return resolveStructTypeSeen(node.Elt, types, seen)
	case *ast.MapType:
		return resolveStructTypeSeen(node.Value, types, seen)
	case *ast.Ident:
		if seen[node.Name] {
			return nil
		}
		seen[node.Name] = true
		return resolveStructTypeSeen(types[node.Name], types, seen)
	case *ast.StructType:
		return node
	default:
		return nil
	}
}

func exprTypeName(expr ast.Expr) string {
	switch node := expr.(type) {
	case *ast.StarExpr:
		return exprTypeName(node.X)
	case *ast.ArrayType:
		return exprTypeName(node.Elt)
	case *ast.MapType:
		return exprTypeName(node.Value)
	case *ast.Ident:
		return node.Name
	default:
		return ""
	}
}

// strongFinancialName reports whether a name alone says the value is money: a
// money value or market figure word, or an exchange/FX rate.
func strongFinancialName(name string) bool {
	return compoundMarketFinancialName(name) || hasTokenIn(name, moneyValueTokens, moneyMarketTokens)
}

func compoundMarketFinancialName(name string) bool {
	for _, identifier := range strings.Fields(name) {
		tokens := identifierTokens(identifier)
		if len(tokens) == 2 && tokens[0] == "exchange" && (tokens[1] == "rate" || tokens[1] == "rates") {
			return true
		}
		if len(tokens) == 2 && tokens[0] == "fx" && (tokens[1] == "rate" || tokens[1] == "rates") {
			return true
		}
	}
	return false
}

func contextualMarketFinancialName(name string) bool {
	for _, identifier := range strings.Fields(name) {
		tokens := identifierTokens(identifier)
		if len(tokens) != 1 {
			continue
		}
		switch tokens[0] {
		case "mid", "rate", "rates", "fx":
			return true
		}
	}
	return false
}

func financialValueName(name string) bool {
	return strongFinancialName(name) || contextualMarketFinancialName(name)
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
		case "asset", "assets", "fee", "fees", "fx", "market", "mid", "money", "payment", "payments", "portfolio", "quote", "rate", "rates", "token", "tokens", "transaction", "transactions", "transfer", "transfers", "wallet":
			return true
		}
	}
	return strongFinancialName(name)
}

func identifierTokens(name string) []string {
	runes := []rune(name)
	var tokens []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			tokens = append(tokens, strings.ToLower(string(current)))
			current = nil
		}
	}
	for index, char := range runes {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
			flush()
			continue
		}
		if len(current) > 0 && unicode.IsUpper(char) {
			previous := runes[index-1]
			nextIsLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
			if unicode.IsLower(previous) || unicode.IsDigit(previous) || unicode.IsUpper(previous) && nextIsLower {
				flush()
			}
		}
		current = append(current, char)
	}
	flush()
	return tokens
}
