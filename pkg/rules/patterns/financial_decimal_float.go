package patterns

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFinancialDecimalFloatRule())
}

// FinancialDecimalFloatRule detects discarded exactness from financial decimal conversions.
type FinancialDecimalFloatRule struct {
	*rules.BaseRule
}

// NewFinancialDecimalFloatRule creates the rule.
func NewFinancialDecimalFloatRule() *FinancialDecimalFloatRule {
	return &FinancialDecimalFloatRule{BaseRule: rules.NewBaseRule(
		"financial-decimal-float",
		"patterns",
		"Detects ignored exact results from decimal.Decimal.Float64 in financial conversions",
		core.SeverityHigh,
	)}
}

// AnalyzeFile checks two-result Float64 assignments on shopspring decimal values.
func (r *FinancialDecimalFloatRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	decimalAliases := importedPackageAliases(ctx.GoAST, `"github.com/shopspring/decimal"`, "decimal")
	if len(decimalAliases) == 0 {
		return nil
	}
	decimalFields := collectDecimalFieldEvidence(ctx.GoAST, decimalAliases)
	for _, declaration := range ctx.GoAST.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		types := NewTypeInferrerFromNode(function)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 || !isBlankIdentifier(assignment.Lhs[1]) {
				return true
			}

			call, ok := assignment.Rhs[0].(*ast.CallExpr)
			if !ok || len(call.Args) != 0 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Float64" {
				return true
			}
			if !isShopspringDecimalReceiver(selector.X, assignment.Pos(), function, types, decimalAliases, decimalFields) {
				return true
			}
			if !hasFinancialValueName(assignment.Lhs[0]) && !hasFinancialValueName(selector.X) {
				return true
			}

			line := ctx.GoFileSet.Position(assignment.Pos()).Line
			v := r.CreateViolation(ctx.RelPath, line, "financial decimal Float64 conversion ignores whether the result is exact")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Capture and handle the exact bool returned by decimal.Decimal.Float64, or keep the value as decimal.Decimal")
			v.WithContext("pattern", "financial_decimal_float")
			violations = append(violations, v)
			return true
		})
	}
	return violations
}

func isBlankIdentifier(expr ast.Expr) bool {
	identifier, ok := expr.(*ast.Ident)
	return ok && identifier.Name == "_"
}

func importedPackageAliases(file *ast.File, path, defaultName string) map[string]bool {
	aliases := make(map[string]bool)
	for _, spec := range file.Imports {
		if spec.Path == nil || spec.Path.Value != path {
			continue
		}
		name := defaultName
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != "_" && name != "." {
			aliases[name] = true
		}
	}
	return aliases
}

func isShopspringDecimalReceiver(
	expr ast.Expr,
	position token.Pos,
	function *ast.FuncDecl,
	types *TypeInferrer,
	aliases map[string]bool,
	decimalFields decimalFieldEvidence,
) bool {
	if identifier, ok := expr.(*ast.Ident); ok {
		if typeName, scoped := rangeValueTypeAt(function, identifier.Name, position, types); scoped {
			return isShopspringDecimalTypeName(typeName, aliases)
		}
	}
	if selector, ok := expr.(*ast.SelectorExpr); ok && decimalFields.matchesSelector(selector, types) {
		return true
	}
	typeName := types.analyzeExpr(expr).TypeName
	return isShopspringDecimalTypeName(typeName, aliases)
}

func isShopspringDecimalTypeName(typeName string, aliases map[string]bool) bool {
	for len(typeName) > 0 && typeName[0] == '*' {
		typeName = typeName[1:]
	}
	for alias := range aliases {
		if typeName == alias+".Decimal" {
			return true
		}
	}
	return false
}

type decimalFieldEvidence struct {
	unambiguous map[string]bool
	byStruct    map[string]map[string]bool
}

func collectDecimalFieldEvidence(file *ast.File, aliases map[string]bool) decimalFieldEvidence {
	evidence := decimalFieldEvidence{
		unambiguous: make(map[string]bool),
		byStruct:    make(map[string]map[string]bool),
	}
	seen := make(map[string]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		structType, ok := node.(*ast.StructType)
		if !ok || structType.Fields == nil {
			return true
		}
		for _, field := range structType.Fields.List {
			isDecimal := isShopspringDecimalTypeExpr(field.Type, aliases)
			for _, name := range field.Names {
				if !seen[name.Name] {
					evidence.unambiguous[name.Name] = isDecimal
					seen[name.Name] = true
					continue
				}
				evidence.unambiguous[name.Name] = evidence.unambiguous[name.Name] && isDecimal
			}
		}
		return true
	})
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range generic.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok || structType.Fields == nil {
				continue
			}
			fields := make(map[string]bool)
			for _, field := range structType.Fields.List {
				for _, name := range field.Names {
					fields[name.Name] = isShopspringDecimalTypeExpr(field.Type, aliases)
				}
			}
			evidence.byStruct[typeSpec.Name.Name] = fields
		}
	}
	return evidence
}

func (evidence decimalFieldEvidence) matchesSelector(selector *ast.SelectorExpr, types *TypeInferrer) bool {
	if !evidence.unambiguous[selector.Sel.Name] {
		return false
	}
	typeName := types.analyzeExpr(selector.X).TypeName
	for len(typeName) > 0 && typeName[0] == '*' {
		typeName = typeName[1:]
	}
	return evidence.byStruct[typeName][selector.Sel.Name]
}

func isShopspringDecimalTypeExpr(expr ast.Expr, aliases map[string]bool) bool {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return isShopspringDecimalTypeExpr(node.X, aliases)
	case *ast.StarExpr:
		return isShopspringDecimalTypeExpr(node.X, aliases)
	case *ast.SelectorExpr:
		identifier, ok := node.X.(*ast.Ident)
		return ok && aliases[identifier.Name] && node.Sel.Name == "Decimal"
	default:
		return false
	}
}

func rangeValueTypeAt(function *ast.FuncDecl, name string, position token.Pos, types *TypeInferrer) (string, bool) {
	var innermost *ast.RangeStmt
	ast.Inspect(function.Body, func(node ast.Node) bool {
		rangeStmt, ok := node.(*ast.RangeStmt)
		if !ok || position < rangeStmt.Body.Pos() || position > rangeStmt.Body.End() {
			return true
		}
		value, ok := rangeStmt.Value.(*ast.Ident)
		if ok && value.Name == name && (innermost == nil || rangeStmt.Pos() > innermost.Pos()) {
			innermost = rangeStmt
		}
		return true
	})
	if innermost == nil {
		return "", false
	}
	return types.analyzeExpr(innermost.X).ElementTypeName, true
}

func hasFinancialValueName(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		if financialValueName(identifier.Name) {
			found = true
			return false
		}
		return true
	})
	return found
}
