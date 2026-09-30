package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewFinancialDecimalFloatRule())
}

// FinancialDecimalFloatRule detects discarded exactness from financial decimal
// conversions. With type information a float that serves only comparisons
// inside the function - a price against a threshold, amounts against a
// tolerance - is not reported: the approximation never becomes an amount.
type FinancialDecimalFloatRule struct {
	*rules.BaseRule
}

// NewFinancialDecimalFloatRule creates the rule.
func NewFinancialDecimalFloatRule() *FinancialDecimalFloatRule {
	return &FinancialDecimalFloatRule{BaseRule: rules.NewBaseRule(
		"financial-decimal-float",
		"patterns",
		"Detects ignored exact results from decimal.Decimal.Float64 in financial conversions whose float is used as an amount, not only compared",
		core.SeverityHigh,
	)}
}

// AnalyzeFile checks two-result Float64 assignments on shopspring decimal
// values, judging the receiver by what the file itself declares.
func (r *FinancialDecimalFloatRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *FinancialDecimalFloatRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; with type information the receiver's
// type decides whether Float64 is decimal.Decimal's.
func (r *FinancialDecimalFloatRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze reports `x, _ := d.Float64()` on a decimal named as money. info is
// nil for a file without type information: then a receiver is a decimal only
// when the file declares it as one, and anything else is unknown and not
// reported.
func (r *FinancialDecimalFloatRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	decimalAliases := helpers.PackageAliases(ctx.GoAST, `"`+shopspringDecimalPath+`"`, "decimal")
	if len(decimalAliases) == 0 {
		return nil
	}
	var decimalFields decimalFieldEvidence
	if info == nil {
		decimalFields = collectDecimalFieldEvidence(ctx.GoAST, decimalAliases)
	}
	for _, declaration := range ctx.GoAST.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		var inferred *TypeInferrer
		if info == nil {
			inferred = NewTypeInferrerFromNode(function)
		}
		isDecimal := func(expr ast.Expr, position token.Pos) bool {
			if info != nil {
				return isShopspringDecimalType(info.TypeOf(expr))
			}
			return isShopspringDecimalReceiver(expr, position, function, inferred, decimalAliases, decimalFields)
		}
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
			if !isDecimal(selector.X, assignment.Pos()) {
				return true
			}
			if !hasFinancialValueName(assignment.Lhs[0]) && !hasFinancialValueName(selector.X) {
				return true
			}
			if info != nil && floatOnlyCompared(function, info, assignment.Lhs[0]) {
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

// floatOnlyCompared reports whether the float a conversion stored in target
// serves only yes-or-no judgements inside the function: every value computed
// from it - through arithmetic, math functions and local variables or maps -
// ends in a comparison. Comparing a price with a threshold or amounts with a
// tolerance needs no exact value; the approximation never becomes an amount
// anyone stores or pays. Any other use - a return, a field, a call argument -
// lets the float out.
func floatOnlyCompared(function *ast.FuncDecl, info *types.Info, target ast.Expr) bool {
	ident, ok := target.(*ast.Ident)
	if !ok {
		return false
	}
	start := info.ObjectOf(ident)
	if start == nil || !declaredInBody(function, start) {
		return false
	}
	tracked := map[types.Object]bool{start: true}
	queue := []types.Object{start}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		derived, escapes := floatUses(function, info, current)
		if escapes {
			return false
		}
		for _, obj := range derived {
			if !tracked[obj] {
				tracked[obj] = true
				queue = append(queue, obj)
			}
		}
	}
	return true
}

// declaredInBody reports whether the object is a local of the function body,
// not a parameter or a named result.
func declaredInBody(function *ast.FuncDecl, obj types.Object) bool {
	return obj.Pos() > function.Body.Lbrace && obj.Pos() < function.Body.Rbrace
}

// floatUses classifies the reads of obj: the locals that receive a value
// computed from it, and whether any read lets the value out of the function.
func floatUses(function *ast.FuncDecl, info *types.Info, obj types.Object) (derived []types.Object, escapes bool) {
	var stack []ast.Node
	ast.Inspect(function.Body, func(n ast.Node) bool {
		if escapes {
			return false
		}
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if ident, ok := n.(*ast.Ident); ok && info.Uses[ident] == obj {
			local, leaves := floatUseTarget(function, info, ident, stack)
			if leaves {
				escapes = true
				return false
			}
			if local != nil {
				derived = append(derived, local)
			}
		}
		stack = append(stack, n)
		return true
	})
	return derived, escapes
}

// floatUseTarget climbs from one read of a float through the expressions that
// carry its value on. It ends in a comparison (nil, false), in a local that
// receives the value (local, false), or anywhere else (nil, true).
func floatUseTarget(function *ast.FuncDecl, info *types.Info, use ast.Expr, stack []ast.Node) (types.Object, bool) {
	current := ast.Node(use)
	for i := len(stack) - 1; i >= 0; i-- {
		switch parent := stack[i].(type) {
		case *ast.ParenExpr:
		case *ast.UnaryExpr:
			if parent.Op == token.AND {
				return nil, true // its address can be kept anywhere
			}
		case *ast.BinaryExpr:
			switch parent.Op {
			case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
				return nil, false
			case token.ADD, token.SUB, token.MUL, token.QUO:
			default:
				return nil, true
			}
		case *ast.IndexExpr:
			if current != parent.X {
				return nil, false // used as a key
			}
		case *ast.CallExpr:
			if builtin, ok := typeutil.Callee(info, parent).(*types.Builtin); ok && (builtin.Name() == "len" || builtin.Name() == "cap") {
				return nil, false // a count of the entries, not an amount
			}
			if !keepsFloatJudgement(info, parent) {
				return nil, true
			}
		case *ast.AssignStmt:
			return floatAssignTarget(function, info, parent, current)
		case *ast.RangeStmt:
			if current != parent.X {
				return nil, true
			}
			value, ok := parent.Value.(*ast.Ident)
			if !ok {
				return nil, false
			}
			return info.ObjectOf(value), false
		case *ast.IncDecStmt:
			return nil, false
		default:
			return nil, true
		}
		current = stack[i]
	}
	return nil, true
}

// keepsFloatJudgement reports the calls a float may pass through on its way
// to a comparison: the math package and the min and max built-ins.
func keepsFloatJudgement(info *types.Info, call *ast.CallExpr) bool {
	switch callee := typeutil.Callee(info, call).(type) {
	case *types.Builtin:
		return callee.Name() == "min" || callee.Name() == "max"
	case *types.Func:
		return callee.Pkg() != nil && callee.Pkg().Path() == "math"
	}
	return false
}

// floatAssignTarget follows a float value into an assignment: a local
// variable or an element of a local map or slice receives it and is followed
// in turn; anything else keeps it beyond the function.
func floatAssignTarget(function *ast.FuncDecl, info *types.Info, assign *ast.AssignStmt, value ast.Node) (types.Object, bool) {
	for _, lhs := range assign.Lhs {
		if lhs == value {
			return nil, false // the variable is written, not read
		}
	}
	index := -1
	for i, rhs := range assign.Rhs {
		if rhs == value {
			index = i
		}
	}
	switch {
	case index >= 0 && len(assign.Lhs) == len(assign.Rhs):
	case index == 0 && len(assign.Rhs) == 1:
		index = 0 // v, ok := m[k]
	default:
		return nil, true
	}
	target := ast.Unparen(assign.Lhs[index])
	if indexed, ok := target.(*ast.IndexExpr); ok {
		target = ast.Unparen(indexed.X)
	}
	ident, ok := target.(*ast.Ident)
	if !ok {
		return nil, true
	}
	if ident.Name == "_" {
		return nil, false
	}
	obj := info.ObjectOf(ident)
	if obj == nil || !declaredInBody(function, obj) {
		return nil, true
	}
	return obj, false
}

func isBlankIdentifier(expr ast.Expr) bool {
	identifier, ok := expr.(*ast.Ident)
	return ok && identifier.Name == "_"
}

func isShopspringDecimalReceiver(
	expr ast.Expr,
	position token.Pos,
	function *ast.FuncDecl,
	inferred *TypeInferrer,
	aliases map[string]bool,
	decimalFields decimalFieldEvidence,
) bool {
	if identifier, ok := expr.(*ast.Ident); ok {
		if typeName, scoped := rangeValueTypeAt(function, identifier.Name, position, inferred); scoped {
			return isShopspringDecimalTypeName(typeName, aliases)
		}
	}
	if selector, ok := expr.(*ast.SelectorExpr); ok && decimalFields.matchesSelector(selector, inferred) {
		return true
	}
	typeName := inferred.analyzeExpr(expr).TypeName
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

func (evidence decimalFieldEvidence) matchesSelector(selector *ast.SelectorExpr, inferred *TypeInferrer) bool {
	if !evidence.unambiguous[selector.Sel.Name] {
		return false
	}
	typeName := inferred.analyzeExpr(selector.X).TypeName
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

func rangeValueTypeAt(function *ast.FuncDecl, name string, position token.Pos, inferred *TypeInferrer) (string, bool) {
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
	return inferred.analyzeExpr(innermost.X).ElementTypeName, true
}

// hasFinancialValueName reports whether an identifier of the expression names
// money. The value is already a decimal, so money flow words (total, payout,
// payment, ...) count alongside the value and market words.
func hasFinancialValueName(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		if financialValueName(identifier.Name) || hasTokenIn(identifier.Name, moneyFlowTokens) {
			found = true
			return false
		}
		return true
	})
	return found
}
