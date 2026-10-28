package patterns

import (
	"go/ast"
	"go/types"
	"sort"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

const excelizePath = "github.com/xuri/excelize/v2"

func init() {
	rules.Register(NewSpreadsheetRawDoubleParsedAsExactDecimalRule())
}

// NewSpreadsheetRawDoubleParsedAsExactDecimalRule detects risky flows from raw spreadsheet reads.
func NewSpreadsheetRawDoubleParsedAsExactDecimalRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"spreadsheet-raw-double-parsed-as-exact-decimal",
			"patterns",
			"Detects raw spreadsheet values that reach exact decimal parsing without type checks or 15 digit normalization",
			core.SeverityMedium,
		),
		suggestion: "Check GetCellType for numeric cells and round with strconv.FormatFloat(..., 'G', 15, 64) before exact decimal parsing",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		decimalPackages := make(map[*types.Package]bool)
		directDecimal := make(map[*types.Func]bool)
		directNormalizers := make(map[*types.Func]bool)
		// A package that rounds numbers to 15 significant digits somewhere
		// normalizes its amounts on the parse path: the raw read and the
		// rounding often sit in different functions of a streaming reader.
		roundingPackages := make(map[*types.Package]bool)
		roundingFuncs := make(map[*types.Func]bool)
		gridPackages := make(map[*types.Package]bool)
		functions := make(map[*types.Func]typedFuncDecl)
		for obj, decl := range decls {
			if decl.decl == nil || decl.decl.Body == nil || obj.Pkg() == nil {
				continue
			}
			functions[obj.Origin()] = decl
			if declaresSpreadsheetGrid(decl.info, decl.decl) {
				gridPackages[obj.Pkg()] = true
			}
			if hasExactDecimalParse(decl.info, decl.decl.Body) {
				decimalPackages[obj.Pkg()] = true
				directDecimal[obj.Origin()] = true
			}
			if hasSpreadsheetNormalization(decl.info, decl.decl.Body) {
				directNormalizers[obj.Origin()] = true
			}
			if hasSpreadsheetPrecisionFormat(decl.info, decl.decl.Body) {
				roundingPackages[obj.Pkg()] = true
				roundingFuncs[obj.Origin()] = true
			}
		}
		// A shared rounding helper of another package rounds for its callers.
		for obj, decl := range decls {
			if decl.decl == nil || decl.decl.Body == nil || obj.Pkg() == nil {
				continue
			}
			info := decl.info
			if callsAny(decl.decl.Body, func(call *ast.CallExpr) bool {
				fn := staticFunc(info, call)
				return fn != nil && roundingFuncs[fn.Origin()]
			}) {
				roundingPackages[obj.Pkg()] = true
			}
		}
		decimalConsumers := make(map[*types.Func]bool)
		for obj, decl := range decls {
			if decl.decl == nil || decl.decl.Body == nil || obj.Pkg() == nil {
				continue
			}
			origin := obj.Origin()
			if directDecimal[origin] {
				decimalConsumers[origin] = true
				continue
			}
			if callsSamePackage(decl, directDecimal) {
				decimalConsumers[origin] = true
			}
		}

		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			if fn.Body == nil {
				return nil
			}
			current, _ := scope.info.Defs[fn.Name].(*types.Func)
			if current == nil || current.Pkg() == nil {
				return nil
			}
			decl := typedFuncDecl{decl: fn, info: scope.info}
			var findings []funcFinding
			if decimalPackages[current.Pkg()] && !roundingPackages[current.Pkg()] {
				if !reachesNormalizer(decl, directNormalizers, functions, 2, map[*types.Func]bool{}) {
					findings = spreadsheetRiskFindings(decl, decimalConsumers)
				}
			}
			if gridPackages[current.Pkg()] && !roundingPackages[current.Pkg()] {
				findings = append(findings, spreadsheetGridDoubleFindings(decl)...)
			}
			return findings
		}
	}
	return r
}

func declaresSpreadsheetGrid(info *types.Info, fn *ast.FuncDecl) bool {
	obj, _ := info.Defs[fn.Name].(*types.Func)
	if obj != nil {
		if sig, ok := obj.Type().(*types.Signature); ok && signatureReturnsSpreadsheetGrid(sig) {
			return true
		}
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok {
			if signatureReturnsSpreadsheetGrid(info.TypeOf(call)) || signatureReturnsSpreadsheetGrid(info.TypeOf(call.Fun)) {
				found = true
				return false
			}
			if callee := staticFunc(info, call); callee != nil && signatureReturnsSpreadsheetGrid(callee.Type()) {
				found = true
				return false
			}
		}
		return !found
	})
	return found
}

func signatureReturnsSpreadsheetGrid(typ types.Type) bool {
	if tuple, ok := typ.(*types.Tuple); ok {
		for v := range tuple.Variables() {
			if isAnyGridType(v.Type(), 2) || isAnyGridType(v.Type(), 3) {
				return true
			}
		}
		return false
	}
	sig, ok := typ.(*types.Signature)
	if !ok || sig.Results() == nil {
		return false
	}
	for v := range sig.Results().Variables() {
		if isAnyGridType(v.Type(), 2) || isAnyGridType(v.Type(), 3) {
			return true
		}
	}
	return false
}

func isAnyGridType(typ types.Type, dimensions int) bool {
	for range dimensions {
		slice, ok := typ.Underlying().(*types.Slice)
		if !ok {
			return false
		}
		typ = slice.Elem()
	}
	if slice, ok := typ.Underlying().(*types.Slice); ok { // dimensions are exact
		_ = slice
		return false
	}
	if basic, ok := typ.Underlying().(*types.Interface); ok && basic.Empty() {
		return true
	}
	return false
}

func spreadsheetGridDoubleFindings(decl typedFuncDecl) []funcFinding {
	info, body := decl.info, decl.decl.Body
	asserted := spreadsheetAnyFloatAssertions(info, body)
	if len(asserted) == 0 {
		return nil
	}
	calls, targets, rounded := spreadsheetFloatConstructors(info, body, asserted)
	var findings []funcFinding
	for _, call := range calls {
		if isConstructorRounded(body, call) || rounded[targets[call]] {
			continue
		}
		findings = append(findings, funcFinding{node: call, message: "NewFromFloat preserves the binary double returned for formula cells; use strconv.FormatFloat(x, 'g', 15, 64) with NewFromString, or round to the column precision"})
	}
	return findings
}

func spreadsheetAnyFloatAssertions(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	asserted := make(map[types.Object]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				assertion, ok := ast.Unparen(rhs).(*ast.TypeAssertExpr)
				if !ok || !isFloat64Type(typeExprType(info, assertion.Type)) || !isAnyType(info.TypeOf(assertion.X)) || i >= len(node.Lhs) {
					continue
				}
				if id, ok := ast.Unparen(node.Lhs[i]).(*ast.Ident); ok {
					asserted[info.Defs[id]] = true
					asserted[info.Uses[id]] = true
				}
			}
		case *ast.ValueSpec:
			for i, rhs := range node.Values {
				assertion, ok := ast.Unparen(rhs).(*ast.TypeAssertExpr)
				if !ok || !isFloat64Type(typeExprType(info, assertion.Type)) || !isAnyType(info.TypeOf(assertion.X)) || i >= len(node.Names) {
					continue
				}
				asserted[info.Defs[node.Names[i]]] = true
			}
		case *ast.TypeSwitchStmt:
			if node.Assign == nil {
				break
			}
			as, ok := node.Assign.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 {
				break
			}
			id, ok := as.Lhs[0].(*ast.Ident)
			if !ok {
				break
			}
			for _, stmt := range node.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range clause.List {
					if isFloat64Type(typeExprType(info, expr)) {
						if obj := info.Implicits[clause]; obj != nil {
							asserted[obj] = true
						}
						asserted[info.Defs[id]] = true
						asserted[info.Uses[id]] = true
					}
				}
			}
		}
		return true
	})
	return asserted
}

func spreadsheetFloatConstructors(info *types.Info, body *ast.BlockStmt, asserted map[types.Object]bool) ([]*ast.CallExpr, map[*ast.CallExpr]types.Object, map[types.Object]bool) {
	targets := make(map[*ast.CallExpr]types.Object)
	rounded := make(map[types.Object]bool)
	var calls []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isDecimalNewFromFloat(info, call) && len(call.Args) == 1 {
			if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); ok && asserted[info.Uses[id]] {
				calls = append(calls, call)
			}
		}
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && isDecimalRoundingMethod(sel.Sel.Name) {
			if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
				rounded[info.Uses[id]] = true
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if call, ok := ast.Unparen(rhs).(*ast.CallExpr); ok && isDecimalNewFromFloat(info, call) && i < len(node.Lhs) {
					if id, ok := node.Lhs[i].(*ast.Ident); ok {
						targets[call] = info.Defs[id]
						if targets[call] == nil {
							targets[call] = info.Uses[id]
						}
					}
				}
			}
		case *ast.ValueSpec:
			for i, rhs := range node.Values {
				if call, ok := ast.Unparen(rhs).(*ast.CallExpr); ok && isDecimalNewFromFloat(info, call) && i < len(node.Names) {
					targets[call] = info.Defs[node.Names[i]]
				}
			}
		}
		return true
	})
	return calls, targets, rounded
}

func isFloat64Type(typ types.Type) bool {
	if typ == nil {
		return false
	}
	b, ok := typ.Underlying().(*types.Basic)
	return ok && b.Kind() == types.Float64
}
func typeExprType(info *types.Info, expr ast.Expr) types.Type {
	if typ := info.TypeOf(expr); typ != nil {
		return typ
	}
	if id, ok := expr.(*ast.Ident); ok {
		if obj, ok := info.Uses[id].(*types.TypeName); ok {
			return obj.Type()
		}
	}
	return nil
}
func isAnyType(typ types.Type) bool {
	if typ == nil {
		return false
	}
	i, ok := typ.Underlying().(*types.Interface)
	return ok && i.Empty()
}
func isDecimalNewFromFloat(info *types.Info, call *ast.CallExpr) bool {
	fn := staticFunc(info, call)
	return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == shopspringDecimalPath && fn.Name() == "NewFromFloat"
}
func isDecimalRoundingMethod(name string) bool {
	switch name {
	case "Round", "RoundBank", "RoundCeil", "RoundFloor", "Truncate", "StringFixed":
		return true
	}
	return false
}
func isConstructorRounded(body *ast.BlockStmt, constructor *ast.CallExpr) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.X == constructor && isDecimalRoundingMethod(sel.Sel.Name) {
			found = true
			return false
		}
		return !found
	})
	return found
}
func spreadsheetRiskFindings(decl typedFuncDecl, decimalConsumers map[*types.Func]bool) []funcFinding {
	fn := decl.decl
	info := decl.info
	roots := make(map[*ast.CallExpr]bool)
	tainted := make(map[types.Object]map[*ast.CallExpr]bool)
	addTaint := func(obj types.Object, values map[*ast.CallExpr]bool) bool {
		if obj == nil || len(values) == 0 {
			return false
		}
		if tainted[obj] == nil {
			tainted[obj] = make(map[*ast.CallExpr]bool)
		}
		changed := false
		for root := range values {
			if !tainted[obj][root] {
				tainted[obj][root] = true
				changed = true
			}
		}
		return changed
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					var rhs ast.Expr
					if len(node.Rhs) == len(node.Lhs) {
						rhs = node.Rhs[i]
					} else if len(node.Rhs) == 1 && i == 0 {
						rhs = node.Rhs[0]
					}
					if rhs == nil {
						continue
					}
					values := spreadsheetExprRoots(info, rhs, tainted)
					if raw, ok := ast.Unparen(rhs).(*ast.CallExpr); ok && isExplicitRawSpreadsheetRead(info, raw) {
						roots[raw] = true
						values[raw] = true
					}
					if addTaint(spreadsheetLHSObject(info, lhs), values) {
						changed = true
					}
				}
			case *ast.ValueSpec:
				for i, lhs := range node.Names {
					if i >= len(node.Values) {
						continue
					}
					values := spreadsheetExprRoots(info, node.Values[i], tainted)
					if raw, ok := ast.Unparen(node.Values[i]).(*ast.CallExpr); ok && isExplicitRawSpreadsheetRead(info, raw) {
						roots[raw] = true
						values[raw] = true
					}
					if addTaint(info.Defs[lhs], values) {
						changed = true
					}
				}
			}
			return true
		})
	}

	used := spreadsheetRiskRoots(decl, tainted, decimalConsumers)
	var findings []funcFinding
	for root := range used {
		findings = append(findings, funcFinding{
			node:    root,
			message: "Raw spreadsheet numeric values may contain binary double noise (for example 74074.07000000001); check GetCellType and round to 15 significant digits before exact decimal parsing",
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].node.Pos() < findings[j].node.Pos()
	})
	return findings
}

func spreadsheetRiskRoots(decl typedFuncDecl, tainted map[types.Object]map[*ast.CallExpr]bool, decimalConsumers map[*types.Func]bool) map[*ast.CallExpr]bool {
	used := make(map[*ast.CallExpr]bool)
	info := decl.info
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if isExactDecimalStringParse(info, node) {
				for _, arg := range node.Args {
					for root := range spreadsheetExprRoots(info, arg, tainted) {
						used[root] = true
					}
				}
			} else if isDecimalConsumerCall(info, decl.decl, node, decimalConsumers) {
				for _, arg := range node.Args {
					for root := range spreadsheetExprRoots(info, arg, tainted) {
						used[root] = true
					}
				}
			}
		case *ast.ReturnStmt:
			for _, result := range node.Results {
				if isStringSlice(info.TypeOf(result)) {
					for root := range spreadsheetExprRoots(info, result, tainted) {
						used[root] = true
					}
				}
			}
		}
		return true
	})
	return used
}

func isDecimalConsumerCall(info *types.Info, fn *ast.FuncDecl, call *ast.CallExpr, decimalConsumers map[*types.Func]bool) bool {
	callee := staticFunc(info, call)
	return callee != nil && callee.Pkg() == objectPackage(info, fn) && decimalConsumers[callee.Origin()]
}

func spreadsheetExprRoots(info *types.Info, expr ast.Expr, tainted map[types.Object]map[*ast.CallExpr]bool) map[*ast.CallExpr]bool {
	result := make(map[*ast.CallExpr]bool)
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			obj := info.Uses[node]
			for root := range tainted[obj] {
				result[root] = true
			}
		case *ast.CallExpr:
			if isExplicitRawSpreadsheetRead(info, node) {
				result[node] = true
			}
		}
		return true
	})
	return result
}

func spreadsheetLHSObject(info *types.Info, lhs ast.Expr) types.Object {
	switch node := ast.Unparen(lhs).(type) {
	case *ast.Ident:
		if obj := info.Defs[node]; obj != nil {
			return obj
		}
		return info.Uses[node]
	case *ast.IndexExpr:
		return spreadsheetLHSObject(info, node.X)
	case *ast.SelectorExpr:
		return spreadsheetLHSObject(info, node.X)
	}
	return nil
}

func isStringSlice(typ types.Type) bool {
	slice, ok := typ.Underlying().(*types.Slice)
	if !ok {
		return false
	}
	if basic, ok := slice.Elem().Underlying().(*types.Basic); ok {
		return basic.Kind() == types.String
	}
	inner, ok := slice.Elem().Underlying().(*types.Slice)
	if !ok {
		return false
	}
	basic, ok := inner.Elem().Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

func objectPackage(info *types.Info, fn *ast.FuncDecl) *types.Package {
	if fn == nil || fn.Name == nil {
		return nil
	}
	obj, _ := info.Defs[fn.Name].(*types.Func)
	if obj == nil {
		return nil
	}
	return obj.Pkg()
}

func hasExactDecimalParse(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && isExactDecimalStringParse(info, call) {
			found = true
			return false
		}
		return !found
	})
	return found
}

func isExactDecimalStringParse(info *types.Info, call *ast.CallExpr) bool {
	fn := staticFunc(info, call)
	return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == shopspringDecimalPath &&
		(fn.Name() == "NewFromString" || fn.Name() == "RequireFromString")
}

func hasSpreadsheetNormalization(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && (isSpreadsheetCellTypeCall(info, call) || isSpreadsheetPrecisionFormat(info, call)) {
			found = true
			return false
		}
		return !found
	})
	return found
}

func hasSpreadsheetPrecisionFormat(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isSpreadsheetPrecisionFormat(info, call) {
			found = true
		}
		return !found
	})
	return found
}

func reachesNormalizer(decl typedFuncDecl, direct map[*types.Func]bool, functions map[*types.Func]typedFuncDecl, depth int, seen map[*types.Func]bool) bool {
	obj, _ := decl.info.Defs[decl.decl.Name].(*types.Func)
	if obj == nil || seen[obj.Origin()] {
		return false
	}
	seen[obj.Origin()] = true
	if direct[obj.Origin()] {
		return true
	}
	if depth == 0 {
		return false
	}
	found := false
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := staticFunc(decl.info, call)
		if callee == nil || callee.Pkg() != obj.Pkg() {
			return true
		}
		if direct[callee.Origin()] {
			found = true
			return false
		}
		if next, ok := functions[callee.Origin()]; ok && reachesNormalizer(next, direct, functions, depth-1, seen) {
			found = true
			return false
		}
		return true
	})
	return found
}

func callsSamePackage(decl typedFuncDecl, targets map[*types.Func]bool) bool {
	current, _ := decl.info.Defs[decl.decl.Name].(*types.Func)
	if current == nil {
		return false
	}
	found := false
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := staticFunc(decl.info, call)
		if callee != nil && callee.Pkg() == current.Pkg() && targets[callee.Origin()] {
			found = true
			return false
		}
		return true
	})
	return found
}

func isSpreadsheetCellTypeCall(info *types.Info, call *ast.CallExpr) bool {
	fn := staticFunc(info, call)
	return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == excelizePath && fn.Name() == "GetCellType"
}

func isSpreadsheetPrecisionFormat(info *types.Info, call *ast.CallExpr) bool {
	if !isPkgFunc(info, call, "strconv", "FormatFloat") || len(call.Args) < 3 {
		return false
	}
	format, formatOK := constantInt(info, call.Args[1])
	precision, precisionOK := constantInt(info, call.Args[2])
	return formatOK && (format == 'G' || format == 'g') && precisionOK && precision == 15
}

func isExplicitRawSpreadsheetRead(info *types.Info, call *ast.CallExpr) bool {
	fn := staticFunc(info, call)
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != excelizePath {
		return false
	}
	switch fn.Name() {
	case "GetRows", "GetCols", "GetCellValue", "Columns":
		return hasRawCellValueTrue(info, call)
	default:
		return false
	}
}

func hasRawCellValueTrue(info *types.Info, call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		lit, ok := ast.Unparen(arg).(*ast.CompositeLit)
		if !ok {
			continue
		}
		typ, ok := ast.Unparen(lit.Type).(*ast.SelectorExpr)
		if !ok || typ.Sel.Name != "Options" {
			continue
		}
		pkg, ok := typ.X.(*ast.Ident)
		if !ok {
			continue
		}
		pkgName, ok := info.Uses[pkg].(*types.PkgName)
		if !ok || pkgName.Imported().Path() != excelizePath {
			continue
		}
		for _, element := range lit.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := field.Key.(*ast.Ident)
			value, valueOK := ast.Unparen(field.Value).(*ast.Ident)
			if ok && key.Name == "RawCellValue" && valueOK && value.Name == "true" {
				return true
			}
		}
	}
	return false
}
