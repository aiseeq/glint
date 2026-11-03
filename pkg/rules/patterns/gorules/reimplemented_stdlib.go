package gorules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewReimplementedStdlibRule())
}

// ReimplementedStdlibRule detects small helpers that redo what the standard
// library already does:
//
//	func itoa(i int) string {          // strconv.Itoa
//	    s := ""
//	    for i > 0 { s = string(rune('0'+i%10)) + s; i /= 10 }
//	    return s
//	}
//
// The copy is not merely redundant: it is the version nobody tested. glint
// carried four such itoa helpers, and they all shared the same bug — a negative
// number came back as the empty string.
//
// The rule recognizes the shapes it can name with certainty: digit-by-digit
// integer formatting and parsing, a linear search for an element, absolute
// value, the smaller/larger of two values, and reversing a slice in place.
type ReimplementedStdlibRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewReimplementedStdlibRule creates the rule
func NewReimplementedStdlibRule() *ReimplementedStdlibRule {
	return &ReimplementedStdlibRule{
		BaseRule: rules.NewBaseRule(
			"reimplemented-stdlib",
			"patterns",
			"Detects hand-written helpers that duplicate the standard library — the copy is the version nobody tested",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *ReimplementedStdlibRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ReimplementedStdlibRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; the collections and result types the
// shapes depend on are resolved wherever the project declares them.
func (r *ReimplementedStdlibRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	versions := helpers.NewGoVersions(ctx)
	return rules.AnalyzeGoRunFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, versions)
	})
}

// analyze checks every function declared in the file. info is nil for a file
// without type information; versions is nil outside a project analysis.
func (r *ReimplementedStdlibRule) analyze(ctx *core.FileContext, info *types.Info, versions *helpers.GoVersions) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	operands := stdlibOperands{info: info, file: ctx.GoAST}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		replacement, ok := stdlibEquivalent(fn, operands)
		caveat := ""
		mapsKeys := versions != nil && versions.AtLeast(ctx, info, "go1.23")
		if !ok && mapsKeys && sortsMapKeys(fn, info) {
			if sortedReplacement, hasReplacement := sortedMapKeysReplacement(fn); hasReplacement {
				replacement, ok = sortedReplacement, true
				caveat = nilForEmptyMapCaveat
			}
		}
		if !ok {
			if mapsKeys {
				violations = append(violations, r.sortedKeyBlocks(ctx, fn, info)...)
			}
			continue
		}

		line := ctx.LineFor(fn)
		v := r.CreateViolation(ctx.RelPath, line,
			fmt.Sprintf("%s does by hand what %s already does — the hand-written copy is the one without tests behind it",
				fn.Name.Name, replacement))
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		if wrapsOwnData(fn) {
			v.WithSuggestion(fmt.Sprintf("Replace the body of %s with a call to %s over its own list%s", fn.Name.Name, replacement, caveat))
		} else {
			v.WithSuggestion(fmt.Sprintf("Delete %s and call %s at every one of its call sites, in every file of the package%s", fn.Name.Name, replacement, caveat))
		}
		v.WithColumn(ctx.PositionFor(fn).Column)
		v.WithContext("pattern", "reimplemented_stdlib")
		v.WithContext("replacement", replacement)
		if collection, target, ok := exactContainsSearch(ctx, fn, info, versions); ok && replacement == "slices.Contains" {
			// The fixer may replace the body with slices.Contains(collection, target).
			v.WithContext("fix_collection", collection)
			v.WithContext("fix_target", target)
		}
		violations = append(violations, v)
	}

	return violations
}

const nilForEmptyMapCaveat = "; for an empty map it returns nil, not an empty slice, so keep a non-nil result where a caller encodes it to JSON or compares it with nil"

// sortedKeyBlocks reports the three statements that collect every key of a
// map and sort them - an empty keys slice, a range appending each key, an
// ascending sort - standing in a row in any block of fn.
func (r *ReimplementedStdlibRule) sortedKeyBlocks(ctx *core.FileContext, fn *ast.FuncDecl, info *types.Info) []*core.Violation {
	if info == nil {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		var list []ast.Stmt
		switch block := n.(type) {
		case *ast.BlockStmt:
			list = block.List
		case *ast.CaseClause:
			list = block.Body
		case *ast.CommClause:
			list = block.Body
		}
		for i := 0; i+2 < len(list); i++ {
			loop, ok := list[i+1].(*ast.RangeStmt)
			if !ok {
				continue
			}
			keys := appendedSlice(loop)
			if keys == nil || !sortedKeyBlock(list[i], loop, list[i+2], keys, info) {
				continue
			}
			replacement := "slices.Sorted(maps.Keys(" + types.ExprString(loop.X) + "))"
			line := ctx.LineFor(list[i])
			v := r.CreateViolation(ctx.RelPath, line,
				fmt.Sprintf("%s collects and sorts the keys of %s by hand — %s already does it, and the hand-written copy is the one without tests behind it",
					keys.Name, types.ExprString(loop.X), replacement))
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion(fmt.Sprintf("Replace the three statements with %s := %s%s", keys.Name, replacement, nilForEmptyMapCaveat))
			v.WithColumn(ctx.PositionFor(list[i]).Column)
			v.WithContext("pattern", "reimplemented_stdlib")
			v.WithContext("replacement", replacement)
			// The fixer may replace the three statements with keys := replacement:
			// the map operand must print as its source and read the same once,
			// maps and slices must name the packages an added import brings, and
			// the sort's own import must not be renamed: the fixer drops "sort"
			// once nothing refers to it, a renamed import would stay behind.
			if isSortedKeysOperand(loop.X, keys.Name) && namesStdlibPackages(ctx.GoAST, list[i].Pos(), info, "maps", "slices") &&
				packagesCalledByPath(list[i+2], info) && nilAsGood(fn, list[i], list[i+2], keys, info) {
				v.WithContext("fix_sorted_keys", keys.Name)
			}
			violations = append(violations, v)
		}
		return true
	})
	return violations
}

// isSortedKeysOperand reports a map expression the replacement can name once
// for the block's two reads of it: a plain operand, or one indexed by a plain
// operand or a literal, so nothing in it runs or changes between the reads,
// and none of it the keys slice the rewrite declares.
func isSortedKeysOperand(expr ast.Expr, keys string) bool {
	switch node := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return node.Name != keys
	case *ast.SelectorExpr:
		return isSortedKeysOperand(node.X, keys)
	case *ast.IndexExpr:
		_, literal := ast.Unparen(node.Index).(*ast.BasicLit)
		return isSortedKeysOperand(node.X, keys) && (literal || isSortedKeysOperand(node.Index, keys))
	}
	return false
}

// nilAsGood reports keys that are read after the sort and read the same nil
// as empty: declared nil by var keys []T, or after the sort only ranged over,
// measured with len, indexed and joined by strings.Join. slices.Sorted of an
// empty map returns nil; a subslice of nil is nil again and carries the
// difference out. Unread keys would leave keys := replacement unused, which
// does not compile.
func nilAsGood(fn *ast.FuncDecl, start, sort ast.Stmt, keys *ast.Ident, info *types.Info) bool {
	obj := info.ObjectOf(keys)
	assigned := make(map[*ast.Ident]bool)
	readsAsList := make(map[*ast.Ident]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
					assigned[id] = true
				}
			}
		case *ast.RangeStmt:
			if id, ok := node.X.(*ast.Ident); ok {
				readsAsList[id] = true
			}
			if node.Tok == token.ASSIGN {
				for _, target := range []ast.Expr{node.Key, node.Value} {
					if id, ok := ast.Unparen(target).(*ast.Ident); ok {
						assigned[id] = true
					}
				}
			}
		case *ast.IndexExpr:
			if id, ok := node.X.(*ast.Ident); ok {
				readsAsList[id] = true
			}
		case *ast.CallExpr:
			if isLenCall(node, info) || isStringsJoin(node, info) {
				if arg, ok := node.Args[0].(*ast.Ident); ok {
					readsAsList[arg] = true
				}
			}
		}
		return true
	})
	_, declaredNil := start.(*ast.DeclStmt)
	read, good := false, true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || id.Pos() <= sort.End() || info.Uses[id] != obj || assigned[id] {
			return true
		}
		read = true
		if !declaredNil && !readsAsList[id] {
			good = false
		}
		return good
	})
	return read && good
}

// isLenCall reports a call of the builtin len.
func isLenCall(call *ast.CallExpr, info *types.Info) bool {
	id, ok := call.Fun.(*ast.Ident)
	return ok && isBuiltin(id, "len", info) && len(call.Args) == 1
}

// isStringsJoin reports strings.Join(elems, sep) of the standard library:
// it joins nil as it joins an empty slice, to "".
func isStringsJoin(call *ast.CallExpr, info *types.Info) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Join" && importedPackage(sel.X, info) == "strings" && len(call.Args) == 2
}

// isBuiltin reports id naming the predeclared function name, not a local
// one that shadows it.
func isBuiltin(id *ast.Ident, name string, info *types.Info) bool {
	_, ok := info.Uses[id].(*types.Builtin)
	return ok && id.Name == name
}

// packagesCalledByPath reports a statement whose every package name is the
// last element of its import path.
func packagesCalledByPath(stmt ast.Stmt, info *types.Info) bool {
	plain := true
	ast.Inspect(stmt, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if path := importedPackage(id, info); path != "" && path[strings.LastIndex(path, "/")+1:] != id.Name {
				plain = false
			}
		}
		return plain
	})
	return plain
}

// appendedSlice returns the slice a range loop appends to in its only
// statement: keys in `for k := range m { keys = append(keys, k) }`.
func appendedSlice(loop *ast.RangeStmt) *ast.Ident {
	if len(loop.Body.List) != 1 {
		return nil
	}
	assign, ok := loop.Body.List[0].(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 {
		return nil
	}
	keys, _ := assign.Lhs[0].(*ast.Ident)
	return keys
}

// sortedKeyBlock reports start, loop and sort as an empty keys slice of the
// map's key type, a loop appending every key to it and its ascending sort.
func sortedKeyBlock(start ast.Stmt, loop *ast.RangeStmt, sort ast.Stmt, keys *ast.Ident, info *types.Info) bool {
	if !initializedKeySlice(start, keys.Name, loop.X, info) || !mapKeyAppendLoop(loop, info, keys.Name) {
		return false
	}
	mapType, ok := info.TypeOf(loop.X).Underlying().(*types.Map)
	if !ok || !sliceContainsType(info.TypeOf(keys), mapType.Key()) {
		return false
	}
	sortStmt, ok := sort.(*ast.ExprStmt)
	return ok && isSortCall(sortStmt.X, keys.Name, mapType.Key(), info)
}

// sortsMapKeys recognizes a function that collects every key from one map,
// sorts the resulting slice in ascending order, and returns it.
func sortsMapKeys(fn *ast.FuncDecl, info *types.Info) bool {
	// Exactly declare, collect, sort and return: any other statement may change the keys.
	if info == nil || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 || len(fn.Body.List) != 4 {
		return false
	}
	keysName, ok := returnedSlice(fn)
	if !ok {
		return false
	}
	loop, ok := fn.Body.List[1].(*ast.RangeStmt)
	if !ok || !mapKeyAppendLoop(loop, info, keysName) || !startsKeySlice(fn, keysName, loop.X, info) {
		return false
	}
	returnStmt, ok := fn.Body.List[3].(*ast.ReturnStmt)
	if !ok || len(returnStmt.Results) != 1 {
		return false
	}
	targetType := info.TypeOf(loop.X)
	if targetType == nil {
		return false
	}
	mapType, ok := targetType.Underlying().(*types.Map)
	if !ok || !isOrderedKey(mapType.Key()) || !sliceContainsType(info.TypeOf(returnStmt.Results[0]), mapType.Key()) {
		return false
	}
	sortStmt, ok := fn.Body.List[2].(*ast.ExprStmt)
	return ok && isSortCall(sortStmt.X, keysName, mapType.Key(), info)
}

func returnedSlice(fn *ast.FuncDecl) (string, bool) {
	result, ok := fn.Type.Results.List[0].Type.(*ast.ArrayType)
	if !ok || result.Len != nil {
		return "", false
	}
	last, ok := fn.Body.List[len(fn.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(last.Results) != 1 {
		return "", false
	}
	name, ok := last.Results[0].(*ast.Ident)
	if !ok {
		return "", false
	}
	return name.Name, true
}

// mapKeyAppendLoop recognizes `for k := range m { keys = append(keys, k) }`
// over a map whose key type is ordered.
func mapKeyAppendLoop(loop *ast.RangeStmt, info *types.Info, keys string) bool {
	if loop.Tok != token.DEFINE || (loop.Value != nil && !sameIdent(loop.Value, "_")) || len(loop.Body.List) != 1 {
		return false
	}
	key, keyOK := loop.Key.(*ast.Ident)
	targetType := info.TypeOf(loop.X)
	if !keyOK || targetType == nil {
		return false
	}
	mapType, mapOK := targetType.Underlying().(*types.Map)
	if !mapOK || !isOrderedKey(mapType.Key()) {
		return false
	}
	assign, ok := loop.Body.List[0].(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || !sameIdent(assign.Lhs[0], keys) {
		return false
	}
	appendCall, ok := assign.Rhs[0].(*ast.CallExpr)
	return ok && isBuiltinAppend(appendCall, info) && len(appendCall.Args) == 2 && sameIdent(appendCall.Args[0], keys) && sameIdent(appendCall.Args[1], key.Name)
}

func isOrderedKey(t types.Type) bool {
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&(types.IsInteger|types.IsFloat|types.IsString) != 0
}

func sliceContainsType(slice, elem types.Type) bool {
	if slice == nil || elem == nil {
		return false
	}
	t, ok := slice.Underlying().(*types.Slice)
	return ok && types.Identical(t.Elem(), elem)
}

func sortedMapKeysReplacement(fn *ast.FuncDecl) (string, bool) {
	if fn == nil || fn.Body == nil || len(fn.Body.List) < 2 {
		return "", false
	}
	loop, ok := fn.Body.List[1].(*ast.RangeStmt)
	if !ok || loop.X == nil {
		return "", false
	}
	return "slices.Sorted(maps.Keys(" + types.ExprString(loop.X) + "))", true
}

// namesResult reports a function whose single result is named name.
func namesResult(fn *ast.FuncDecl, name string) bool {
	for _, ident := range fn.Type.Results.List[0].Names {
		if ident.Name == name {
			return true
		}
	}
	return false
}

// startsKeySlice recognizes the first statement of fn as the start of an empty
// keys slice: a declaration, or `keys = nil` when keys is the named result.
func startsKeySlice(fn *ast.FuncDecl, keys string, mapExpr ast.Expr, info *types.Info) bool {
	stmt := fn.Body.List[0]
	if assign, ok := stmt.(*ast.AssignStmt); ok && assign.Tok == token.ASSIGN {
		return namesResult(fn, keys) && len(assign.Lhs) == 1 && len(assign.Rhs) == 1 && sameIdent(assign.Lhs[0], keys) && isPredeclaredNil(assign.Rhs[0], info)
	}
	return initializedKeySlice(stmt, keys, mapExpr, info)
}

// isPredeclaredNil reports the predeclared nil, not a package variable named so.
func isPredeclaredNil(expr ast.Expr, info *types.Info) bool {
	id, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	_, ok = info.Uses[id].(*types.Nil)
	return ok
}

// initializedKeySlice recognizes a statement declaring an empty keys slice:
// `var keys []T`, `keys := []T{}` or `keys := make([]T, 0[, len(m)])`.
func initializedKeySlice(stmt ast.Stmt, keys string, mapExpr ast.Expr, info *types.Info) bool {
	emptySliceOf := func(expr ast.Expr) bool {
		slice, ok := expr.(*ast.ArrayType)
		return ok && slice.Len == nil
	}
	if decl, ok := stmt.(*ast.DeclStmt); ok {
		gen, ok := decl.Decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR || len(gen.Specs) != 1 {
			return false
		}
		value, ok := gen.Specs[0].(*ast.ValueSpec)
		return ok && len(value.Names) == 1 && value.Names[0].Name == keys && emptySliceOf(value.Type) && len(value.Values) == 0
	}
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || !sameIdent(assign.Lhs[0], keys) || len(assign.Rhs) != 1 {
		return false
	}
	if literal, ok := assign.Rhs[0].(*ast.CompositeLit); ok {
		return emptySliceOf(literal.Type) && len(literal.Elts) == 0
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok || !sameIdent(call.Fun, "make") || len(call.Args) < 1 || !emptySliceOf(call.Args[0]) {
		return false
	}
	switch len(call.Args) {
	case 1:
		return true
	case 2:
		return patternkit.IsIntLiteral(call.Args[1], 0)
	case 3:
		return patternkit.IsIntLiteral(call.Args[1], 0) && isLenOf(call.Args[2], mapExpr, info)
	}
	return false
}

// isLenOf reports the builtin len(target), with target written the same way
// (m, s.items).
func isLenOf(expr, target ast.Expr, info *types.Info) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || types.ExprString(call.Args[0]) != types.ExprString(target) {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && isBuiltin(id, "len", info)
}

func isBuiltinAppend(call *ast.CallExpr, info *types.Info) bool {
	id, ok := call.Fun.(*ast.Ident)
	return ok && isBuiltin(id, "append", info)
}

// isSortCall recognizes an ascending sort of keys by package sort or slices,
// resolved by import path: a local sort value or a package imported under
// that name sorts as it likes.
func isSortCall(expr ast.Expr, keys string, elem types.Type, info *types.Info) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg := importedPackage(selector.X, info)
	if selector.Sel.Name != "Sort" || pkg != "sort" {
		if !sameIdent(call.Args[0], keys) {
			return false
		}
	}
	switch {
	case selector.Sel.Name == "Strings" && pkg == "sort" && basicKind(elem) == types.String:
		return true
	case selector.Sel.Name == "Ints" && pkg == "sort" && basicKind(elem) == types.Int:
		return true
	case selector.Sel.Name == "Sort" && pkg == "slices":
		return true
	case selector.Sel.Name == "Slice" && pkg == "sort" && len(call.Args) == 2 && !isFloatType(elem):
		// By < a NaN key compares with nothing and lands anywhere; slices.Sorted puts it first.
		return ascendingSortSlice(call.Args[1], keys)
	case selector.Sel.Name == "Sort" && pkg == "sort" && len(call.Args) == 1:
		wrapped, ok := call.Args[0].(*ast.CallExpr)
		if !ok || len(wrapped.Args) != 1 || basicKind(elem) != types.String {
			return false
		}
		wrappedSelector, ok := wrapped.Fun.(*ast.SelectorExpr)
		if !ok || wrappedSelector.Sel.Name != "StringSlice" {
			return false
		}
		return importedPackage(wrappedSelector.X, info) == "sort" && sameIdent(wrapped.Args[0], keys)
	}
	return false
}

// importedPackage returns the import path of the package expr names, empty
// when expr names no package.
func importedPackage(expr ast.Expr, info *types.Info) string {
	id, ok := expr.(*ast.Ident)
	if !ok {
		return ""
	}
	pkg, ok := info.Uses[id].(*types.PkgName)
	if !ok {
		return ""
	}
	return pkg.Imported().Path()
}

func basicKind(t types.Type) types.BasicKind {
	basic, ok := t.Underlying().(*types.Basic)
	if !ok {
		return types.Invalid
	}
	return basic.Kind()
}

func ascendingSortSlice(expr ast.Expr, keys string) bool {
	lit, ok := expr.(*ast.FuncLit)
	if !ok || lit.Type.Params == nil || len(lit.Body.List) != 1 {
		return false
	}
	var indices []string
	for _, field := range lit.Type.Params.List {
		for _, name := range field.Names {
			indices = append(indices, name.Name)
		}
	}
	if len(indices) != 2 {
		return false
	}
	ret, ok := lit.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	cmp, ok := ret.Results[0].(*ast.BinaryExpr)
	if !ok || cmp.Op != token.LSS {
		return false
	}
	left, lok := cmp.X.(*ast.IndexExpr)
	right, rok := cmp.Y.(*ast.IndexExpr)
	if !lok || !rok || !sameIdent(left.X, keys) || !sameIdent(right.X, keys) {
		return false
	}
	return sameIdent(left.Index, indices[0]) && sameIdent(right.Index, indices[1])
}

func sameIdent(expr ast.Expr, name string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == name
}

// wrapsOwnData reports whether the helper searches a collection of its own
// rather than one handed to it: then the function is a named question about the
// package's data, and only its body should change.
func wrapsOwnData(fn *ast.FuncDecl) bool {
	params := make(map[string]bool)
	if fn.Type.Params != nil {
		for _, param := range fn.Type.Params.List {
			for _, name := range param.Names {
				params[name.Name] = true
			}
		}
	}

	ownData := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		rangeStmt, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		if ident, ok := rangeStmt.X.(*ast.Ident); !ok || !params[ident.Name] {
			ownData = true
		}
		return false
	})
	return ownData
}

// stdlibOperands answers the type questions some shapes depend on. With type
// information the checker answers, wherever the type is declared. Without it
// only what the file itself declares is known, and an unknown type is not a
// slice: a map or a string declared in another file looked like one.
type stdlibOperands struct {
	info *types.Info
	file *ast.File
}

// rangesOverSlice reports whether target, ranged over in fn, is a slice or an
// array - the collections slices.Contains can search.
func (o stdlibOperands) rangesOverSlice(fn *ast.FuncDecl, target ast.Expr) bool {
	if o.info != nil {
		t := o.info.TypeOf(target)
		if t == nil {
			return false
		}
		switch u := t.Underlying().(type) {
		case *types.Slice, *types.Array:
			return true
		case *types.Pointer:
			_, isArray := u.Elem().Underlying().(*types.Array)
			return isArray
		}
		return false
	}

	ident, ok := target.(*ast.Ident)
	if !ok {
		return false
	}
	for _, fields := range []*ast.FieldList{fn.Recv, fn.Type.Params} {
		if fields == nil {
			continue
		}
		for _, field := range fields.List {
			for _, name := range field.Names {
				if name.Name == ident.Name {
					return o.declaresSliceType(field.Type)
				}
			}
		}
	}
	for _, decl := range o.file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valueSpec.Names {
				if name.Name != ident.Name {
					continue
				}
				if valueSpec.Type != nil {
					return o.declaresSliceType(valueSpec.Type)
				}
				if i < len(valueSpec.Values) {
					lit, ok := valueSpec.Values[i].(*ast.CompositeLit)
					return ok && o.declaresSliceType(lit.Type)
				}
				return false
			}
		}
	}
	return false
}

// declaresSliceType reports whether a type expression is a slice or array
// type, spelled out or named by a type this file declares.
func (o stdlibOperands) declaresSliceType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.ArrayType:
		return true
	case *ast.Ident:
		for _, decl := range o.file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if ok && typeSpec.Name.Name == t.Name {
					_, isArray := typeSpec.Type.(*ast.ArrayType)
					return isArray
				}
			}
		}
	}
	return false
}

// returnsFloat reports whether fn returns a single floating-point value.
func (o stdlibOperands) returnsFloat(fn *ast.FuncDecl) bool {
	if o.info == nil {
		return returnsBasicType(fn, "float64") || returnsBasicType(fn, "float32")
	}
	obj, ok := o.info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	results := obj.Signature().Results()
	if results.Len() != 1 {
		return false
	}
	basic, ok := results.At(0).Type().Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsFloat != 0
}

// stdlibEquivalent names the standard-library call a function duplicates.
func stdlibEquivalent(fn *ast.FuncDecl, operands stdlibOperands) (string, bool) {
	switch {
	case formatsDigitByDigit(fn):
		return "strconv.Itoa", true
	case parsesDigitByDigit(fn):
		return "strconv.Atoi", true
	case searchesLinearly(fn, operands):
		return "slices.Contains", true
	case negatesWhenNegative(fn):
		// Go has no built-in abs: math.Abs covers floats, integer copies
		// should collapse into one shared helper.
		if operands.returnsFloat(fn) {
			return "math.Abs", true
		}
		return "a single shared abs helper (Go has no integer abs)", true
	case returnsSmallerOrLarger(fn):
		return "the built-in min/max", true
	case reversesInPlace(fn):
		return "slices.Reverse", true
	}
	return "", false
}

// formatsDigitByDigit recognizes building a decimal string from the last digit
// up: the body divides by ten, takes the remainder of ten, and turns the digit
// into a character. The last part is what separates printing a number from
// merely reading it digit by digit — spelling a number in words divides the same
// way but uses each digit as an index into a table of words, and replacing that
// with strconv.Itoa would be nonsense.
func formatsDigitByDigit(fn *ast.FuncDecl) bool {
	return returnsBasicType(fn, "string") && hasDecimalDigitLoop(fn.Body) &&
		rendersDigitAsCharacter(fn.Body) && !mentionsPackage(fn.Body, "strconv")
}

// rendersDigitAsCharacter reports whether the body turns a digit into its ASCII
// character, written either as `'0' + d` or as an index into a literal "0123…".
func rendersDigitAsCharacter(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op != token.ADD {
				return true
			}
			for _, operand := range []ast.Expr{node.X, node.Y} {
				if lit, ok := operand.(*ast.BasicLit); ok && lit.Kind == token.CHAR && lit.Value == `'0'` {
					found = true
					return false
				}
			}
		case *ast.IndexExpr:
			lit, ok := node.X.(*ast.BasicLit)
			if ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "0123456789") {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// parsesDigitByDigit recognizes accumulating a number as `n = n*10 + digit`.
func parsesDigitByDigit(fn *ast.FuncDecl) bool {
	if !returnsBasicType(fn, "int") || mentionsPackage(fn.Body, "strconv") {
		return false
	}

	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		binary, ok := n.(*ast.BinaryExpr)
		if !ok || binary.Op != token.ADD {
			return true
		}
		multiply, ok := binary.X.(*ast.BinaryExpr)
		if !ok || multiply.Op != token.MUL {
			return true
		}
		if patternkit.IsIntLiteral(multiply.Y, 10) && subtractsZeroRune(binary.Y) {
			found = true
			return false
		}
		return true
	})
	return found
}

// hasDecimalDigitLoop reports whether the body both divides by ten and takes a
// remainder of ten — the two halves of printing a number by hand.
func hasDecimalDigitLoop(body *ast.BlockStmt) bool {
	divides, remainders := false, false

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if patternkit.IsIntLiteral(node.Y, 10) {
				divides = divides || node.Op == token.QUO
				remainders = remainders || node.Op == token.REM
			}
		case *ast.AssignStmt:
			// `i /= 10` is an assignment, not a binary expression.
			if node.Tok == token.QUO_ASSIGN && len(node.Rhs) == 1 && patternkit.IsIntLiteral(node.Rhs[0], 10) {
				divides = true
			}
		}
		return true
	})

	return divides && remainders
}

// searchesLinearly recognizes ranging over a collection to answer "is it there".
func searchesLinearly(fn *ast.FuncDecl, operands stdlibOperands) bool {
	if !returnsBasicType(fn, "bool") || len(fn.Body.List) == 0 {
		return false
	}

	rangeStmt, ok := fn.Body.List[0].(*ast.RangeStmt)
	if !ok {
		return false
	}
	// Ranging over a map or a string looks identical to ranging over a
	// slice, but slices.Contains cannot search either — the advice would be
	// unactionable.
	if !operands.rangesOverSlice(fn, rangeStmt.X) {
		return false
	}
	element := patternkit.RangeElementOf(rangeStmt)
	if len(element.Idents) == 0 || !returnsLiteral(fn.Body.List[len(fn.Body.List)-1], "false") {
		return false
	}

	// The loop must do nothing but compare the element itself (past its
	// binding by index): a body that also unpacks or converts is asking a
	// question slices.Contains cannot answer.
	body := element.Statements(rangeStmt.Body)
	if len(body) != 1 {
		return false
	}
	ifStmt, ok := body[0].(*ast.IfStmt)
	if !ok || ifStmt.Else != nil || len(ifStmt.Body.List) != 1 {
		return false
	}
	comparison, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok || comparison.Op != token.EQL {
		return false
	}
	if !element.IsElement(comparison.X) && !element.IsElement(comparison.Y) {
		return false
	}
	return returnsLiteral(ifStmt.Body.List[0], "true")
}

// negatesWhenNegative recognizes `if x < 0 { return -x }; return x`.
func negatesWhenNegative(fn *ast.FuncDecl) bool {
	if len(fn.Body.List) != 2 {
		return false
	}
	ifStmt, ok := fn.Body.List[0].(*ast.IfStmt)
	if !ok || ifStmt.Else != nil || len(ifStmt.Body.List) != 1 {
		return false
	}
	comparison, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok || comparison.Op != token.LSS || !patternkit.IsIntLiteral(comparison.Y, 0) {
		return false
	}
	subject, ok := comparison.X.(*ast.Ident)
	if !ok {
		return false
	}

	negated, ok := returnedExpr(ifStmt.Body.List[0])
	if !ok {
		return false
	}
	unary, ok := negated.(*ast.UnaryExpr)
	if !ok || unary.Op != token.SUB || !patternkit.IsIdent(unary.X, subject.Name) {
		return false
	}
	plain, ok := returnedExpr(fn.Body.List[1])
	return ok && patternkit.IsIdent(plain, subject.Name)
}

// returnsSmallerOrLarger recognizes `if a < b { return a }; return b`.
func returnsSmallerOrLarger(fn *ast.FuncDecl) bool {
	if len(fn.Body.List) != 2 || countParams(fn) != 2 {
		return false
	}
	ifStmt, ok := fn.Body.List[0].(*ast.IfStmt)
	if !ok || ifStmt.Else != nil || len(ifStmt.Body.List) != 1 {
		return false
	}
	comparison, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok || !isOrderComparison(comparison.Op) {
		return false
	}
	left, leftOK := comparison.X.(*ast.Ident)
	right, rightOK := comparison.Y.(*ast.Ident)
	if !leftOK || !rightOK {
		return false
	}

	first, ok := returnedExpr(ifStmt.Body.List[0])
	if !ok {
		return false
	}
	second, ok := returnedExpr(fn.Body.List[1])
	if !ok {
		return false
	}
	return (patternkit.IsIdent(first, left.Name) && patternkit.IsIdent(second, right.Name)) ||
		(patternkit.IsIdent(first, right.Name) && patternkit.IsIdent(second, left.Name))
}

// reversesInPlace recognizes swapping elements from both ends towards the middle.
func reversesInPlace(fn *ast.FuncDecl) bool {
	swaps := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if swaps {
			return false
		}
		forStmt, ok := n.(*ast.ForStmt)
		if !ok || forStmt.Post == nil {
			return true
		}
		post, ok := forStmt.Post.(*ast.AssignStmt)
		if !ok || len(post.Lhs) != 2 {
			return true
		}
		for _, stmt := range forStmt.Body.List {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 2 {
				continue
			}
			if isIndexExpr(assign.Lhs[0]) && isIndexExpr(assign.Lhs[1]) &&
				isIndexExpr(assign.Rhs[0]) && isIndexExpr(assign.Rhs[1]) {
				swaps = true
				return false
			}
		}
		return true
	})

	return swaps
}

func returnsBasicType(fn *ast.FuncDecl, name string) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == name
}

func countParams(fn *ast.FuncDecl) int {
	if fn.Type.Params == nil {
		return 0
	}
	count := 0
	for _, param := range fn.Type.Params.List {
		count += max(len(param.Names), 1)
	}
	return count
}

func returnedExpr(stmt ast.Stmt) (ast.Expr, bool) {
	ret, ok := stmt.(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil, false
	}
	return ret.Results[0], true
}

func returnsLiteral(stmt ast.Stmt, literal string) bool {
	expr, ok := returnedExpr(stmt)
	return ok && patternkit.IsIdent(expr, literal)
}

func isIndexExpr(expr ast.Expr) bool {
	_, ok := expr.(*ast.IndexExpr)
	return ok
}

func isOrderComparison(op token.Token) bool {
	return op == token.LSS || op == token.GTR || op == token.LEQ || op == token.GEQ
}

// subtractsZeroRune recognizes the digit extraction `c - '0'`, in any of the
// forms it is written in.
func subtractsZeroRune(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		binary, ok := n.(*ast.BinaryExpr)
		if !ok || binary.Op != token.SUB {
			return true
		}
		lit, ok := binary.Y.(*ast.BasicLit)
		if ok && lit.Kind == token.CHAR && lit.Value == `'0'` {
			found = true
			return false
		}
		return true
	})
	return found
}

// mentionsPackage reports whether the body already calls into a package, which
// means the author knows about it and is doing something else.
func mentionsPackage(body *ast.BlockStmt, pkg string) bool {
	mentions := false
	ast.Inspect(body, func(n ast.Node) bool {
		if mentions {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if patternkit.IsIdent(sel.X, pkg) {
			mentions = true
			return false
		}
		return true
	})
	return mentions
}
