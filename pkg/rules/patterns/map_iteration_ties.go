package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

// The shapes below are order dependences that survive a comparison or a sort:
// the comparison decides between entries only while their keys differ, and
// equal keys leave the choice to the walk, which Go randomizes.

// loopTaint returns the loop's key and value names and every name the body
// declares from them: t := catalog[unit] carries the entry as much as unit
// does.
func loopTaint(rangeStmt *ast.RangeStmt) map[string]bool {
	key, value := rangeTargetNames(rangeStmt)
	tainted := map[string]bool{}
	for _, name := range []string{key, value} {
		if name != "" {
			tainted[name] = true
		}
	}
	ast.Inspect(rangeStmt.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if ok && ident.Name != "_" && readsAnyName(assign.Rhs[i], tainted) {
				tainted[ident.Name] = true
			}
		}
		return true
	})
	return tainted
}

// readsAnyName reports whether the expression reads one of the names.
func readsAnyName(expr ast.Expr, names map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && names[ident.Name] {
			found = true
		}
		return !found
	})
	return found
}

// inspectLoopBody walks the body of a map loop, leaving out function literals
// and the bodies of nested map loops, which are reported on their own.
func inspectLoopBody(rangeStmt *ast.RangeStmt, info *types.Info, visit func(ast.Node)) {
	ast.Inspect(rangeStmt.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.RangeStmt:
			if isMapRange(node, info) {
				return false
			}
		}
		if n != nil {
			visit(n)
		}
		return true
	})
}

// outerTargetOf reports whether an assignment target outlives one iteration:
// a variable declared before the loop, a field, or an entry of a map other than
// the one at the loop's own key. An entry at the key is written once per walk,
// so nothing is chosen between entries there.
func outerTargetOf(lhs ast.Expr, rangeStmt *ast.RangeStmt, info *types.Info) bool {
	key, _ := rangeTargetNames(rangeStmt)
	switch node := ast.Unparen(lhs).(type) {
	case *ast.Ident:
		obj := info.ObjectOf(node)
		return obj != nil && obj.Pos() < rangeStmt.Pos()
	case *ast.SelectorExpr:
		return !rowOfKey(node.X, key)
	case *ast.IndexExpr:
		return key == "" || !isIdent(node.Index, key)
	}
	return false
}

// rowOfKey reports whether the expression looks up the row of the loop key -
// rowOf(rows, k) or rows[k] - which one walk reaches once.
func rowOfKey(expr ast.Expr, key string) bool {
	if key == "" {
		return false
	}
	switch node := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		for _, arg := range node.Args {
			if isIdent(arg, key) {
				return true
			}
		}
	case *ast.IndexExpr:
		return isIdent(node.Index, key)
	}
	return false
}

// usedAfter reports whether the function reads the target after the loop: a
// field or a map entry always stays readable, a variable when it is read.
func usedAfter(fn *ast.FuncDecl, target ast.Expr, end token.Pos) bool {
	ident, ok := ast.Unparen(target).(*ast.Ident)
	if !ok {
		return true
	}
	used := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Pos() > end && id.Name == ident.Name {
			used = true
		}
		return !used
	})
	return used
}

// tieChoice finds a best-of choice inside a map loop that leaves ties to the
// walk: an if whose condition orders a value computed from the entry with a
// strict comparison and no second comparison for equal values, and whose body
// keeps the entry itself, not the compared value.
//
//	for _, w := range free {
//	    if best == nil || w.Dist < best.Dist { best = w }   // equal Dist: walk decides
//	}
//
// Keeping the compared value (best = v after v > best) has no tie to break,
// and an order on the key itself cannot tie, since a map holds a key once.
func tieChoice(fn *ast.FuncDecl, rangeStmt *ast.RangeStmt, info *types.Info) (*ast.IfStmt, string, bool) {
	tainted := loopTaint(rangeStmt)
	var (
		found  *ast.IfStmt
		winner string
	)
	inspectLoopBody(rangeStmt, info, func(n ast.Node) {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || found != nil {
			return
		}
		operands, ok := untiedOrder(ifStmt.Cond, tainted, rangeStmt, info)
		if !ok || !comparesRunningBest(ifStmt, operands) {
			return
		}
		if target := keptEntry(fn, ifStmt.Body, operands, tainted, rangeStmt, info); target != "" {
			found, winner = ifStmt, target
		}
	})
	return found, winner, found != nil
}

// untiedOrder returns the operands of the ordering comparisons in the
// condition that read the entry, when nothing in the condition breaks a tie:
// no equality between two values and no order on the loop key.
func untiedOrder(cond ast.Expr, tainted map[string]bool, rangeStmt *ast.RangeStmt, info *types.Info) ([]ast.Expr, bool) {
	key, _ := rangeTargetNames(rangeStmt)
	var operands []ast.Expr
	tied := false
	ast.Inspect(cond, func(n ast.Node) bool {
		binary, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		switch binary.Op {
		case token.EQL:
			if !isTieSentinel(binary.X) && !isTieSentinel(binary.Y) {
				tied = true
			}
		case token.LSS, token.GTR, token.LEQ, token.GEQ:
			if uniqueOperand(binary.X, cond, key, rangeStmt, info) || uniqueOperand(binary.Y, cond, key, rangeStmt, info) {
				tied = true
			}
			if !isNumericOrString(info.TypeOf(binary.X)) {
				return true
			}
			if readsAnyName(binary.X, tainted) || readsAnyName(binary.Y, tainted) {
				operands = append(operands, binary.X, binary.Y)
			}
		}
		return true
	})
	return operands, !tied && len(operands) > 0
}

// uniqueOperand reports whether an ordered operand cannot be shared by two
// entries: the loop key itself, a field named as an identity (ID, Name, Key)
// or of the map key's type, or the length of a key the condition requires to
// be a prefix or a suffix of one string - two such keys of one length are the
// same key.
func uniqueOperand(operand, cond ast.Expr, key string, rangeStmt *ast.RangeStmt, info *types.Info) bool {
	if key != "" && isIdent(operand, key) {
		return true
	}
	if call, ok := ast.Unparen(operand).(*ast.CallExpr); ok && len(call.Args) == 0 {
		if method, ok := call.Fun.(*ast.SelectorExpr); ok && isIdentityName(method.Sel.Name) {
			return true
		}
	}
	if selector, ok := ast.Unparen(operand).(*ast.SelectorExpr); ok {
		if isIdentityName(selector.Sel.Name) {
			return true
		}
		if mapType, ok := typeOrNil(info, rangeStmt.X).Underlying().(*types.Map); ok {
			if t := info.TypeOf(selector); t != nil && !isFloatType(t) && types.Identical(t, mapType.Key()) {
				return true
			}
		}
	}
	call, ok := ast.Unparen(operand).(*ast.CallExpr)
	if !ok || key == "" || !isIdent(call.Fun, "len") || len(call.Args) != 1 || !isIdent(call.Args[0], key) {
		return false
	}
	anchored := false
	ast.Inspect(cond, func(n ast.Node) bool {
		test, ok := n.(*ast.CallExpr)
		if !ok {
			return !anchored
		}
		if selector, ok := test.Fun.(*ast.SelectorExpr); ok && len(test.Args) == 2 && anchorsKey(test.Args[1], key) &&
			(selector.Sel.Name == "HasPrefix" || selector.Sel.Name == "HasSuffix") {
			anchored = true
		}
		return !anchored
	})
	return anchored
}

// anchorsKey reports whether a prefix or suffix argument is the key, alone or
// joined with string literals ("/"+dir): two such arguments of one key length
// are the same key.
func anchorsKey(arg ast.Expr, key string) bool {
	switch node := ast.Unparen(arg).(type) {
	case *ast.Ident:
		return node.Name == key
	case *ast.BinaryExpr:
		if node.Op != token.ADD {
			return false
		}
		_, leftLit := ast.Unparen(node.X).(*ast.BasicLit)
		_, rightLit := ast.Unparen(node.Y).(*ast.BasicLit)
		return (leftLit && anchorsKey(node.Y, key)) || (rightLit && anchorsKey(node.X, key))
	}
	return false
}

// isIdentityName reports whether a field or method name says it tells entries
// apart.
func isIdentityName(name string) bool {
	switch name {
	case "id", "name", "key":
		return true
	}
	for _, suffix := range []string{"ID", "Id", "Name", "Key"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// comparesRunningBest reports whether the condition compares against the best
// found so far: a compared operand reads a target the if body assigns, or a
// name the if's init statement read off such a target (best := m[k] before
// m[k] = t). A comparison with a constant or an unrelated value is a filter,
// which keeps every entry that passes and chooses none.
func comparesRunningBest(ifStmt *ast.IfStmt, operands []ast.Expr) bool {
	running := map[string]bool{}
	for _, stmt := range ifStmt.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN {
			continue
		}
		for i, lhs := range assign.Lhs {
			if i < len(assign.Rhs) && isBareAppend(assign.Rhs[i]) {
				continue
			}
			running[types.ExprString(lhs)] = true
		}
	}
	if init, ok := ifStmt.Init.(*ast.AssignStmt); ok && init.Tok == token.DEFINE && len(init.Lhs) == len(init.Rhs) {
		for i, lhs := range init.Lhs {
			if running[types.ExprString(init.Rhs[i])] {
				running[types.ExprString(lhs)] = true
			}
		}
	}
	found := false
	for _, operand := range operands {
		ast.Inspect(operand, func(n ast.Node) bool {
			if expr, ok := n.(ast.Expr); ok && running[types.ExprString(expr)] {
				found = true
			}
			return !found
		})
	}
	return found
}

func isBareAppend(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	return ok && isIdent(call.Fun, "append")
}

// isTieSentinel recognizes the operands an equality uses to test for the first
// candidate rather than to break a tie: nil and literals.
func isTieSentinel(expr ast.Expr) bool {
	switch ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return true
	}
	return isNilIdent(expr)
}

func isNumericOrString(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&(types.IsNumeric|types.IsString) != 0
}

// keptEntry returns the target the if body hands the entry to, when that
// target outlives the loop and is read after it. The entry is anything read
// off the loop variables other than the compared values themselves.
func keptEntry(fn *ast.FuncDecl, body *ast.BlockStmt, operands []ast.Expr, tainted map[string]bool, rangeStmt *ast.RangeStmt, info *types.Info) string {
	compared := map[string]bool{}
	for _, operand := range operands {
		compared[types.ExprString(operand)] = true
	}
	for _, stmt := range body.List {
		switch node := stmt.(type) {
		case *ast.BranchStmt, *ast.ReturnStmt:
			return "" // a first match, reported by firstMatchSelection
		case *ast.AssignStmt:
			if node.Tok != token.ASSIGN || len(node.Lhs) != len(node.Rhs) {
				continue
			}
			for i, lhs := range node.Lhs {
				rhs := node.Rhs[i]
				if compared[types.ExprString(rhs)] || !readsAnyName(rhs, tainted) {
					continue
				}
				if outerTargetOf(lhs, rangeStmt, info) && usedAfter(fn, lhs, rangeStmt.End()) {
					return types.ExprString(lhs)
				}
			}
		}
	}
	return ""
}

// floatSum finds a float accumulated across the entries of a map: float
// addition is not associative, so the sum changes in its last digits with the
// order of the terms. A target at the loop's own key gets one term per walk.
func floatSum(fn *ast.FuncDecl, rangeStmt *ast.RangeStmt, info *types.Info) (string, bool) {
	tainted := loopTaint(rangeStmt)
	target := ""
	inspectLoopBody(rangeStmt, info, func(n ast.Node) {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || target != "" || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return
		}
		if assign.Tok != token.ADD_ASSIGN && assign.Tok != token.SUB_ASSIGN {
			return
		}
		lhs := assign.Lhs[0]
		if !isFloatType(info.TypeOf(lhs)) || !readsAnyName(assign.Rhs[0], tainted) || !outerTargetOf(lhs, rangeStmt, info) {
			return
		}
		if ident, ok := ast.Unparen(lhs).(*ast.Ident); ok && !floatLeaves(fn, ident.Name, info) {
			return
		}
		target = types.ExprString(lhs)
	})
	return target, target != ""
}

func isFloatType(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsFloat != 0
}

// floatLeaves reports whether a float variable reaches the caller or the
// output with its digits: returned, stored into a field or written out. A
// comparison with a threshold keeps only its answer.
func floatLeaves(fn *ast.FuncDecl, name string, info *types.Info) bool {
	leaves := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if leaves {
			return false
		}
		switch node := n.(type) {
		case *ast.ReturnStmt:
			leaves = anyCarriesDigits(node.Results, name)
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if _, ok := lhs.(*ast.SelectorExpr); ok && anyCarriesDigits(node.Rhs, name) {
					leaves = true
				}
			}
		case *ast.CallExpr:
			writer, args, ok := outputCall(node, info)
			leaves = ok && anyCarriesDigits(args, name) && (writer == nil || writerLeaves(fn, writer, info))
		}
		return !leaves
	})
	return leaves
}

// anyCarriesDigits reports whether one of the expressions reads the name
// outside a comparison.
func anyCarriesDigits(exprs []ast.Expr, name string) bool {
	for _, expr := range exprs {
		found := false
		ast.Inspect(expr, func(n ast.Node) bool {
			if binary, ok := n.(*ast.BinaryExpr); ok && isComparison(binary.Op) {
				return false
			}
			if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
				found = true
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

func isComparison(op token.Token) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ:
		return true
	}
	return false
}

// groupedAppend finds entries of a map loop appended into groups of another
// map, m[k] = append(m[k], entry), where the groups are never sorted and the
// map outlives the function: each group lists its members in walk order.
func groupedAppend(fn *ast.FuncDecl, rangeStmt *ast.RangeStmt, info *types.Info) (*ast.AssignStmt, string, bool) {
	tainted := loopTaint(rangeStmt)
	var (
		found  *ast.AssignStmt
		groups string
	)
	inspectLoopBody(rangeStmt, info, func(n ast.Node) {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || found != nil || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return
		}
		index, ok := assign.Lhs[0].(*ast.IndexExpr)
		if !ok || !outerTargetOf(index, rangeStmt, info) || !isMapType(typeOrNil(info, index.X)) {
			return
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) < 2 || !isIdent(call.Fun, "append") || types.ExprString(call.Args[0]) != types.ExprString(index) {
			return
		}
		if !argsMention(call.Args[1:], tainted) {
			return
		}
		name := types.ExprString(index.X)
		if groupsSortedAfter(fn, name, rangeStmt.End()) || !groupsLeave(index.X, info) {
			return
		}
		found, groups = assign, name
	})
	return found, groups, found != nil
}

func typeOrNil(info *types.Info, expr ast.Expr) types.Type {
	if t := info.TypeOf(expr); t != nil {
		return t
	}
	return types.Typ[types.Invalid]
}

func argsMention(args []ast.Expr, names map[string]bool) bool {
	for _, arg := range args {
		if readsAnyName(arg, names) {
			return true
		}
	}
	return false
}

// groupsSortedAfter reports whether the groups are put in order after the
// loop: a sort that reads the map, or a walk over the map that sorts each
// group it visits.
func groupsSortedAfter(fn *ast.FuncDecl, groups string, end token.Pos) bool {
	sorted := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if sorted || n == nil || n.Pos() < end {
			return !sorted
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			if isSortingCall(node.Fun) {
				for _, arg := range node.Args {
					if strings.Contains(types.ExprString(arg), groups) {
						sorted = true
					}
				}
			}
		case *ast.RangeStmt:
			if types.ExprString(node.X) != groups {
				return true
			}
			if value, ok := node.Value.(*ast.Ident); ok && isSortedBefore(&ast.FuncDecl{Body: node.Body}, value.Name, node.Body.Pos()) {
				sorted = true
			}
		}
		return !sorted
	})
	return sorted
}

// groupsLeave reports whether the grouping map is kept as state - a field or a
// package variable - that later code reads group by group. Groups returned to
// a caller are left alone: the caller may read them in a way the order does
// not reach, such as taking the only member of a group of one.
func groupsLeave(groups ast.Expr, info *types.Info) bool {
	ident, ok := ast.Unparen(groups).(*ast.Ident)
	if !ok {
		return true
	}
	obj := info.ObjectOf(ident)
	return obj != nil && obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope()
}

// tielessSort returns the sort that puts the collected slice in order, when
// every sort of it after the loop compares a single value that equal entries
// can share: they then keep the walk order, a stable sort included. A sort on
// the element itself, on a field filled from the map key or on an identity
// field (ID, Name, Key) has nothing to tie.
func tielessSort(fn *ast.FuncDecl, rangeStmt *ast.RangeStmt, name string, info *types.Info) (*ast.CallExpr, bool) {
	keyFields := keyFilledFields(rangeStmt, name, info)
	var first *ast.CallExpr
	defined := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || defined || call.Pos() < rangeStmt.End() || !isSortingCall(call.Fun) || len(call.Args) == 0 || !mentions(call.Args[0], name) {
			return !defined
		}
		projection, sortType, ok := comparatorProjection(call, name, info)
		if !ok || !isMeasure(projection, sortType) || isIdentityProjection(projection, keyFields) || sortsByKeyType(projection, sortType, rangeStmt, info) {
			defined = true
			return false
		}
		if first == nil {
			first = call
		}
		return true
	})
	return first, first != nil && !defined
}

// comparatorProjection returns what a comparator sort orders by, with the
// element written as @: "@.secs" for rows[i].secs > rows[j].secs. It answers
// false for any sort it cannot read as a single comparison - a named sorter,
// a comparator with a second key, more than one statement.
func comparatorProjection(call *ast.CallExpr, name string, info *types.Info) (string, types.Type, bool) {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || len(call.Args) != 2 {
		return "", nil, false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return "", nil, false
	}
	lit, ok := call.Args[1].(*ast.FuncLit)
	if !ok || len(lit.Body.List) != 1 {
		return "", nil, false
	}
	ret, ok := lit.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return "", nil, false
	}
	params := funcLitParams(lit.Type)
	if len(params) != 2 {
		return "", nil, false
	}
	switch {
	case pkg.Name == "sort" && (selector.Sel.Name == "Slice" || selector.Sel.Name == "SliceStable"):
		binary, ok := ast.Unparen(ret.Results[0]).(*ast.BinaryExpr)
		if !ok || !isOrdering(binary.Op) {
			return "", nil, false
		}
		left := strings.ReplaceAll(types.ExprString(binary.X), name+"["+params[0]+"]", "@")
		left = strings.ReplaceAll(left, name+"["+params[1]+"]", "@")
		right := strings.ReplaceAll(types.ExprString(binary.Y), name+"["+params[1]+"]", "@")
		right = strings.ReplaceAll(right, name+"["+params[0]+"]", "@")
		return left, info.TypeOf(binary.X), left == right && strings.Contains(left, "@")
	case pkg.Name == "slices" && (selector.Sel.Name == "SortFunc" || selector.Sel.Name == "SortStableFunc"):
		leftExpr, rightExpr, ok := comparedPair(ret.Results[0])
		if !ok {
			return "", nil, false
		}
		leftKey, rightKey := replaceParam(leftExpr, params[0]), replaceParam(rightExpr, params[1])
		return leftKey, info.TypeOf(leftExpr), leftKey == rightKey && strings.Contains(leftKey, "@")
	}
	return "", nil, false
}

// comparedPair reads cmp.Compare(a, b), strings.Compare(a, b) and a - b.
func comparedPair(expr ast.Expr) (ast.Expr, ast.Expr, bool) {
	switch node := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		selector, ok := node.Fun.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "Compare" && len(node.Args) == 2 {
			return node.Args[0], node.Args[1], true
		}
	case *ast.BinaryExpr:
		if node.Op == token.SUB {
			return node.X, node.Y, true
		}
	}
	return nil, nil, false
}

// replaceParam writes the parameter of a comparator as @ in an operand.
func replaceParam(expr ast.Expr, param string) string {
	var b strings.Builder
	text := types.ExprString(expr)
	for i := 0; i < len(text); {
		if strings.HasPrefix(text[i:], param) && (i == 0 || !isIdentChar(text[i-1])) &&
			(i+len(param) == len(text) || !isIdentChar(text[i+len(param)])) {
			b.WriteByte('@')
			i += len(param)
			continue
		}
		b.WriteByte(text[i])
		i++
	}
	return b.String()
}

func isOrdering(op token.Token) bool {
	switch op {
	case token.LSS, token.GTR, token.LEQ, token.GEQ:
		return true
	}
	return false
}

func funcLitParams(fnType *ast.FuncType) []string {
	var names []string
	for _, field := range fnType.Params.List {
		for _, ident := range field.Names {
			names = append(names, ident.Name)
		}
	}
	return names
}

// isMeasure reports whether the sort key is a number read off the element - a
// count, a duration, a score - which entries commonly share. A string key is
// usually a name, the element itself is its own key, and a lookup of the
// element in a rank table (slices.Index(order, e)) gives each value its own
// place.
func isMeasure(projection string, sortType types.Type) bool {
	if projection == "@" || strings.Contains(projection, "(@") || strings.Contains(projection, ", @") {
		return false
	}
	if sortType == nil || isSourcePosition(sortType) {
		return false
	}
	basic, ok := sortType.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsNumeric != 0
}

// isSourcePosition reports whether the type is go/token.Pos: distinct nodes
// start at distinct offsets, so a sort by position has nothing to tie.
func isSourcePosition(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "go/token" && named.Obj().Name() == "Pos"
}

// sortsByKeyType reports whether the sort key is a plain field of the map
// key's type, other than a float: an element built from an entry carries the
// key it was stored under (Tag of a map keyed by tag), and two entries never
// share it.
func sortsByKeyType(projection string, sortType types.Type, rangeStmt *ast.RangeStmt, info *types.Info) bool {
	field, ok := strings.CutPrefix(projection, "@.")
	if !ok || field == "" || strings.ContainsAny(field, ".([") || sortType == nil || isFloatType(sortType) {
		return false
	}
	mapType, ok := typeOrNil(info, rangeStmt.X).Underlying().(*types.Map)
	return ok && types.Identical(mapType.Key(), sortType)
}

// isIdentityProjection reports whether the sort key is a field that tells
// entries apart: one filled from the map key, or one named as an identity.
func isIdentityProjection(projection string, keyFields map[string]bool) bool {
	field, ok := strings.CutPrefix(projection, "@.")
	if !ok {
		return false
	}
	field = strings.TrimSuffix(field, "()")
	if field == "" || strings.ContainsAny(field, ".([") {
		return false
	}
	return keyFields[field] || isIdentityName(field)
}

// keyFilledFields returns the fields of the elements appended to the slice
// that the loop fills from the map key: row{n, v} fills the first field.
func keyFilledFields(rangeStmt *ast.RangeStmt, name string, info *types.Info) map[string]bool {
	key, _ := rangeTargetNames(rangeStmt)
	fields := map[string]bool{}
	if key == "" {
		return fields
	}
	ast.Inspect(rangeStmt.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isAppendTo(call, name) {
			return true
		}
		for _, arg := range call.Args[1:] {
			lit, ok := ast.Unparen(arg).(*ast.CompositeLit)
			if !ok {
				continue
			}
			for field := range keyFieldsOf(lit, key, info) {
				fields[field] = true
			}
		}
		return true
	})
	return fields
}

func keyFieldsOf(lit *ast.CompositeLit, key string, info *types.Info) map[string]bool {
	fields := map[string]bool{}
	strct, _ := typeOrNil(info, lit).Underlying().(*types.Struct)
	for i, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if field, ok := kv.Key.(*ast.Ident); ok && isKeyValue(kv.Value, key, info) {
				fields[field.Name] = true
			}
			continue
		}
		if strct != nil && i < strct.NumFields() && isKeyValue(elt, key, info) {
			fields[strct.Field(i).Name()] = true
		}
	}
	return fields
}

// isKeyValue reports whether the expression is the key, possibly converted:
// string(kind) carries the key as much as kind does.
func isKeyValue(expr ast.Expr, key string, info *types.Info) bool {
	if call, ok := ast.Unparen(expr).(*ast.CallExpr); ok && len(call.Args) == 1 {
		if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
			expr = call.Args[0]
		}
	}
	return isIdent(expr, key)
}
