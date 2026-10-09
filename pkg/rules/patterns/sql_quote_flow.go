package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
	"golang.org/x/tools/go/types/typeutil"
)

// sqlTextEvidence is text that is SQL: a statement, or a clause written apart
// from its statement (" WHERE ", " AND name = "). Clause words count in upper
// case only: in lower case they are English.
var sqlTextEvidence = regexp.MustCompile(`(?is:\bselect\b.*\bfrom\b|\binsert\s+into\b|\bupdate\s+[\w."]+\s+set\b|\bdelete\s+from\b)` +
	`|\b(?:WHERE|VALUES|HAVING|JOIN|ORDER\s+BY|GROUP\s+BY|LIKE|ILIKE)\b` +
	`|\b(?:AND|OR|ON|SET)\s+[\w."]+\s*(?:=|<>|!=|<|>)`)

// maxEscapedSQLHops bounds how many calls up (to the callers of a helper that
// returns the value) or down (into a function it is handed to) the escaped
// value is followed.
const maxEscapedSQLHops = 4

// escapedSQLFlow follows a quote-escaped value to where it goes: into a
// concatenation or a format with SQL text, a variable or a builder that
// holds SQL text, the query argument of a database call, through helpers
// that return it to their callers and functions it is handed to. Doubling a
// quote escapes other texts as well (a sheet name in a spreadsheet range), so
// the value counts as SQL only where SQL is seen.
type escapedSQLFlow struct {
	decls   map[*types.Func]typedFuncDecl
	callers map[*types.Func][]funcCallSite
	parents map[*ast.FuncDecl]map[ast.Node]ast.Node
	seen    map[types.Object]bool
}

func newEscapedSQLFlow(decls map[*types.Func]typedFuncDecl, callers map[*types.Func][]funcCallSite) *escapedSQLFlow {
	return &escapedSQLFlow{decls: decls, callers: callers, parents: make(map[*ast.FuncDecl]map[ast.Node]ast.Node)}
}

// valueReaches reports an escaped value, expr in fn, that reaches SQL text.
func (f *escapedSQLFlow) valueReaches(fn typedFuncDecl, expr ast.Expr) bool {
	f.seen = make(map[types.Object]bool)
	return f.reaches(fn, expr, 0)
}

// variableReaches reports a package-level variable holding an escaped value
// (or the replacer that escapes) that reaches SQL text.
func (f *escapedSQLFlow) variableReaches(info *types.Info, obj types.Object) bool {
	f.seen = make(map[types.Object]bool)
	return f.objectReaches(typedFuncDecl{info: info}, obj, 0)
}

func (f *escapedSQLFlow) parentsOf(decl *ast.FuncDecl) map[ast.Node]ast.Node {
	parents, ok := f.parents[decl]
	if !ok {
		parents = helpers.ParentMap(decl)
		f.parents[decl] = parents
	}
	return parents
}

// reaches climbs from expr through the expressions made of its value.
func (f *escapedSQLFlow) reaches(fn typedFuncDecl, expr ast.Expr, hops int) bool {
	if fn.decl == nil {
		return false
	}
	parents := f.parentsOf(fn.decl)
	info := fn.info
	node := ast.Node(expr)
	for {
		switch parent := parents[node].(type) {
		case *ast.ParenExpr, *ast.CompositeLit, *ast.KeyValueExpr, *ast.UnaryExpr:
			node = parent
		case *ast.BinaryExpr:
			if parent.Op != token.ADD {
				return false
			}
			if sqlTextIn(info, parent) {
				return true
			}
			node = parent
		case *ast.IndexExpr:
			if parent.X != node {
				return false
			}
			node = parent
		case *ast.SliceExpr:
			if parent.X != node {
				return false
			}
			node = parent
		case *ast.SelectorExpr:
			if parent.X != node {
				return false
			}
			// A field of the value, or what its method answers: b.String(),
			// replacer.Replace(s).
			node = parent
			if call, ok := parents[parent].(*ast.CallExpr); ok && call.Fun == parent {
				node = call
			}
		case *ast.CallExpr:
			index := -1
			for i, arg := range parent.Args {
				if arg == node {
					index = i
				}
			}
			if index < 0 {
				return false
			}
			reached, onward := f.throughCall(fn, parent, index, hops)
			if reached || !onward {
				return reached
			}
			node = parent
		case *ast.AssignStmt:
			return f.assignedReaches(fn, parent, node, hops)
		case *ast.ValueSpec:
			for i, value := range parent.Values {
				if value == node && i < len(parent.Names) {
					return f.objectReaches(fn, info.Defs[parent.Names[i]], hops)
				}
			}
			return false
		case *ast.RangeStmt:
			value, ok := parent.Value.(*ast.Ident)
			if parent.X != node || !ok {
				return false
			}
			return f.objectReaches(fn, info.ObjectOf(value), hops)
		case *ast.ReturnStmt:
			return f.returnedReaches(fn, parents, parent, hops)
		default:
			return false
		}
	}
}

// assignedReaches follows a value assigned to a variable (or to an element
// or a field of one) into the uses of that variable.
func (f *escapedSQLFlow) assignedReaches(fn typedFuncDecl, assign *ast.AssignStmt, value ast.Node, hops int) bool {
	var targets []ast.Expr
	for i, rhs := range assign.Rhs {
		if rhs != value {
			continue
		}
		switch {
		case len(assign.Lhs) == len(assign.Rhs):
			targets = append(targets, assign.Lhs[i])
		case len(assign.Rhs) == 1:
			// q, err := build(): the results that are not the error.
			for _, lhs := range assign.Lhs {
				if t := fn.info.TypeOf(lhs); t != nil && !types.Identical(t, types.Universe.Lookup("error").Type()) {
					targets = append(targets, lhs)
				}
			}
		}
	}
	for _, target := range targets {
		if holder := heldIn(target); holder != nil && f.objectReaches(fn, fn.info.ObjectOf(holder), hops) {
			return true
		}
	}
	return false
}

// returnedReaches follows a value a function returns to its callers.
func (f *escapedSQLFlow) returnedReaches(fn typedFuncDecl, parents map[ast.Node]ast.Node, ret *ast.ReturnStmt, hops int) bool {
	for node := parents[ret]; node != nil && node != fn.decl; node = parents[node] {
		if _, closure := node.(*ast.FuncLit); closure {
			return false
		}
	}
	obj, ok := fn.info.Defs[fn.decl.Name].(*types.Func)
	if !ok || hops >= maxEscapedSQLHops {
		return false
	}
	for _, site := range f.callers[obj] {
		if f.reaches(site.caller, site.call, hops+1) {
			return true
		}
	}
	return false
}

// throughCall judges a value handed to a call as its index-th argument:
// reached is SQL seen, onward is a call whose result is made of the value and
// is followed further.
func (f *escapedSQLFlow) throughCall(fn typedFuncDecl, call *ast.CallExpr, index, hops int) (reached, onward bool) {
	info := fn.info
	if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
		return false, true
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if builtin, ok := info.Uses[id].(*types.Builtin); ok {
			return false, builtin.Name() == "append"
		}
	}
	callee, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok || callee.Pkg() == nil {
		return false, false
	}
	sig, _ := callee.Type().(*types.Signature)
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sig != nil && sig.Recv() != nil {
		if sqlDriverValue(info.TypeOf(sel.X)) {
			return index == sqlQueryParam(sig), false
		}
		if strings.HasPrefix(callee.Name(), "Write") {
			if holder := heldIn(sel.X); holder != nil {
				return f.objectReaches(fn, info.ObjectOf(holder), hops), false
			}
			return false, false
		}
	}
	switch callee.Pkg().Path() {
	case "fmt":
		switch callee.Name() {
		case "Sprintf", "Sprint", "Sprintln":
			return len(call.Args) > 0 && sqlTextIn(info, call.Args[0]), true
		case "Fprintf", "Fprint", "Fprintln":
			if len(call.Args) > 1 && sqlTextIn(info, call.Args[1]) {
				return true, false
			}
			if holder := heldIn(call.Args[0]); holder != nil {
				return f.objectReaches(fn, info.ObjectOf(holder), hops), false
			}
		}
		return false, false
	case "strings", "bytes":
		return false, true
	}
	decl, ok := f.decls[callee.Origin()]
	if !ok || hops >= maxEscapedSQLHops {
		return false, false
	}
	if sig != nil && sig.Variadic() && index >= sig.Params().Len() {
		index = sig.Params().Len() - 1
	}
	param := paramAt(decl, index)
	return param != nil && f.objectReaches(decl, param, hops+1), false
}

// objectReaches reports a variable that holds SQL text and gets the escaped
// value, or whose value reaches SQL text where it is used. The uses of a
// local are in its function, those of a package-level variable in every
// loaded body.
func (f *escapedSQLFlow) objectReaches(fn typedFuncDecl, obj types.Object, hops int) bool {
	if obj == nil || f.seen[obj] {
		return false
	}
	f.seen[obj] = true
	scopes := []typedFuncDecl{fn}
	if obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() {
		scopes = scopes[:0]
		for _, decl := range f.decls {
			scopes = append(scopes, decl)
		}
	}
	for _, scope := range scopes {
		if scope.decl == nil {
			continue
		}
		parents := f.parentsOf(scope.decl)
		found := false
		ast.Inspect(scope.decl, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if found || !ok || scope.info.ObjectOf(id) != obj {
				return !found
			}
			if holdsSQLText(scope.info, parents, id) {
				found = true
				return false
			}
			if scope.info.Uses[id] == obj && !assignedTo(parents, id) && f.reaches(scope, id, hops) {
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

// holdsSQLText reports a mention of a variable that puts SQL text in it:
// query := "SELECT ...", b.WriteString(" WHERE "), fmt.Fprintf(&b, "SELECT ...").
func holdsSQLText(info *types.Info, parents map[ast.Node]ast.Node, id *ast.Ident) bool {
	switch parent := parents[id].(type) {
	case *ast.AssignStmt:
		for i, lhs := range parent.Lhs {
			if lhs == id && len(parent.Lhs) == len(parent.Rhs) {
				return sqlTextIn(info, parent.Rhs[i])
			}
		}
	case *ast.ValueSpec:
		for i, name := range parent.Names {
			if name == id && i < len(parent.Values) {
				return sqlTextIn(info, parent.Values[i])
			}
		}
	case *ast.SelectorExpr:
		call, ok := parents[parent].(*ast.CallExpr)
		if ok && call.Fun == parent && strings.HasPrefix(parent.Sel.Name, "Write") {
			for _, arg := range call.Args {
				if sqlTextIn(info, arg) {
					return true
				}
			}
		}
	case *ast.UnaryExpr:
		call, ok := parents[parent].(*ast.CallExpr)
		if ok && parent.Op == token.AND && len(call.Args) > 1 && call.Args[0] == parent && isPackageFuncCall(nil, info, call, "fmt", "Fprintf", "Fprint", "Fprintln") {
			return sqlTextIn(info, call.Args[1])
		}
	}
	return false
}

// assignedTo reports an identifier written by an assignment, not read.
func assignedTo(parents map[ast.Node]ast.Node, id *ast.Ident) bool {
	assign, ok := parents[id].(*ast.AssignStmt)
	if !ok {
		return false
	}
	for _, lhs := range assign.Lhs {
		if lhs == id {
			return true
		}
	}
	return false
}

// sqlTextIn reports a constant, a concatenation or a format call whose
// constant text is SQL.
func sqlTextIn(info *types.Info, expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) > 0 && isPackageFuncCall(nil, info, call, "fmt", "Sprintf") {
		expr = ast.Unparen(call.Args[0])
	}
	var texts []string
	for _, operand := range concatOperands(expr) {
		if text, ok := goConstantString(operand, info); ok {
			texts = append(texts, text)
		}
	}
	return len(texts) > 0 && sqlTextEvidence.MatchString(strings.Join(texts, " "))
}

// heldIn returns the variable a target expression is part of: b in b, &b,
// conds[i], s.query.
func heldIn(expr ast.Expr) *ast.Ident {
	for {
		switch node := ast.Unparen(expr).(type) {
		case *ast.Ident:
			return node
		case *ast.SelectorExpr:
			expr = node.X
		case *ast.IndexExpr:
			expr = node.X
		case *ast.StarExpr:
			expr = node.X
		case *ast.UnaryExpr:
			if node.Op != token.AND {
				return nil
			}
			expr = node.X
		default:
			return nil
		}
	}
}

// sqlDriverValue reports a value of a type declared by a SQL driver package:
// *sql.DB, *sqlx.Tx, *pgxpool.Pool, *gorm.DB.
func sqlDriverValue(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && sqlDriverPackage(named.Obj().Pkg().Path())
}

// sqlQueryParam returns the index of the parameter of a driver method that
// takes the query text: the first string or empty-interface parameter
// (Query(query string, ...), QueryContext(ctx, query, ...), Where(query any,
// ...)), -1 for a method without one.
func sqlQueryParam(sig *types.Signature) int {
	for i := 0; i < sig.Params().Len(); i++ {
		if sig.Variadic() && i == sig.Params().Len()-1 {
			break
		}
		switch u := sig.Params().At(i).Type().Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.String {
				return i
			}
		case *types.Interface:
			if u.Empty() {
				return i
			}
		}
	}
	return -1
}
