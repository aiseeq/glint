package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewUpsertAffectedCountedAsInsertedRule())
	rules.Register(NewBatchUpsertDuplicateConflictKeysRule())
}

// maxQueryTexts bounds the variants of a query text built from parts.
const maxQueryTexts = 8

// queryGap stands for a part of a query the code computes.
const queryGap = " $9 "

// queryTexts returns the texts a string expression of fn can hold at the
// expression: constants, + of parts, a local variable by its assignments
// before it (= and +=), a parameter by what the callers pass. A part the code
// computes is a parameter-like gap.
func queryTexts(scope funcScope, fn *ast.FuncDecl, expr ast.Expr) []string {
	return queryTextsAt(scope, fn, expr, expr.Pos(), 0)
}

func queryTextsAt(scope funcScope, fn *ast.FuncDecl, expr ast.Expr, at token.Pos, depth int) []string {
	expr = ast.Unparen(expr)
	if tv, ok := scope.info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		return []string{constant.StringVal(tv.Value)}
	}
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return []string{queryGap}
		}
		return joinTexts(queryTextsAt(scope, fn, e.X, at, depth), queryTextsAt(scope, fn, e.Y, at, depth))
	case *ast.Ident:
		v, ok := scope.info.ObjectOf(e).(*types.Var)
		if !ok || depth > 2 {
			return []string{queryGap}
		}
		if index, ok := paramIndex(typedFunc{info: scope.info, decl: fn}, v); ok {
			return callerTexts(scope, fn, index, depth)
		}
		return localTexts(scope, fn, v, at, depth)
	}
	return []string{queryGap}
}

// joinTexts returns every left text followed by every right one, bounded.
func joinTexts(left, right []string) []string {
	var texts []string
	for _, l := range left {
		for _, r := range right {
			if len(texts) < maxQueryTexts {
				texts = append(texts, l+r)
			}
		}
	}
	return texts
}

// localTexts returns the texts a local variable holds at a position, by its
// assignments in source order before it: = and := start over, += appends.
func localTexts(scope funcScope, fn *ast.FuncDecl, v *types.Var, at token.Pos, depth int) []string {
	texts := []string{queryGap}
	assigned := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Pos() >= at || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || scope.info.ObjectOf(id) != v {
				continue
			}
			value := queryTextsAt(scope, fn, assign.Rhs[i], assign.Pos(), depth+1)
			if assign.Tok == token.ADD_ASSIGN && assigned {
				texts = joinTexts(texts, value)
			} else {
				texts = value
			}
			assigned = true
		}
		return true
	})
	return texts
}

// callerTexts returns the texts the callers of fn pass for the parameter at
// index, each built in its caller's scope; a gap when no caller passes text.
func callerTexts(scope funcScope, fn *ast.FuncDecl, index, depth int) []string {
	obj, ok := scope.info.Defs[fn.Name].(*types.Func)
	if !ok {
		return []string{queryGap}
	}
	var texts []string
	for _, site := range scope.callers[obj.Origin()] {
		if index >= len(site.call.Args) {
			continue
		}
		caller := funcScope{info: site.caller.info, decls: scope.decls, callers: scope.callers}
		arg := site.call.Args[index]
		for _, text := range queryTextsAt(caller, site.caller.decl, arg, arg.Pos(), depth+1) {
			if text != queryGap && len(texts) < maxQueryTexts && !slices.Contains(texts, text) {
				texts = append(texts, text)
			}
		}
	}
	if len(texts) == 0 {
		return []string{queryGap}
	}
	return texts
}

// upsertAny reports a text among them that is an INSERT ... ON CONFLICT ...
// DO UPDATE.
func upsertAny(texts []string) bool {
	return slices.ContainsFunc(texts, sqlschema.UpdatesOnConflict)
}

// queryArgument returns the first string argument of a call: the query of
// Exec(ctx, query, args...) and its kin.
func queryArgument(info *types.Info, call *ast.CallExpr) ast.Expr {
	for _, arg := range call.Args {
		if basic, ok := info.TypeOf(arg).(*types.Basic); ok && basic.Info()&types.IsString != 0 {
			return arg
		}
	}
	return nil
}

// insertedCounter is the name of a count of newly inserted rows.
var insertedCounter = regexp.MustCompile(`(?i)insert|creat|added|^new`)

// NewUpsertAffectedCountedAsInsertedRule creates upsert-affected-counted-as-inserted:
// PostgreSQL counts a row an INSERT ... ON CONFLICT ... DO UPDATE updated
// among the affected rows, so RowsAffected of an upsert is not the number of
// new rows:
//
//	res, err := db.NamedExecContext(ctx, `INSERT ... ON CONFLICT (key) DO UPDATE SET ...`, row)
//	n, _ := res.RowsAffected()
//	inserted += int(n)        // every re-sync of a known row counts as new
//
// The upsert's text may come from the callers (`INSERT ...` + conflictClause).
// RETURNING (xmax = 0) AS inserted tells a new row from an updated one.
func NewUpsertAffectedCountedAsInsertedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"upsert-affected-counted-as-inserted",
			"patterns",
			"Detects RowsAffected of an INSERT ... ON CONFLICT DO UPDATE counted as inserted rows — PostgreSQL counts updated rows as affected, so every known row counts as new",
			core.SeverityMedium,
		),
		suggestion: "Return RETURNING (xmax = 0) AS inserted and count the rows where it is true, or name the count for what it is (written)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				return true
			}
			call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
			if !ok || len(call.Args) != 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "RowsAffected" {
				return true
			}
			result, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			exec := execAssigning(scope.info, fn, scope.info.ObjectOf(result))
			if exec == nil {
				return true
			}
			query := queryArgument(scope.info, exec)
			if query == nil || !upsertAny(queryTexts(scope, fn, query)) {
				return true
			}
			count, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			if insertedCounter.MatchString(count.Name) || countedAsInserted(scope.info, fn, scope.info.ObjectOf(count)) {
				findings = append(findings, funcFinding{node: call, message: "RowsAffected of an upsert is counted as inserted rows — PostgreSQL counts the rows ON CONFLICT DO UPDATE updated, so every known row counts as new"})
			}
			return true
		})
		return findings
	}
	return r
}

// execAssigning returns the Exec call (Exec, ExecContext, NamedExec,
// NamedExecContext) whose result the variable holds.
func execAssigning(info *types.Info, fn *ast.FuncDecl, result types.Object) *ast.CallExpr {
	var exec *ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || info.ObjectOf(id) != result {
			return true
		}
		if call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && strings.Contains(sel.Sel.Name, "Exec") {
				exec = call
			}
		}
		return true
	})
	return exec
}

// countedAsInserted reports the affected count added to a counter of
// inserted rows: inserted += int(n).
func countedAsInserted(info *types.Info, fn *ast.FuncDecl, affected types.Object) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ADD_ASSIGN || len(assign.Lhs) != 1 {
			return true
		}
		counter, ok := assign.Lhs[0].(*ast.Ident)
		if ok && insertedCounter.MatchString(counter.Name) && mentionsObject(info, assign.Rhs[0], affected) {
			found = true
		}
		return !found
	})
	return found
}

// mentionsObject reports an expression reading the object.
func mentionsObject(info *types.Info, expr ast.Expr, obj types.Object) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && info.ObjectOf(id) == obj {
			found = true
		}
		return !found
	})
	return found
}

// namedBulkCalls are the sqlx calls that expand a slice argument into a
// multi-row VALUES list, with the index of the query and of the rows.
var namedBulkCalls = map[string][2]int{
	"Named": {0, 1}, "NamedExec": {0, 1}, "NamedExecContext": {1, 2}, "NamedQuery": {0, 1}, "NamedQueryContext": {1, 2},
}

// NewBatchUpsertDuplicateConflictKeysRule creates batch-upsert-duplicate-conflict-keys:
// a multi-row INSERT ... ON CONFLICT ... DO UPDATE fails as a whole when two
// of its rows share the conflict key ("ON CONFLICT DO UPDATE command cannot
// affect row a second time"):
//
//	func (r *Repo) UpsertBatch(ctx context.Context, rows []*Row) error {
//		for chunk := range slices.Chunk(rows, 500) {
//			q, args, err := sqlx.Named(`INSERT ... VALUES (...) ON CONFLICT (key) DO UPDATE SET ...`, chunk)
//
// A provider that returns one row twice fails the whole batch. Reported: the
// rows are a parameter of the function, chunked or as is, that the function
// never replaces with a deduplicated set nor checks row by row against a map
// of keys seen.
func NewBatchUpsertDuplicateConflictKeysRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"batch-upsert-duplicate-conflict-keys",
			"patterns",
			"Detects a multi-row INSERT ... ON CONFLICT DO UPDATE of a slice parameter never deduplicated by the conflict key — two rows with one key fail the whole statement",
			core.SeverityMedium,
		),
		suggestion: "Keep one row per conflict key before building the statement (last wins, as sequential upserts would)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			indexes, ok := namedBulkCalls[sel.Sel.Name]
			if !ok || indexes[1] >= len(call.Args) {
				return true
			}
			argType := scope.info.TypeOf(call.Args[indexes[1]])
			if argType == nil {
				return true
			}
			if _, isSlice := argType.Underlying().(*types.Slice); !isSlice {
				return true
			}
			if !upsertAny(queryTexts(scope, fn, call.Args[indexes[0]])) {
				return true
			}
			rows := rowsSource(scope.info, fn, call.Args[indexes[1]])
			if rows == nil || assignedIn(scope.info, fn.Body, rows) || keyedPerRow(scope.info, fn.Body, rows) {
				return true
			}
			if _, isParam := paramIndex(typedFunc{info: scope.info, decl: fn}, rows); !isParam {
				return true
			}
			findings = append(findings, funcFinding{node: call, message: "A multi-row upsert of " + rows.Name() + " that is never deduplicated by the conflict key — two rows with one key fail the whole statement"})
			return true
		})
		return findings
	}
	return r
}

// rowsSource returns the variable a slice argument takes its rows from:
// itself, the slice it chunks (for chunk := range slices.Chunk(rows, n)), the
// slice it cuts (rows[i:j]).
func rowsSource(info *types.Info, fn *ast.FuncDecl, arg ast.Expr) *types.Var {
	switch e := ast.Unparen(arg).(type) {
	case *ast.SliceExpr:
		return rowsSource(info, fn, e.X)
	case *ast.Ident:
		v, ok := info.ObjectOf(e).(*types.Var)
		if !ok {
			return nil
		}
		var source *types.Var
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if !ok || loop.Key == nil {
				return true
			}
			if key, ok := loop.Key.(*ast.Ident); ok && info.Defs[key] == v {
				if chunk, ok := ast.Unparen(loop.X).(*ast.CallExpr); ok && len(chunk.Args) == 2 && strings.HasSuffix(selectorName(chunk.Fun), "Chunk") {
					source = rowsSource(info, fn, chunk.Args[0])
				}
			}
			return source == nil
		})
		if source != nil {
			return source
		}
		return v
	}
	return nil
}

// keyedPerRow reports a loop over the rows that looks a row's value up in a
// map: seen[row.Key], the check for a key met twice.
func keyedPerRow(info *types.Info, body *ast.BlockStmt, rows *types.Var) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		loop, ok := n.(*ast.RangeStmt)
		if !ok || found {
			return !found
		}
		x, ok := ast.Unparen(loop.X).(*ast.Ident)
		value, isIdent := loop.Value.(*ast.Ident)
		if !ok || !isIdent || info.ObjectOf(x) != rows {
			return true
		}
		row := info.ObjectOf(value)
		ast.Inspect(loop.Body, func(n ast.Node) bool {
			index, ok := n.(*ast.IndexExpr)
			if !ok {
				return !found
			}
			typ := info.TypeOf(index.X)
			if typ == nil {
				return true
			}
			if _, isMap := typ.Underlying().(*types.Map); isMap && mentionsObject(info, index.Index, row) {
				found = true
			}
			return !found
		})
		return !found
	})
	return found
}

// selectorName returns the name a call's function is written with: Chunk of
// slices.Chunk.
func selectorName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

// assignedIn reports an assignment to the variable in the body.
func assignedIn(info *types.Info, body *ast.BlockStmt, v *types.Var) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && info.ObjectOf(id) == v {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
