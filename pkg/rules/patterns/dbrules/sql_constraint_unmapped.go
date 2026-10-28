package dbrules

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLConstraintViolationUnmappedRule())
	rules.Register(NewTruncatedRandomIDAsUniqueNumberRule())
}

// TruncatedRandomIDAsUniqueNumberRule reports short random values used as
// unique database keys when a collision is neither retried nor mapped.
type TruncatedRandomIDAsUniqueNumberRule struct {
	*rules.BaseRule
}

// NewTruncatedRandomIDAsUniqueNumberRule creates the rule.
func NewTruncatedRandomIDAsUniqueNumberRule() *TruncatedRandomIDAsUniqueNumberRule {
	return &TruncatedRandomIDAsUniqueNumberRule{BaseRule: rules.NewBaseRule(
		"truncated-random-id-as-unique-number",
		"patterns",
		"Detects a truncated random identifier stored in a unique database key without retrying a collision",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op because the rule follows data across callers.
func (r *TruncatedRandomIDAsUniqueNumberRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *TruncatedRandomIDAsUniqueNumberRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the truncated random origin of an unhandled unique
// key conflict.
func (r *TruncatedRandomIDAsUniqueNumberRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("truncated random identifier as unique number: nil Go project context")
	}
	callers, err := newCallerIndex(ctx)
	if err != nil {
		return nil, err
	}
	conflicts, err := unhandledUniqueConflicts(ctx, callers, r.BaseRule)
	if err != nil {
		return nil, err
	}
	var violations []*core.Violation
	for _, conflict := range conflicts {
		origin := truncatedRandomUniqueOrigin(conflict.callers, conflict.target)
		if origin == nil {
			continue
		}
		line := origin.fn.File.LineFor(origin.node)
		if origin.fn.File.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(origin.fn.File.RelPath, line,
			"A truncated random identifier is stored in a unique key without retrying a collision")
		v.WithCode(strings.TrimSpace(origin.fn.File.GetLine(line)))
		v.WithSuggestion("Use the full random value, or retry after a unique-key collision")
		violations = append(violations, v)
	}
	return violations, nil
}

// SQLConstraintViolationUnmappedRule detects a statement the migrations'
// constraints can refuse, in a function that never looks at the database
// error:
//
//	DELETE FROM tariffs WHERE id = $1   -- orders.tariff_id REFERENCES tariffs, no ON DELETE
//	INSERT INTO tariffs (project_id, corridor) ...  -- UNIQUE (project_id, corridor), no ON CONFLICT
//
// A delete of a row other rows still point at, a second row for a unique
// key, are things users do in the normal course: the refusal deserves a
// conflict the caller can explain ("the tariff is in use", "a tariff for
// this corridor exists"). Returned as it is, the foreign key or unique
// violation reaches the user as a generic server error with the database's
// wording, and the logs count it as a failure.
//
// Reported when the error reaches an HTTP handler - the function is called
// from one, at most three calls up - and nothing on the way looks at it: the
// function, or a function of its file it calls, checks the driver's error
// (PgError, a 23505 or 23503 code, the constraint name) or hands it to a
// mapper named for it, or a caller's error branch tells a conflict apart. A
// refusal in a background job or a command-line tool reaches no user.
type SQLConstraintViolationUnmappedRule struct {
	*rules.BaseRule
}

// NewSQLConstraintViolationUnmappedRule creates the rule
func NewSQLConstraintViolationUnmappedRule() *SQLConstraintViolationUnmappedRule {
	return &SQLConstraintViolationUnmappedRule{BaseRule: rules.NewBaseRule(
		"sql-constraint-violation-unmapped",
		"patterns",
		"Detects a DELETE of rows a foreign key without ON DELETE protects, or an INSERT of a whole unique key without ON CONFLICT, in a function that never checks the database error — the expected refusal reaches the user as a server error",
		core.SeverityMedium,
	)}
}

// constraintCheck is code looking at a constraint violation of the driver.
var constraintCheck = regexp.MustCompile(`PgError|pq\.Error|"23505"|"23503"|"23P01"|UniqueViolation|ForeignKeyViolation|pgerrcode|ConstraintName|Constraint\b|(?i:duplicate key)`)

// constraintMapper is the name of a function handed an error to translate.
var constraintMapper = regexp.MustCompile(`(?i)^(map|translate|convert|classify)\w*err|pgerr|constraint|unique|duplicate|conflict|foreignkey`)

// AnalyzeFile is a no-op: whether a refusal reaches a client is found by
// following the callers across the project.
func (r *SQLConstraintViolationUnmappedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLConstraintViolationUnmappedRule) RequiresSSA() bool { return false }

// maxRefusalHops bounds how many callers up a refusal is followed to the
// handler answering it.
const maxRefusalHops = 3

// AnalyzeGoProject reports the refusable statements whose error reaches an
// HTTP handler with nothing on the way checking it.
func (r *SQLConstraintViolationUnmappedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("sql constraint violation unmapped: nil Go project context")
	}
	callers, err := newCallerIndex(ctx)
	if err != nil {
		return nil, err
	}
	checkersByFile := make(map[*core.FileContext]map[string]bool)
	var violations []*core.Violation
	for _, fn := range callers.funcs {
		literals := patternkit.SqlLiterals(fn.Decl.Body)
		if len(literals) == 0 {
			continue
		}
		schema, ok := fileSchema(fn.File, r.BaseRule)
		if !ok || schema == nil {
			continue
		}
		checkers, ok := checkersByFile[fn.File]
		if !ok {
			checkers = constraintCheckingFuncs(fn.File)
			checkersByFile[fn.File] = checkers
		}
		obj, ok := fn.Info.Defs[fn.Decl.Name].(*types.Func)
		if !ok || checksConstraints(fn.File, fn.Decl, checkers) || !callers.reachesHandlerUnmapped(obj, 0, map[*types.Func]bool{}) {
			continue
		}
		for i, literal := range literals {
			earlier := earlierStatements(literals[:i])
			for _, del := range sqlschema.Deletes(literal.Text) {
				refs := slices.DeleteFunc(schema.RestrictingReferences(del.Table), func(ref sqlschema.Reference) bool { return earlier.deleted[ref.Table] })
				if len(refs) == 0 {
					continue
				}
				names := make([]string, 0, len(refs))
				for _, ref := range refs {
					names = append(names, ref.Table+"."+ref.Column)
				}
				violations = r.report(fn.File, violations, literal.LineAt(fn.File, del.Offset),
					"Rows of "+del.Table+" are deleted while "+strings.Join(names, ", ")+" point at them with a foreign key that refuses the delete, and nothing between here and the handler checks the database error — a row still in use comes back to the user as a server error")
			}

		}
	}
	conflicts, err := unhandledUniqueConflicts(ctx, callers, r.BaseRule)
	if err != nil {
		return nil, err
	}
	for _, conflict := range conflicts {
		violations = r.report(conflict.file, violations, conflict.line,
			"The INSERT writes the whole unique key ("+strings.Join(conflict.key, ", ")+") of "+conflict.table+" with no ON CONFLICT, and nothing between here and the handler checks the database error — a duplicate comes back to the user as a server error")
	}
	return violations, nil
}

type unhandledUniqueConflict struct {
	file    *core.FileContext
	line    int
	table   string
	key     []string
	callers *callerIndex
	target  *types.Func
}

// unhandledUniqueConflicts finds unique-key INSERTs whose errors reach an
// HTTP handler without a conflict check, retry, or earlier write ruling them out.
func unhandledUniqueConflicts(ctx *core.GoProjectContext, callers *callerIndex, rule *rules.BaseRule) ([]unhandledUniqueConflict, error) {
	if ctx == nil {
		return nil, errors.New("sql constraint violation unmapped: nil Go project context")
	}
	checkersByFile := make(map[*core.FileContext]map[string]bool)
	var conflicts []unhandledUniqueConflict
	for _, fn := range callers.funcs {
		literals := patternkit.SqlLiterals(fn.Decl.Body)
		if len(literals) == 0 {
			continue
		}
		schema, ok := fileSchema(fn.File, rule)
		if !ok || schema == nil {
			continue
		}
		checkers, ok := checkersByFile[fn.File]
		if !ok {
			checkers = constraintCheckingFuncs(fn.File)
			checkersByFile[fn.File] = checkers
		}
		target, ok := fn.Info.Defs[fn.Decl.Name].(*types.Func)
		if !ok || checksConstraints(fn.File, fn.Decl, checkers) || !callers.reachesHandlerUnmapped(target, 0, map[*types.Func]bool{}) {
			continue
		}
		for i, literal := range literals {
			earlier := earlierStatements(literals[:i])
			for _, conflict := range schema.UniqueConflicts(literal.Text) {
				if earlier.rulesOut(schema, conflict) {
					continue
				}
				conflicts = append(conflicts, unhandledUniqueConflict{
					file: fn.File, line: literal.LineAt(fn.File, conflict.Offset),
					table: conflict.Table, key: conflict.Key, callers: callers, target: target,
				})
			}
		}
	}
	return conflicts, nil
}

// truncatedRandomUniqueOrigin finds a short random identifier passed by an
// HTTP handler to the function that writes a unique key. The database error
// already has a finding at the INSERT; this points at the lossy construction
// that made retries necessary.
type truncatedRandomOrigin struct {
	fn   patternkit.TypedFunc
	node ast.Node
}

func truncatedRandomUniqueOrigin(callers *callerIndex, target *types.Func) *truncatedRandomOrigin {
	return truncatedRandomUniqueOriginAt(callers, target.Origin(), 0, make(map[*types.Func]bool))
}

func truncatedRandomUniqueOriginAt(callers *callerIndex, target *types.Func, depth int, seen map[*types.Func]bool) *truncatedRandomOrigin {
	if seen[target] || depth >= maxRefusalHops {
		return nil
	}
	seen[target] = true
	sites := callers.sites[target]
	for _, method := range patternkit.ImplementedMethods(target, callers.interfaces) {
		sites = append(sites, callers.sites[method]...)
	}
	for _, site := range sites {
		if conflictHandledAt(site) || retriesConflictAt(site) {
			continue
		}
		if patternkit.TakesResponseWriter(site.Caller.Info, site.Caller.Decl.Type) {
			caller, ok := typedCaller(callers.funcs, site.Caller.Decl)
			if ok {
				if node := shortRandomUniqueCallArgument(site, caller); node != nil {
					return &truncatedRandomOrigin{fn: caller, node: node}
				}
			}
			continue
		}
		if caller, ok := site.Caller.Info.Defs[site.Caller.Decl.Name].(*types.Func); ok {
			if node := truncatedRandomUniqueOriginAt(callers, caller.Origin(), depth+1, seen); node != nil {
				return node
			}
		}
	}
	return nil
}

func typedCaller(funcs []patternkit.TypedFunc, decl *ast.FuncDecl) (patternkit.TypedFunc, bool) {
	for _, fn := range funcs {
		if fn.Decl == decl {
			return fn, true
		}
	}
	return patternkit.TypedFunc{}, false
}

// shortRandomUniqueCallArgument finds a truncated random value passed to the
// function that writes the unique key.
func shortRandomUniqueCallArgument(site patternkit.FuncCallSite, fn patternkit.TypedFunc) ast.Node {
	randomVars := randomIdentifierVars(fn)
	for _, arg := range site.Call.Args {
		if node := truncatedRandomValue(arg, fn, randomVars, make(map[types.Object]bool)); node != nil {
			return node
		}
	}
	return nil
}

func truncatedRandomValue(expr ast.Expr, fn patternkit.TypedFunc, randomVars map[types.Object]bool, seen map[types.Object]bool) ast.Node {
	var found ast.Node
	ast.Inspect(expr, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		if slice, ok := n.(*ast.SliceExpr); ok {
			if id, ok := ast.Unparen(slice.X).(*ast.Ident); ok && randomVars[fn.Info.Uses[id]] {
				if high, ok := ast.Unparen(slice.High).(*ast.BasicLit); ok && high.Kind == token.INT {
					if size, err := strconv.Atoi(high.Value); err == nil && size > 0 && size < 16 {
						found = slice
						return false
					}
				}
			}
		}
		if id, ok := n.(*ast.Ident); ok {
			obj := fn.Info.Uses[id]
			if obj != nil && !seen[obj] {
				seen[obj] = true
				if value := localObjectValue(fn, obj); value != nil {
					found = truncatedRandomValue(value, fn, randomVars, seen)
				}
			}
		}
		return found == nil
	})
	return found
}

func localObjectValue(fn patternkit.TypedFunc, object types.Object) ast.Expr {
	var value ast.Expr
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if fn.Info.Defs[name] == object && i < len(node.Values) {
					value = node.Values[i]
					return false
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || i >= len(node.Rhs) {
					continue
				}
				if fn.Info.Defs[id] == object || fn.Info.Uses[id] == object {
					value = node.Rhs[i]
					return false
				}
			}
		}
		return value == nil
	})
	return value
}

// randomIdentifierVars records UUID values and buffers filled by crypto/rand.
func randomIdentifierVars(fn patternkit.TypedFunc) map[types.Object]bool {
	vars := make(map[types.Object]bool)
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				obj := fn.Info.Defs[id]
				if obj == nil {
					obj = fn.Info.Uses[id]
				}
				if obj == nil {
					continue
				}
				if i < len(node.Rhs) {
					if call, ok := ast.Unparen(node.Rhs[i]).(*ast.CallExpr); ok && patternkit.IsPackageFuncCall(fn.File.GoAST, fn.Info, call, "github.com/google/uuid", "New") {
						vars[obj] = true
					}
				}
			}
		case *ast.CallExpr:
			if !patternkit.IsPackageFuncCall(fn.File.GoAST, fn.Info, node, "crypto/rand", "Read") || len(node.Args) != 1 {
				break
			}
			slice, ok := ast.Unparen(node.Args[0]).(*ast.SliceExpr)
			if !ok {
				break
			}
			if id, ok := ast.Unparen(slice.X).(*ast.Ident); ok {
				if obj := fn.Info.Uses[id]; obj != nil {
					vars[obj] = true
				}
			}
		}
		return true
	})
	return vars
}

// callerIndex tells, for a project function, where it is called: directly
// or through a project interface method it implements.
type callerIndex struct {
	funcs      []patternkit.TypedFunc
	sites      map[*types.Func][]patternkit.FuncCallSite
	interfaces []*types.TypeName
}

func newCallerIndex(ctx *core.GoProjectContext) (*callerIndex, error) {
	decls, err := patternkit.FuncDeclsByObject(ctx)
	if err != nil {
		return nil, err
	}
	sites, err := patternkit.FuncCallSites(ctx, decls)
	if err != nil {
		return nil, err
	}
	return &callerIndex{funcs: patternkit.ProjectFuncDecls(ctx), sites: sites, interfaces: patternkit.ProjectInterfaces(ctx)}, nil
}

// reachesHandlerUnmapped reports a function whose error reaches an HTTP
// handler within maxRefusalHops callers, through call sites none of which
// tells a conflict apart.
func (c *callerIndex) reachesHandlerUnmapped(fn *types.Func, depth int, seen map[*types.Func]bool) bool {
	if seen[fn] || depth >= maxRefusalHops {
		return false
	}
	seen[fn] = true
	sites := c.sites[fn]
	for _, method := range patternkit.ImplementedMethods(fn, c.interfaces) {
		sites = append(sites, c.sites[method]...)
	}
	for _, site := range sites {
		if conflictHandledAt(site) {
			continue
		}
		if patternkit.TakesResponseWriter(site.Caller.Info, site.Caller.Decl.Type) {
			return true
		}
		if caller, ok := site.Caller.Info.Defs[site.Caller.Decl.Name].(*types.Func); ok && c.reachesHandlerUnmapped(caller, depth+1, seen) {
			return true
		}
	}
	return false
}

func retriesConflictAt(site patternkit.FuncCallSite) bool {
	var errorObject types.Object
	ast.Inspect(site.Caller.Decl.Body, func(n ast.Node) bool {
		if assignment, ok := n.(*ast.AssignStmt); ok && patternkit.ContainsNode(assignment, site.Call) {
			for _, lhs := range assignment.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					errorObject = site.Caller.Info.Defs[id]
					if errorObject == nil {
						errorObject = site.Caller.Info.Uses[id]
					}
					if errorObject != nil {
						return false
					}
				}
			}
		}
		return errorObject == nil
	})
	if errorObject == nil {
		return false
	}
	handled := false
	ast.Inspect(site.Caller.Decl.Body, func(n ast.Node) bool {
		if handled {
			return false
		}
		branch, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		matches := false
		ast.Inspect(branch.Cond, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !conflictWords.MatchString(types.ExprString(call.Fun)) {
				return true
			}
			for _, arg := range call.Args {
				if id, ok := ast.Unparen(arg).(*ast.Ident); ok && site.Caller.Info.Uses[id] == errorObject {
					matches = true
				}
			}
			return !matches
		})
		if matches {
			ast.Inspect(branch.Body, func(n ast.Node) bool {
				if _, ok := n.(*ast.BranchStmt); ok {
					handled = true
					return false
				}
				return true
			})
		}
		return !handled
	})
	return handled
}

// conflictWords are how a caller's error branch names a refusal it tells
// apart.
var conflictWords = regexp.MustCompile(`(?i)conflict|duplicate|exists|unique|constraint|inuse|in_use|referenced|2350[35]`)

// conflictHandledAt reports a call site whose error branch tells a conflict
// apart: errors.Is or errors.As, or a check naming a conflict.
func conflictHandledAt(site patternkit.FuncCallSite) bool {
	var branch *ast.BlockStmt
	ast.Inspect(site.Caller.Decl.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok || branch != nil {
			return branch == nil
		}
		for i, stmt := range block.List {
			if call, body := patternkit.ExecuteChecked(block.List, i, stmt); call != nil && patternkit.ContainsNode(call, site.Call) {
				branch = body
			}
		}
		return branch == nil
	})
	if branch == nil {
		return false
	}
	if patternkit.ComparesError(branch) {
		return true
	}
	named := false
	ast.Inspect(branch, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && conflictWords.MatchString(types.ExprString(call.Fun)) {
			named = true
		}
		return !named
	})
	return named
}

// report appends a finding unless the line suppresses it.
func (r *SQLConstraintViolationUnmappedRule) report(ctx *core.FileContext, violations []*core.Violation, line int, message string) []*core.Violation {
	if ctx.IsSuppressed(line, r.Name()) {
		return violations
	}
	return append(violations, patternkit.SqlViolation(r.BaseRule, ctx, line, message,
		"Check the error for the violation (errors.As to the driver's error, code 23503 or 23505 and the constraint name) and return a conflict the caller can explain"))
}

// constraintCheckingFuncs returns the names of the file's functions that
// look at a constraint violation.
func constraintCheckingFuncs(ctx *core.FileContext) map[string]bool {
	names := make(map[string]bool)
	for _, decl := range ctx.GoAST.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && constraintCheck.MatchString(funcText(ctx, fn)) {
			names[fn.Name.Name] = true
		}
	}
	return names
}

// checksConstraints reports a function looking at a constraint violation
// itself, calling a function of the file that does, or handing its error to
// a mapper named for it.
func checksConstraints(ctx *core.FileContext, fn *ast.FuncDecl, checkers map[string]bool) bool {
	if constraintCheck.MatchString(funcText(ctx, fn)) {
		return true
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		name := helpers.CalleeName(call)
		if checkers[name] || constraintMapper.MatchString(name) {
			found = true
		}
		return !found
	})
	return found
}

// funcText returns the source of a function.
func funcText(ctx *core.FileContext, fn *ast.FuncDecl) string {
	start, end := ctx.GoFileSet.Position(fn.Pos()).Offset, ctx.GoFileSet.Position(fn.End()).Offset
	if start < 0 || end > len(ctx.Content) || start >= end {
		return ""
	}
	return string(ctx.Content[start:end])
}

// earlierWrites are what the statements before one in a function did: the
// tables they deleted rows of and the tables they inserted a row into and
// read it back.
type earlierWrites struct {
	deleted  map[string]bool
	returned map[string]bool
}

// earlierStatements collects the deletes and the returning inserts of the
// statements of a function before the one checked.
func earlierStatements(literals []patternkit.SqlLiteral) earlierWrites {
	writes := earlierWrites{deleted: make(map[string]bool), returned: make(map[string]bool)}
	for _, literal := range literals {
		for _, del := range sqlschema.Deletes(literal.Text) {
			writes.deleted[del.Table] = true
		}
		for _, table := range sqlschema.ReturningInserts(literal.Text) {
			writes.returned[table] = true
		}
	}
	return writes
}

// rulesOut reports a unique conflict the function itself rules out: it
// cleared the table before (a set of rows replaced), or a key column points
// at a row it has just inserted - a new parent has no children yet.
func (w earlierWrites) rulesOut(schema *sqlschema.Schema, conflict sqlschema.UniqueConflict) bool {
	if w.deleted[conflict.Table] {
		return true
	}
	for _, column := range conflict.Key {
		if target := schema.ForeignKeyTarget(conflict.Table, column); target != "" && w.returned[target] {
			return true
		}
	}
	return false
}
