package patterns

import (
	"errors"
	"go/ast"
	"go/types"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLConstraintViolationUnmappedRule())
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
		literals := sqlLiterals(fn.decl.Body)
		if len(literals) == 0 {
			continue
		}
		schema, ok := fileSchema(fn.file, r.BaseRule)
		if !ok || schema == nil {
			continue
		}
		checkers, ok := checkersByFile[fn.file]
		if !ok {
			checkers = constraintCheckingFuncs(fn.file)
			checkersByFile[fn.file] = checkers
		}
		obj, ok := fn.info.Defs[fn.decl.Name].(*types.Func)
		if !ok || checksConstraints(fn.file, fn.decl, checkers) || !callers.reachesHandlerUnmapped(obj, 0, map[*types.Func]bool{}) {
			continue
		}
		for i, literal := range literals {
			earlier := earlierStatements(literals[:i])
			for _, del := range sqlschema.Deletes(literal.text) {
				refs := slices.DeleteFunc(schema.RestrictingReferences(del.Table), func(ref sqlschema.Reference) bool { return earlier.deleted[ref.Table] })
				if len(refs) == 0 {
					continue
				}
				names := make([]string, 0, len(refs))
				for _, ref := range refs {
					names = append(names, ref.Table+"."+ref.Column)
				}
				violations = r.report(fn.file, violations, literal.lineAt(fn.file, del.Offset),
					"Rows of "+del.Table+" are deleted while "+strings.Join(names, ", ")+" point at them with a foreign key that refuses the delete, and nothing between here and the handler checks the database error — a row still in use comes back to the user as a server error")
			}
			for _, conflict := range schema.UniqueConflicts(literal.text) {
				if earlier.rulesOut(schema, conflict) {
					continue
				}
				violations = r.report(fn.file, violations, literal.lineAt(fn.file, conflict.Offset),
					"The INSERT writes the whole unique key ("+strings.Join(conflict.Key, ", ")+") of "+conflict.Table+" with no ON CONFLICT, and nothing between here and the handler checks the database error — a duplicate comes back to the user as a server error")
			}
		}
	}
	return violations, nil
}

// callerIndex tells, for a project function, where it is called: directly
// or through a project interface method it implements.
type callerIndex struct {
	funcs      []typedFunc
	sites      map[*types.Func][]funcCallSite
	interfaces []*types.TypeName
}

func newCallerIndex(ctx *core.GoProjectContext) (*callerIndex, error) {
	decls, err := funcDeclsByObject(ctx)
	if err != nil {
		return nil, err
	}
	sites, err := funcCallSites(ctx, decls)
	if err != nil {
		return nil, err
	}
	return &callerIndex{funcs: projectFuncDecls(ctx), sites: sites, interfaces: projectInterfaces(ctx)}, nil
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
	for _, method := range implementedMethods(fn, c.interfaces) {
		sites = append(sites, c.sites[method]...)
	}
	for _, site := range sites {
		if conflictHandledAt(site) {
			continue
		}
		if takesResponseWriter(site.caller.info, site.caller.decl.Type) {
			return true
		}
		if caller, ok := site.caller.info.Defs[site.caller.decl.Name].(*types.Func); ok && c.reachesHandlerUnmapped(caller, depth+1, seen) {
			return true
		}
	}
	return false
}

// conflictWords are how a caller's error branch names a refusal it tells
// apart.
var conflictWords = regexp.MustCompile(`(?i)conflict|duplicate|exists|unique|constraint|inuse|in_use|referenced|2350[35]`)

// conflictHandledAt reports a call site whose error branch tells a conflict
// apart: errors.Is or errors.As, or a check naming a conflict.
func conflictHandledAt(site funcCallSite) bool {
	var branch *ast.BlockStmt
	ast.Inspect(site.caller.decl.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok || branch != nil {
			return branch == nil
		}
		for i, stmt := range block.List {
			if call, body := executeChecked(block.List, i, stmt); call != nil && containsNode(call, site.call) {
				branch = body
			}
		}
		return branch == nil
	})
	if branch == nil {
		return false
	}
	if comparesError(branch) {
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

// containsNode reports whether inner lies within outer.
func containsNode(outer, inner ast.Node) bool {
	return outer.Pos() <= inner.Pos() && inner.End() <= outer.End()
}

// report appends a finding unless the line suppresses it.
func (r *SQLConstraintViolationUnmappedRule) report(ctx *core.FileContext, violations []*core.Violation, line int, message string) []*core.Violation {
	if ctx.IsSuppressed(line, r.Name()) {
		return violations
	}
	return append(violations, sqlViolation(r.BaseRule, ctx, line, message,
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
		name := callName(call)
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
func earlierStatements(literals []sqlLiteral) earlierWrites {
	writes := earlierWrites{deleted: make(map[string]bool), returned: make(map[string]bool)}
	for _, literal := range literals {
		for _, del := range sqlschema.Deletes(literal.text) {
			writes.deleted[del.Table] = true
		}
		for _, table := range sqlschema.ReturningInserts(literal.text) {
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
