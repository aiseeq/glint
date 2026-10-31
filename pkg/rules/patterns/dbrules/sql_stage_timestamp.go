package dbrules

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewStatusWriteSkipsStageTimestampRule())
	rules.Register(NewTerminalTimestampOverwrittenRule())
}

// NewStatusWriteSkipsStageTimestampRule creates the rule that detects a
// status written without the timestamp the project keeps for that status:
//
//	UPDATE transfers SET status = $1, completed_at = $2 WHERE id = $3   -- the webhook path
//	UPDATE transfers SET status = $1, version = version + 1 WHERE id = $2 -- the poller path
//
// A transfer completed by the poller has completed_at NULL: reports by
// completion date leave it out, and a reconciler choosing CONFIRMED rows by
// confirmed_at < $1 never finds the rows confirmed through the path that
// does not stamp it. A <stage>_at column belongs to the status of the same
// name when an UPDATE sets them together, or a read compares it while fixing
// that status. A write whose status comes from a parameter counts unless
// every caller passes another status.
func NewStatusWriteSkipsStageTimestampRule() *patternkit.TypedFuncRule {
	rule := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"status-write-skips-stage-timestamp",
			"patterns",
			"Detects an UPDATE that can set a status without the <status>_at column another write path sets with it, and a read selecting that status by the column — the rows written here keep it NULL",
			core.SeverityMedium,
		),
		Suggestion: "Stamp the column wherever the status is written (CASE WHEN $n = 'COMPLETED' AND completed_at IS NULL THEN NOW() ELSE completed_at END), or select by a column every path sets",
	}
	rule.ForProject = func(decls map[*types.Func]patternkit.TypedFuncDecl) func(patternkit.FuncScope, *ast.FuncDecl) []patternkit.FuncFinding {
		index := newStageIndex(decls)
		return index.skippedStamps
	}
	return rule
}

// NewTerminalTimestampOverwrittenRule creates the rule that detects a
// <stage>_at column set straight from a parameter in a function applying
// repeated events:
//
//	func (r *Repo) UpdateFromProviderEvent(ctx context.Context, id uuid.UUID, status string, completedAt *time.Time) error {
//		_, err := r.db.Exec(ctx, `UPDATE transfers SET status = $1, completed_at = $2 WHERE id = $3`, status, completedAt, id)
//
// The next event of the same row - a cancel after completion, a repeated
// callback with no time - writes its own value over the moment the stage was
// reached, often NULL. COALESCE(completed_at, $2), or a CASE keeping a set
// value, records the stage once.
func NewTerminalTimestampOverwrittenRule() *patternkit.TypedFuncRule {
	rule := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"terminal-timestamp-overwritten-on-later-update",
			"patterns",
			"Detects a <status>_at column set straight from a parameter by a webhook, poll or sync write — the next event of the row overwrites the moment the status was reached",
			core.SeverityMedium,
		),
		Suggestion: "Keep a value once set: completed_at = COALESCE(completed_at, $n), or CASE WHEN completed_at IS NULL THEN $n ELSE completed_at END",
	}
	rule.ForProject = func(decls map[*types.Func]patternkit.TypedFuncDecl) func(patternkit.FuncScope, *ast.FuncDecl) []patternkit.FuncFinding {
		index := newStageIndex(decls)
		return index.overwrittenStamps
	}
	return rule
}

// stageWrite is an UPDATE of the project that sets the status of a table.
type stageWrite struct {
	update sqlschema.UpdateWrite
	fn     patternkit.TypedFuncDecl
	// status is the Go value bound to the status, nil when unknown.
	status ast.Expr
}

// stageIndex is what the project's SQL says of statuses and their columns.
type stageIndex struct {
	// statuses are the upper-case string constants of the project's
	// packages and the status literals of its UPDATEs.
	statuses map[string]bool
	// stamps are, by table, the <stage>_at columns an UPDATE sets with the
	// status, by column, with the stage in upper case.
	stamps map[string]map[string]string
	// writes are the UPDATEs setting a status, by table.
	writes map[string][]stageWrite
	// calls are the static calls of the project, by callee.
	calls map[*types.Func][]patternkit.FuncCallSite
}

func newStageIndex(decls map[*types.Func]patternkit.TypedFuncDecl) *stageIndex {
	index := &stageIndex{
		statuses: make(map[string]bool),
		stamps:   make(map[string]map[string]string),
		writes:   make(map[string][]stageWrite),
		calls:    patternkit.CollectCallSites(decls),
	}
	packages := make(map[*types.Package]bool)
	for fn, decl := range decls {
		if fn.Pkg() != nil && !packages[fn.Pkg()] {
			packages[fn.Pkg()] = true
			index.addConstants(fn.Pkg())
		}
		for _, bound := range boundUpdates(decl) {
			if _, ok := bound.update.Assignment("status"); ok {
				index.writes[bound.update.Table] = append(index.writes[bound.update.Table], bound)
			}
		}
		index.addUpsertStamps(decl)
	}
	for _, writes := range index.writes {
		for _, write := range writes {
			if status, ok := write.update.Assignment("status"); ok && status.IsLiteral {
				index.statuses[strings.ToUpper(status.Literal)] = true
			}
		}
	}
	for table, writes := range index.writes {
		for _, write := range writes {
			for _, set := range write.update.Sets {
				stage := index.stageOf(set.Column)
				if stage == "" {
					continue
				}
				if index.stamps[table] == nil {
					index.stamps[table] = make(map[string]string)
				}
				index.stamps[table][set.Column] = stage
			}
		}
	}
	return index
}

// addUpsertStamps records the <word>_at columns an upsert of the function
// sets with the status from a value the function stamps only for one
// status:
//
//	if settledAt == nil && p.Status == string(StatusCompleted) { settledAt = &now }
//	INSERT ... ON CONFLICT DO UPDATE SET status = EXCLUDED.status, settled_at = ... EXCLUDED.settled_at
//
// settled_at then belongs to COMPLETED, though the names differ.
func (index *stageIndex) addUpsertStamps(decl patternkit.TypedFuncDecl) {
	queries := namedStrings(decl.Decl)
	ast.Inspect(decl.Decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !runsQuery(call) {
			return true
		}
		for i, arg := range call.Args {
			if ident, ok := arg.(*ast.Ident); ok && queries[ident.Name] != nil {
				arg = queries[ident.Name]
			}
			literals := patternkit.SqlLiterals(arg)
			if !patternkit.IsStringOrConcat(arg) || len(literals) != 1 {
				continue
			}
			for _, write := range sqlschema.UpsertWrites(literals[0].Text) {
				if _, ok := write.Assignment("status"); !ok {
					continue
				}
				for _, set := range write.Sets {
					if set.Param == 0 || i+set.Param >= len(call.Args) || !stageTimestamp(set.Column) {
						continue
					}
					stage := stampedOnlyFor(decl, call.Args[i+set.Param])
					if stage == "" {
						continue
					}
					if index.stamps[write.Table] == nil {
						index.stamps[write.Table] = make(map[string]string)
					}
					index.stamps[write.Table][set.Column] = stage
					index.statuses[stage] = true
				}
			}
		}
		return true
	})
}

// stampedOnlyFor returns the status, upper case, under which the function
// sets the variable passed for a stamp - an if comparing a status with a
// constant and assigning the variable - or "" when it sets it otherwise.
func stampedOnlyFor(decl patternkit.TypedFuncDecl, value ast.Expr) string {
	ident, ok := ast.Unparen(value).(*ast.Ident)
	if !ok {
		return ""
	}
	stage := ""
	ast.Inspect(decl.Decl.Body, func(n ast.Node) bool {
		branch, ok := n.(*ast.IfStmt)
		if !ok || stage != "" || !blockAssignsName(branch.Body, ident.Name) {
			return stage == ""
		}
		ast.Inspect(branch.Cond, func(c ast.Node) bool {
			bin, ok := c.(*ast.BinaryExpr)
			if !ok || bin.Op != token.EQL {
				return true
			}
			for _, pair := range [][2]ast.Expr{{bin.X, bin.Y}, {bin.Y, bin.X}} {
				if text, ok := patternkit.StringConstant(decl.Info, pair[1]); ok && namesStatus(pair[0]) {
					stage = strings.ToUpper(text)
				}
			}
			return stage == ""
		})
		return stage == ""
	})
	return stage
}

// blockAssignsName reports a block assigning the variable with =.
func blockAssignsName(block *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && assign.Tok == token.ASSIGN {
			found = found || slices.ContainsFunc(assign.Lhs, func(lhs ast.Expr) bool { return helpers.IsIdentNamed(lhs, name) })
		}
		return !found
	})
	return found
}

// namesStatus reports an expression naming a status: status, p.Status.
func namesStatus(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return statusOrStateName(e.Name)
	case *ast.SelectorExpr:
		return statusOrStateName(e.Sel.Name)
	}
	return false
}

// addConstants records the status constants of a package: string constants
// named for a status or a state, or of such a type.
func (index *stageIndex) addConstants(pkg *types.Package) {
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		c, ok := scope.Lookup(name).(*types.Const)
		if !ok || c.Val().Kind() != constant.String {
			continue
		}
		typeName := ""
		if named, ok := c.Type().(*types.Named); ok {
			typeName = named.Obj().Name()
		}
		if statusOrStateName(name) || statusOrStateName(typeName) {
			index.statuses[strings.ToUpper(constant.StringVal(c.Val()))] = true
		}
	}
}

// statusOrStateName reports a name with the word status or state.
func statusOrStateName(name string) bool {
	return slices.ContainsFunc(helpers.IdentifierWords(name), func(w string) bool { return w == "status" || w == "state" })
}

// bookkeepingStamps are <word>_at columns that record a row's handling, not
// a status it reaches.
var bookkeepingStamps = map[string]bool{
	"updated": true, "created": true, "modified": true, "changed": true, "touched": true, "synced": true,
	"checked": true, "polled": true, "seen": true, "fetched": true, "refreshed": true, "locked": true,
	"leased": true, "claimed": true, "attempted": true, "retried": true, "notified": true, "inserted": true,
}

// stageOf returns the status a <stage>_at column records, upper case, "" for
// another column.
func (index *stageIndex) stageOf(column string) string {
	stem, ok := strings.CutSuffix(column, "_at")
	if !ok || bookkeepingStamps[stem] || !index.statuses[strings.ToUpper(stem)] {
		return ""
	}
	return strings.ToUpper(stem)
}

// boundUpdates returns the UPDATEs a function runs that set a status, with
// the value bound to it when the call running the statement is found.
func boundUpdates(decl patternkit.TypedFuncDecl) []stageWrite {
	queries := namedStrings(decl.Decl)
	var writes []stageWrite
	seen := make(map[ast.Expr]bool)
	ast.Inspect(decl.Decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !runsQuery(call) {
			return true
		}
		for i, arg := range call.Args {
			if ident, ok := arg.(*ast.Ident); ok && queries[ident.Name] != nil {
				arg = queries[ident.Name]
			}
			if !patternkit.IsStringOrConcat(arg) {
				continue
			}
			for _, update := range literalUpdates(arg) {
				seen[arg] = true
				write := stageWrite{update: update, fn: decl}
				if status, ok := update.Assignment("status"); ok && status.Param > 0 && i+status.Param < len(call.Args) {
					write.status = call.Args[i+status.Param]
				}
				writes = append(writes, write)
			}
		}
		return true
	})
	parents := helpers.ParentMap(decl.Decl.Body)
	extended := extendedStrings(decl.Decl.Body)
	for _, literal := range patternkit.SqlLiterals(decl.Decl.Body) {
		if seen[literal.Expr] || !wholeStatement(parents, extended, literal.Expr) {
			continue
		}
		for _, update := range literalUpdates(literal.Expr) {
			writes = append(writes, stageWrite{update: update, fn: decl})
		}
	}
	return writes
}

// runsQuery reports a call that runs the SQL it is handed: a query method,
// or a function named for running one (exec, query).
func runsQuery(call *ast.CallExpr) bool {
	name := helpers.CalleeName(call)
	return queryMethods[name] || slices.ContainsFunc(helpers.IdentifierWords(name), func(w string) bool { return w == "exec" || w == "query" })
}

// extendedStrings returns the names of the variables a body appends to:
// query += ", closed_at = NOW()".
func extendedStrings(body *ast.BlockStmt) map[string]bool {
	extended := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && assign.Tok == token.ADD_ASSIGN {
			if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
				extended[ident.Name] = true
			}
		}
		return true
	})
	return extended
}

// wholeStatement reports a literal that is the statement run as it is: the
// value of a variable nothing appends to, a return value, or an argument of
// a query call; not the start of a statement written into a builder or
// extended later.
func wholeStatement(parents map[ast.Node]ast.Node, extended map[string]bool, expr ast.Expr) bool {
	switch parent := parents[expr].(type) {
	case *ast.AssignStmt:
		for _, lhs := range parent.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && extended[ident.Name] {
				return false
			}
		}
		return parent.Tok != token.ADD_ASSIGN
	case *ast.ValueSpec:
		for _, name := range parent.Names {
			if extended[name.Name] {
				return false
			}
		}
		return true
	case *ast.ReturnStmt:
		return true
	case *ast.CallExpr:
		return runsQuery(parent)
	}
	return false
}

// literalUpdates returns the UPDATEs of a SQL literal or concatenation.
func literalUpdates(expr ast.Expr) []sqlschema.UpdateWrite {
	literals := patternkit.SqlLiterals(expr)
	if len(literals) != 1 {
		return nil
	}
	updates := sqlschema.Updates(literals[0].Text)
	if len(updates) == 0 && literals[0].Bare != "" {
		updates = sqlschema.Updates(literals[0].Bare)
	}
	return updates
}

// mayWrite reports a status write that can set the stage: a literal of it,
// or a value not known to be another status.
func (index *stageIndex) mayWrite(write stageWrite, stage string) bool {
	status, ok := write.update.Assignment("status")
	if !ok {
		return false
	}
	if status.IsLiteral {
		return strings.EqualFold(status.Literal, stage)
	}
	if status.Param == 0 {
		return false
	}
	if write.status == nil {
		return true
	}
	values, known := index.boundValues(write.fn, write.status, 0)
	if !known {
		return true
	}
	return slices.ContainsFunc(values, func(v string) bool { return strings.EqualFold(v, stage) })
}

// maxStatusDepth bounds how far up the callers a status parameter is
// followed.
const maxStatusDepth = 3

// boundValues returns the string constants a value can be: the constant
// itself, or what every caller passes for the parameter it is; known false
// when any of them is not a constant.
func (index *stageIndex) boundValues(fn patternkit.TypedFuncDecl, value ast.Expr, depth int) ([]string, bool) {
	value = patternkit.WithoutConversion(fn.Info, value)
	if text, ok := patternkit.StringConstant(fn.Info, value); ok {
		return []string{text}, true
	}
	ident, ok := value.(*ast.Ident)
	if !ok || depth >= maxStatusDepth {
		return nil, false
	}
	obj, _ := fn.Info.Defs[fn.Decl.Name].(*types.Func)
	params := patternkit.ParamObjects(fn)
	position := slices.IndexFunc(params, func(p *types.Var) bool { return p != nil && fn.Info.Uses[ident] == p })
	if obj == nil || position < 0 {
		return nil, false
	}
	sites := index.calls[obj.Origin()]
	if len(sites) == 0 {
		return nil, false
	}
	var values []string
	for _, site := range sites {
		if position >= len(site.Call.Args) || site.Call.Ellipsis.IsValid() {
			return nil, false
		}
		passed, known := index.boundValues(site.Caller, site.Call.Args[position], depth+1)
		if !known {
			return nil, false
		}
		values = append(values, passed...)
	}
	return values, true
}

// skippedStamps reports the status writes of a function that leave a stamp
// the project keeps for a status they can write, and the reads of a stage by
// its column while such writes exist.
func (index *stageIndex) skippedStamps(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
	decl := patternkit.TypedFuncDecl{Decl: fn, Info: scope.Info}
	var findings []patternkit.FuncFinding
	for _, write := range boundUpdates(decl) {
		if index.stampsAny(write.update) {
			continue // a write that stamps a stage handles the stages it means
		}
		stamps := index.stamps[write.update.Table]
		var skipped []string
		for _, column := range slices.Sorted(maps.Keys(stamps)) {
			if _, ok := write.update.Assignment(column); !ok && index.mayWrite(write, stamps[column]) {
				skipped = append(skipped, column)
			}
		}
		if len(skipped) == 0 {
			continue
		}
		status, ok := write.update.Assignment("status")
		if !ok {
			continue
		}
		findings = append(findings, patternkit.FuncFinding{Node: updateNode(patternkit.SqlLiterals(fn.Body), write.update, status), Message: fmt.Sprintf(
			"This UPDATE of %s can set the status that %s belongs to and leaves %s — another write path sets them together, and rows written here keep it NULL",
			write.update.Table, strings.Join(skipped, ", "), strings.Join(skipped, ", "))})
	}
	for _, literal := range patternkit.SqlLiterals(fn.Body) {
		text := literal.Text
		reads := sqlschema.StageReads(text)
		if len(reads) == 0 && literal.Bare != "" {
			reads = sqlschema.StageReads(literal.Bare)
		}
		for _, read := range reads {
			if writer := index.skippingWriter(read.Table, read.Column, read.Status); writer != "" {
				findings = append(findings, patternkit.FuncFinding{Node: sqlPosNode(literal.PosAt(read.Offset)), Message: fmt.Sprintf(
					"The read takes %s rows by %s while %s sets %s without stamping it — those rows have NULL there and the comparison never matches them",
					read.Status, read.Column, writer, read.Status)})
			}
		}
	}
	return findings
}

// skippingWriter names a function that can set the stage without its
// column, "" for none.
func (index *stageIndex) skippingWriter(table, column, stage string) string {
	for _, write := range index.writes[table] {
		if !index.stampsAny(write.update) && index.mayWrite(write, strings.ToUpper(stage)) {
			return write.fn.Decl.Name.Name
		}
	}
	return ""
}

// stampsAny reports an UPDATE setting a <stage>_at column.
func (index *stageIndex) stampsAny(update sqlschema.UpdateWrite) bool {
	return slices.ContainsFunc(update.Sets, func(set sqlschema.ColumnWrite) bool {
		return index.stageOf(set.Column) != "" || index.stamps[update.Table][set.Column] != ""
	})
}

// eventWords name a function applying repeated events to a row.
var eventWords = map[string]bool{
	"webhook": true, "callback": true, "poll": true, "poller": true, "sync": true, "event": true,
	"notification": true, "notify": true, "observation": true, "reconcile": true, "refresh": true,
}

// overwrittenStamps reports the stage columns a function applying events
// sets straight from a parameter.
func (index *stageIndex) overwrittenStamps(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
	if !slices.ContainsFunc(helpers.IdentifierWords(fn.Name.Name), func(w string) bool { return eventWords[w] }) {
		return nil
	}
	var findings []patternkit.FuncFinding
	literals := patternkit.SqlLiterals(fn.Body)
	for _, write := range boundUpdates(patternkit.TypedFuncDecl{Decl: fn, Info: scope.Info}) {
		for _, set := range write.update.Sets {
			stage := index.stageOf(set.Column)
			if set.Param == 0 || stage == "" || index.stamps[write.update.Table][set.Column] != stage {
				continue
			}
			findings = append(findings, patternkit.FuncFinding{Node: updateNode(literals, write.update, set), Message: fmt.Sprintf(
				"%s is set straight from $%d on every event — a later event of the row (a cancel after %s, a repeat without the time) overwrites the moment it reached %s",
				set.Column, set.Param, stage, stage)})
		}
	}
	return findings
}

// updateNode returns the position of a set of an UPDATE among the function's
// literals.
func updateNode(literals []patternkit.SqlLiteral, update sqlschema.UpdateWrite, set sqlschema.ColumnWrite) ast.Node {
	for _, literal := range literals {
		for _, text := range []string{literal.Text, literal.Bare} {
			if text == "" {
				continue
			}
			for _, candidate := range sqlschema.Updates(text) {
				if candidate.Table == update.Table && slices.Equal(candidate.Columns(), update.Columns()) {
					return sqlPosNode(literal.PosAt(set.Offset))
				}
			}
		}
	}
	return sqlPosNode(token.NoPos)
}

// sqlPosNode is a position inside SQL text, reported as a node.
type sqlPosNode token.Pos

func (p sqlPosNode) Pos() token.Pos { return token.Pos(p) }
func (p sqlPosNode) End() token.Pos { return token.Pos(p) }
