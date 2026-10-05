package patterns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
func NewStatusWriteSkipsStageTimestampRule() *typedFuncRule {
	rule := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"status-write-skips-stage-timestamp",
			"patterns",
			"Detects an UPDATE that can set a status without the <status>_at column another write path sets with it, and a read selecting that status by the column — the rows written here keep it NULL",
			core.SeverityMedium,
		),
		suggestion: "Stamp the column wherever the status is written (CASE WHEN $n = 'COMPLETED' AND completed_at IS NULL THEN NOW() ELSE completed_at END), or select by a column every path sets",
	}
	rule.forProject = func(decls map[*types.Func]typedFuncDecl) func(funcScope, *ast.FuncDecl) []funcFinding {
		index := newStageIndex(decls)
		return index.skippedStamps
	}
	return rule
}

// NewTerminalTimestampOverwrittenRule creates the rule that detects a
// <stage>_at column set straight from a parameter in a function applying
// repeated events:
//
//	func (r *Repo) UpdateFromWebhook(ctx context.Context, id uuid.UUID, status string, completedAt *time.Time) error {
//		_, err := r.db.Exec(ctx, `UPDATE transfers SET status = $1, completed_at = $2 WHERE id = $3`, status, completedAt, id)
//
// The next event of the same row - a cancel after completion, a repeated
// callback with no time - writes its own value over the moment the stage was
// reached, often NULL. COALESCE(completed_at, $2), or a CASE keeping a set
// value, records the stage once.
func NewTerminalTimestampOverwrittenRule() *typedFuncRule {
	rule := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"terminal-timestamp-overwritten-on-later-update",
			"patterns",
			"Detects a <status>_at column set straight from a parameter by a webhook, poll or sync write — the next event of the row overwrites the moment the status was reached",
			core.SeverityMedium,
		),
		suggestion: "Keep a value once set: completed_at = COALESCE(completed_at, $n), or CASE WHEN completed_at IS NULL THEN $n ELSE completed_at END",
	}
	rule.forProject = func(decls map[*types.Func]typedFuncDecl) func(funcScope, *ast.FuncDecl) []funcFinding {
		index := newStageIndex(decls)
		return index.overwrittenStamps
	}
	return rule
}

// stageWrite is an UPDATE of the project that sets the status of a table.
type stageWrite struct {
	update sqlschema.UpdateWrite
	fn     typedFuncDecl
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
	calls map[*types.Func][]funcCallSite
}

func newStageIndex(decls map[*types.Func]typedFuncDecl) *stageIndex {
	index := &stageIndex{
		statuses: make(map[string]bool),
		stamps:   make(map[string]map[string]string),
		writes:   make(map[string][]stageWrite),
		calls:    make(map[*types.Func][]funcCallSite),
	}
	packages := make(map[*types.Package]bool)
	for fn, decl := range decls {
		if fn.Pkg() != nil && !packages[fn.Pkg()] {
			packages[fn.Pkg()] = true
			index.addConstants(fn.Pkg())
		}
		ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if callee := staticFunc(decl.info, call); callee != nil {
					index.calls[callee.Origin()] = append(index.calls[callee.Origin()], funcCallSite{call: call, caller: decl})
				}
			}
			return true
		})
		for _, bound := range boundUpdates(decl) {
			if _, ok := bound.update.Assignment("status"); ok {
				index.writes[bound.update.Table] = append(index.writes[bound.update.Table], bound)
			}
		}
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
func boundUpdates(decl typedFuncDecl) []stageWrite {
	queries := namedStrings(decl.decl)
	var writes []stageWrite
	seen := make(map[ast.Expr]bool)
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !runsQuery(call) {
			return true
		}
		for i, arg := range call.Args {
			if ident, ok := arg.(*ast.Ident); ok && queries[ident.Name] != nil {
				arg = queries[ident.Name]
			}
			if !isStringOrConcat(arg) {
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
	parents := helpers.ParentMap(decl.decl.Body)
	extended := extendedStrings(decl.decl.Body)
	for _, literal := range sqlLiterals(decl.decl.Body) {
		if seen[literal.expr] || !wholeStatement(parents, extended, literal.expr) {
			continue
		}
		for _, update := range literalUpdates(literal.expr) {
			writes = append(writes, stageWrite{update: update, fn: decl})
		}
	}
	return writes
}

// runsQuery reports a call that runs the SQL it is handed: a query method,
// or a function named for running one (exec, query).
func runsQuery(call *ast.CallExpr) bool {
	name := callName(call)
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
	literals := sqlLiterals(expr)
	if len(literals) != 1 {
		return nil
	}
	updates := sqlschema.Updates(literals[0].text)
	if len(updates) == 0 && literals[0].bare != "" {
		updates = sqlschema.Updates(literals[0].bare)
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
func (index *stageIndex) boundValues(fn typedFuncDecl, value ast.Expr, depth int) ([]string, bool) {
	value = ast.Unparen(value)
	if conv, ok := value.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if tv, ok := fn.info.Types[conv.Fun]; ok && tv.IsType() {
			value = ast.Unparen(conv.Args[0])
		}
	}
	if text, ok := stringConstant(fn.info, value); ok {
		return []string{text}, true
	}
	ident, ok := value.(*ast.Ident)
	if !ok || depth >= maxStatusDepth {
		return nil, false
	}
	obj, _ := fn.info.Defs[fn.decl.Name].(*types.Func)
	params := paramObjects(fn)
	position := slices.IndexFunc(params, func(p *types.Var) bool { return p != nil && fn.info.Uses[ident] == p })
	if obj == nil || position < 0 {
		return nil, false
	}
	sites := index.calls[obj.Origin()]
	if len(sites) == 0 {
		return nil, false
	}
	var values []string
	for _, site := range sites {
		if position >= len(site.call.Args) || site.call.Ellipsis.IsValid() {
			return nil, false
		}
		passed, known := index.boundValues(site.caller, site.call.Args[position], depth+1)
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
func (index *stageIndex) skippedStamps(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	decl := typedFuncDecl{decl: fn, info: scope.info}
	var findings []funcFinding
	for _, write := range boundUpdates(decl) {
		if index.stampsAny(write.update) {
			continue // a write that stamps a stage handles the stages it means
		}
		stamps := index.stamps[write.update.Table]
		var skipped []string
		for _, column := range sortedKeys(stamps) {
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
		findings = append(findings, funcFinding{node: updateNode(sqlLiterals(fn.Body), write.update, status), message: fmt.Sprintf(
			"This UPDATE of %s can set the status that %s belongs to and leaves %s — another write path sets them together, and rows written here keep it NULL",
			write.update.Table, strings.Join(skipped, ", "), strings.Join(skipped, ", "))})
	}
	for _, literal := range sqlLiterals(fn.Body) {
		text := literal.text
		reads := sqlschema.StageReads(text)
		if len(reads) == 0 && literal.bare != "" {
			reads = sqlschema.StageReads(literal.bare)
		}
		for _, read := range reads {
			if writer := index.skippingWriter(read.Table, read.Column, read.Status); writer != "" {
				findings = append(findings, funcFinding{node: sqlPosNode(literal.posAt(read.Offset)), message: fmt.Sprintf(
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
			return write.fn.decl.Name.Name
		}
	}
	return ""
}

// stampsAny reports an UPDATE setting a <stage>_at column.
func (index *stageIndex) stampsAny(update sqlschema.UpdateWrite) bool {
	return slices.ContainsFunc(update.Sets, func(set sqlschema.ColumnWrite) bool { return index.stageOf(set.Column) != "" })
}

// eventWords name a function applying repeated events to a row.
var eventWords = map[string]bool{
	"webhook": true, "callback": true, "poll": true, "poller": true, "sync": true, "event": true,
	"notification": true, "notify": true, "observation": true, "reconcile": true, "refresh": true,
}

// overwrittenStamps reports the stage columns a function applying events
// sets straight from a parameter.
func (index *stageIndex) overwrittenStamps(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	if !slices.ContainsFunc(helpers.IdentifierWords(fn.Name.Name), func(w string) bool { return eventWords[w] }) {
		return nil
	}
	var findings []funcFinding
	literals := sqlLiterals(fn.Body)
	for _, write := range boundUpdates(typedFuncDecl{decl: fn, info: scope.info}) {
		for _, set := range write.update.Sets {
			stage := index.stageOf(set.Column)
			if set.Param == 0 || stage == "" || index.stamps[write.update.Table][set.Column] != stage {
				continue
			}
			findings = append(findings, funcFinding{node: updateNode(literals, write.update, set), message: fmt.Sprintf(
				"%s is set straight from $%d on every event — a later event of the row (a cancel after %s, a repeat without the time) overwrites the moment it reached %s",
				set.Column, set.Param, stage, stage)})
		}
	}
	return findings
}

// updateNode returns the position of a set of an UPDATE among the function's
// literals.
func updateNode(literals []sqlLiteral, update sqlschema.UpdateWrite, set sqlschema.ColumnWrite) ast.Node {
	for _, literal := range literals {
		for _, text := range []string{literal.text, literal.bare} {
			if text == "" {
				continue
			}
			for _, candidate := range sqlschema.Updates(text) {
				if candidate.Table == update.Table && slices.Equal(columnsOf(candidate), columnsOf(update)) {
					return sqlPosNode(literal.posAt(set.Offset))
				}
			}
		}
	}
	return sqlPosNode(token.NoPos)
}

func columnsOf(update sqlschema.UpdateWrite) []string {
	columns := make([]string, len(update.Sets))
	for i, set := range update.Sets {
		columns[i] = set.Column
	}
	return columns
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// sqlPosNode is a position inside SQL text, reported as a node.
type sqlPosNode token.Pos

func (p sqlPosNode) Pos() token.Pos { return token.Pos(p) }
func (p sqlPosNode) End() token.Pos { return token.Pos(p) }

// posAt returns the source position of an offset in the text: exact in a raw
// string, the literal's own position in an interpreted one.
func (l sqlLiteral) posAt(offset int) token.Pos {
	for _, piece := range l.pieces {
		if offset < piece.start || offset >= piece.end {
			continue
		}
		if piece.raw {
			return piece.pos + 1 + token.Pos(offset-piece.start)
		}
		return piece.pos
	}
	if len(l.pieces) == 0 {
		return token.NoPos
	}
	return l.pieces[0].pos
}
