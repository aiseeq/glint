package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSelectThenWriteRaceRule())
}

// SelectThenWriteRaceRule detects a read-validate-write race inside one
// function: a SELECT of a column without FOR UPDATE followed by an UPDATE of
// the same column of the same table. Two concurrent calls read the same value,
// both pass the validation performed between the queries, and the second one
// silently overwrites the first.
//
// Typical case: a status transition reads `status`, runs a state-machine
// check on the value, then writes `status` back. A background job and a manual
// action read the same status concurrently and both pass the validation.
//
// The same race splits an upsert in two: a lookup by a key followed by a
// plain INSERT of that key. Two concurrent webhooks both find no row and both
// insert; INSERT ... ON CONFLICT is the fix.
//
// The rule is silent when the function first takes an advisory or a table
// lock, and when the SELECT locks the row (FOR UPDATE / FOR NO KEY
// UPDATE / FOR SHARE) — that is exactly the fix. A read is serialized too when
// the function earlier locks some row FOR UPDATE with an argument the read
// also passes, through the same handle: concurrent callers for that key queue
// on the parent row, and the second one finds what the first wrote. A lock
// taken through another handle is outside the read's transaction.
//
// Two more forms of the race split the check from the write across calls: a
// worker claims a row by flipping it to running by its key alone, never
// reading RowsAffected, so two workers both take it; and a function loads an
// entity, checks its status in Go and sends a provider command with no claim
// of the row between the check and the send.
type SelectThenWriteRaceRule struct {
	*rules.BaseRule

	selectQuery *regexp.Regexp
	updateQuery *regexp.Regexp
	rowLock     *regexp.Regexp
	// exclusiveLock is a row lock two transactions cannot hold at once;
	// FOR SHARE is held by both and serializes nothing.
	exclusiveLock *regexp.Regexp
	whereClause   *regexp.Regexp
	identifier    *regexp.Regexp
	// quotedText is a single-quoted SQL string: a word inside it is data,
	// not a column.
	quotedText *regexp.Regexp
	// columnReference is a column name, optionally table-qualified.
	columnReference *regexp.Regexp
	// insertQuery is an INSERT with its column list; onConflict marks an
	// upsert.
	insertQuery *regexp.Regexp
	onConflict  *regexp.Regexp
	// keyComparison is a WHERE column compared with a bind parameter.
	keyComparison *regexp.Regexp
	// sessionLock is a blocking advisory lock or a table lock.
	sessionLock *regexp.Regexp
}

// NewSelectThenWriteRaceRule creates the rule.
func NewSelectThenWriteRaceRule() *SelectThenWriteRaceRule {
	return &SelectThenWriteRaceRule{
		BaseRule: rules.NewBaseRule(
			"select-then-write-race",
			"patterns",
			"Detects SELECT without FOR UPDATE followed by an UPDATE of the same column, or by an INSERT of the looked-up key without ON CONFLICT, in one function (read-validate-write race); a claim status set by key alone with RowsAffected unread; a provider command sent after a Go status check with no claim of the row",
			core.SeverityMedium,
		),
		// Anchored at the start of the literal so subqueries inside a larger
		// statement are not mistaken for the read.
		selectQuery:     regexp.MustCompile(`(?is)^\s*SELECT\s+(.+?)\s+FROM\s+([A-Za-z_][A-Za-z0-9_.]*)`),
		updateQuery:     regexp.MustCompile(`(?is)^\s*UPDATE\s+([A-Za-z_][A-Za-z0-9_.]*)\s+SET\s+(.+)`),
		rowLock:         regexp.MustCompile(`(?i)\bFOR\s+(?:NO\s+KEY\s+)?UPDATE\b|\bFOR\s+(?:KEY\s+)?SHARE\b`),
		exclusiveLock:   regexp.MustCompile(`(?i)\bFOR\s+(?:NO\s+KEY\s+)?UPDATE\b`),
		whereClause:     regexp.MustCompile(`(?i)\bWHERE\b`),
		identifier:      regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`),
		quotedText:      regexp.MustCompile(`'(?:[^']|'')*'`),
		columnReference: regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?`),
		insertQuery:     regexp.MustCompile(`(?is)^\s*INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_.]*)\s*\(([^)]*)\)`),
		onConflict:      regexp.MustCompile(`(?i)\bON\s+CONFLICT\b`),
		sessionLock:     regexp.MustCompile(`(?i)\bpg_advisory(?:_xact)?_lock\s*\(|\bLOCK\s+TABLE\b`),
		keyComparison:   regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)\s*=\s*(?:\$\d+|\?)`),
	}
}

// sqlRead is a SELECT literal without a row lock.
type sqlRead struct {
	table   string
	columns map[string]bool
	// keys are the WHERE columns compared with a parameter: what the read
	// looks the row up by.
	keys map[string]bool
	pos  token.Pos
	line int
}

// AnalyzeFile checks the SQL string literals of each function; queries held
// in constants need type information and are read by AnalyzeGoProject.
func (r *SelectThenWriteRaceRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SelectThenWriteRaceRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; with type information a query held in
// a constant (a package const, a concatenation of consts) is read by its value.
func (r *SelectThenWriteRaceRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks each function of the file. info is nil for a file without
// type information: then only string literals written in the function are
// queries, a constant declared elsewhere is unknown.
func (r *SelectThenWriteRaceRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if ctx.GoAST == nil {
		return nil
	}
	sends := unclaimedSendingFunctions(ctx.GoAST)
	return analyzeGoFunctions(ctx, func(fn *ast.FuncDecl) []*core.Violation {
		return append(r.checkFunction(ctx, fn, info), r.sendAfterStatusCheck(ctx, fn, sends)...)
	})
}

// sendingFunctions returns the names of the file's functions that issue a
// provider command (SendPayout, TransferFunds), directly or through another
// function of the file.
func sendingFunctions(file *ast.File) map[string]bool {
	sends := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || sends[fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && sendsCommand(call, sends) {
					sends[fn.Name.Name], changed = true, true
				}
				return !sends[fn.Name.Name]
			})
		}
	}
	return sends
}

// unclaimedSendingFunctions returns the names of the file's functions that
// reach a provider command before anything claims the row: a function that
// claims first (ClaimSendIntent(ctx, tx.ID, tx.Version), a version-checked
// write) serializes its callers itself.
func unclaimedSendingFunctions(file *ast.File) map[string]bool {
	sends := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || sends[fn.Name.Name] {
				continue
			}
			if sendsBeforeClaim(fn.Body, sends) {
				sends[fn.Name.Name], changed = true, true
			}
		}
	}
	return sends
}

// sendsBeforeClaim reports a body whose first claim or send, in source order,
// is a send.
func sendsBeforeClaim(body *ast.BlockStmt, sends map[string]bool) bool {
	decided, sent := false, false
	ast.Inspect(body, func(n ast.Node) bool {
		if decided {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if claimCall.MatchString(calledFunctionName(call.Fun)) || passesVersion(call) {
			decided = true
			return false
		}
		if sendsCommand(call, sends) {
			decided, sent = true, true
			return false
		}
		return true
	})
	return sent
}

// passesVersion reports a call handing on a Version field: an optimistic
// write that fails when the row changed.
func passesVersion(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if sel, ok := arg.(*ast.SelectorExpr); ok && sel.Sel.Name == "Version" {
			return true
		}
	}
	return false
}

// sendsCommand reports a call of a provider command or of a function that
// issues one.
func sendsCommand(call *ast.CallExpr, sends map[string]bool) bool {
	name := calledFunctionName(call.Fun)
	if _, method := call.Fun.(*ast.SelectorExpr); method && providerCommandMethods[name] {
		return true
	}
	return sends[name]
}

// entityLoader is a repository read of one entity.
var entityLoader = regexp.MustCompile(`^(?:Get|Load|Find|Fetch)[A-Z]?\w*$`)

// claimCall is a write that takes the entity conditionally: a claim, a lock,
// a compare-and-set transition.
var claimCall = regexp.MustCompile(`(?i)claim|lock|acquire|reserve|compareandswap|transition`)

// sendAfterStatusCheck reports a provider command sent after a status check of
// an entity loaded by a repository read, with nothing between the check and
// the command that claims the row: two concurrent calls (a double click, a
// retried request) both see the old status, both pass and both send.
func (r *SelectThenWriteRaceRule) sendAfterStatusCheck(ctx *core.FileContext, fn *ast.FuncDecl, sends map[string]bool) []*core.Violation {
	loaded := ""
	var guard ast.Node
	for _, stmt := range fn.Body.List {
		if guard != nil {
			break
		}
		switch stmt := stmt.(type) {
		case *ast.AssignStmt:
			if loaded == "" && len(stmt.Rhs) == 1 && len(stmt.Lhs) >= 1 {
				call, ok := stmt.Rhs[0].(*ast.CallExpr)
				ident, isIdent := stmt.Lhs[0].(*ast.Ident)
				if ok && isIdent && ident.Name != "_" && entityLoader.MatchString(calledFunctionName(call.Fun)) {
					loaded = ident.Name
				}
			}
		case *ast.IfStmt:
			if loaded != "" && checksStatus(stmt.Cond, loaded) && blockBranches(stmt.Body, isReturn) {
				guard = stmt
			}
		}
	}
	if guard == nil {
		return nil
	}
	var send *ast.CallExpr
	claimed := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if send != nil || claimed {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || call.Pos() < guard.End() {
			return true
		}
		if claimCall.MatchString(calledFunctionName(call.Fun)) || passesField(call, loaded, "Version") {
			claimed = true
			return false
		}
		if sendsCommand(call, sends) {
			send = call
		}
		return true
	})
	if send == nil || claimed {
		return nil
	}
	line := lineFromNode(ctx, send)
	if ctx.IsSuppressed(line, r.Name()) {
		return nil
	}
	v := r.CreateViolation(ctx.RelPath, line,
		"'"+loaded+"' is loaded and its status checked in Go, then the provider command is sent with no claim of the row in between — two concurrent calls both pass the check and both send")
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion("Claim the row before the send: UPDATE ... WHERE id = $1 AND status = <checked status> (or version = $2) and refuse when RowsAffected() is 0")
	v.WithContext("pattern", "send-after-status-check")
	v.WithContext("function", fn.Name.Name)
	return []*core.Violation{v}
}

// checksStatus reports a condition comparing the Status or State field of
// the named variable.
func checksStatus(cond ast.Expr, name string) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
			return true
		}
		for _, side := range []ast.Expr{bin.X, bin.Y} {
			if sel, ok := side.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Status" || sel.Sel.Name == "State") {
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == name {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// isReturn reports a return statement.
func isReturn(stmt ast.Stmt) bool {
	_, ok := stmt.(*ast.ReturnStmt)
	return ok
}

// passesField reports a call that passes the named field of a variable.
func passesField(call *ast.CallExpr, name, field string) bool {
	for _, arg := range call.Args {
		if sel, ok := arg.(*ast.SelectorExpr); ok && sel.Sel.Name == field {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == name {
				return true
			}
		}
	}
	return false
}

func (r *SelectThenWriteRaceRule) checkFunction(ctx *core.FileContext, fn *ast.FuncDecl, info *types.Info) []*core.Violation {
	var reads []sqlRead
	var violations []*core.Violation

	// A function that takes an advisory or a table lock first serializes
	// its callers: the read and the write cannot interleave.
	locked := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if expr, ok := n.(ast.Expr); ok && !locked {
			if query, ok := constantString(expr, info); ok && r.sessionLock.MatchString(query) {
				locked = true
			}
		}
		return !locked
	})
	if locked {
		return nil
	}

	arguments := queryArguments(fn, info)
	// lockedKeys are the arguments of earlier exclusive row locks.
	lockedKeys := make(map[string]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		expr, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		query, ok := constantString(expr, info)
		if !ok {
			return true
		}
		if r.selectQuery.MatchString(query) {
			if r.exclusiveLock.MatchString(query) {
				for _, arg := range arguments[expr] {
					lockedKeys[arg] = true
				}
				return false
			}
			if sharesKey(lockedKeys, arguments[expr]) {
				return false
			}
		}
		reads = r.checkQuery(ctx, fn, query, expr, reads, &violations)
		// The whole constant is one query: its operands are not visited again.
		return false
	})
	if len(lockedKeys) == 0 {
		violations = append(violations, r.keyOnlyClaims(ctx, fn, info)...)
	}
	return violations
}

// claimValue is a status that takes a row for one worker: setting it is a
// claim, and only a claim conditional on the current status is exclusive.
var claimValue = regexp.MustCompile(`(?i)^(?:running|processing|in_?progress|claimed|locked|sending|executing)$`)

// claimConstName is a constant naming such a status (JobRunning, StatusProcessing).
var claimConstName = regexp.MustCompile(`(?i)(?:running|processing|inprogress|claimed|locked|sending|executing)$`)

// statusAssignment is the SET of a status column: a literal or a parameter.
var statusAssignment = regexp.MustCompile(`(?i)\bstatus\s*=\s*(?:'(\w+)'|\$(\d+))`)

// keyOnlyClaims reports an UPDATE that sets a claim status (running,
// processing) on a row found by its key alone, in a function that never reads
// RowsAffected: two workers both flip the row and both believe they took it.
// WHERE id = $1 AND status = 'pending' with the affected count read is the
// claim; a lock taken earlier in the function serializes the writers anyway.
func (r *SelectThenWriteRaceRule) keyOnlyClaims(ctx *core.FileContext, fn *ast.FuncDecl, info *types.Info) []*core.Violation {
	if callsSelector(fn.Body, "RowsAffected") {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for i, arg := range call.Args {
			query, ok := constantString(arg, info)
			if !ok {
				continue
			}
			table, columns, guarded, ok := r.parseUpdate(query)
			if !ok || !columns["status"] || len(guarded) != 1 || guarded["status"] {
				break
			}
			m := statusAssignment.FindStringSubmatch(query)
			if m == nil || !r.claims(m, call.Args[i+1:], info) {
				break
			}
			line := lineFromNode(ctx, arg)
			if ctx.IsSuppressed(line, r.Name()) {
				break
			}
			v := r.CreateViolation(ctx.RelPath, line,
				"'"+table+"' is claimed by its key alone and the affected row count is never read — two workers both flip the row to the claim status and both process it")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Claim conditionally: UPDATE ... WHERE id = $1 AND status = <the status the worker expects>, and go on only when RowsAffected() is 1")
			v.WithContext("pattern", "claim-by-key-only")
			v.WithContext("function", fn.Name.Name)
			v.WithContext("table", table)
			violations = append(violations, v)
			break
		}
		return true
	})
	return violations
}

// claims reports a status assignment whose value is a claim status: the
// literal of the SQL or the argument bound to its parameter.
func (r *SelectThenWriteRaceRule) claims(assignment []string, args []ast.Expr, info *types.Info) bool {
	if assignment[1] != "" {
		return claimValue.MatchString(assignment[1])
	}
	index, err := strconv.Atoi(assignment[2])
	if err != nil || index < 1 || index > len(args) {
		return false
	}
	arg := args[index-1]
	if value, ok := constantString(arg, info); ok && info != nil {
		return claimValue.MatchString(value)
	}
	switch arg := arg.(type) {
	case *ast.Ident:
		return claimConstName.MatchString(arg.Name)
	case *ast.SelectorExpr:
		return claimConstName.MatchString(arg.Sel.Name)
	case *ast.CallExpr: // string(StatusRunning)
		return len(arg.Args) == 1 && r.claims([]string{"", "1"}, arg.Args, info)
	}
	return false
}

// callsSelector reports a call of a method or field named name under root.
func callsSelector(root ast.Node, name string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}

// queryArguments maps each query constant passed to a call to the source text
// of the arguments that follow it, the values bound to its parameters, each
// prefixed with the handle the call runs on (tx, r.db).
func queryArguments(fn *ast.FuncDecl, info *types.Info) map[ast.Expr][]string {
	arguments := make(map[ast.Expr][]string)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		handle := ""
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
			handle = types.ExprString(selector.X)
		}
		for i, arg := range call.Args {
			if _, ok := constantString(arg, info); !ok {
				continue
			}
			for _, bound := range call.Args[i+1:] {
				arguments[arg] = append(arguments[arg], handle+" "+types.ExprString(bound))
			}
			break
		}
		return true
	})
	return arguments
}

// sharesKey reports whether a query binds one of the locked arguments.
func sharesKey(lockedKeys map[string]bool, arguments []string) bool {
	for _, arg := range arguments {
		if lockedKeys[arg] {
			return true
		}
	}
	return false
}

// constantString returns the string value of a constant expression: with type
// information any constant (literal, named const, concatenation), without it
// only a string literal.
func constantString(expr ast.Expr, info *types.Info) (string, bool) {
	if info != nil {
		value := info.Types[expr].Value
		if value == nil || value.Kind() != constant.String {
			return "", false
		}
		return constant.StringVal(value), true
	}
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	// A string literal the parser accepted always unquotes; one that does not
	// is not a query, so skipping it is the success path, not a masked failure.
	query, err := strconv.Unquote(lit.Value)
	return query, err == nil
}

// checkQuery classifies one SQL string, extending the list of unlocked reads
// or reporting a read-then-write pair.
func (r *SelectThenWriteRaceRule) checkQuery(ctx *core.FileContext, fn *ast.FuncDecl, query string, node ast.Expr, reads []sqlRead, violations *[]*core.Violation) []sqlRead {
	if read, ok := r.parseSelect(query, node, ctx); ok {
		return append(reads, read)
	}

	if table, columns, ok := r.parseInsert(query); ok {
		r.checkInsert(ctx, fn, node, table, columns, reads, violations)
		return reads
	}

	table, columns, guarded, ok := r.parseUpdate(query)
	if ok {
		for _, prior := range reads {
			if prior.table != table || prior.pos >= node.Pos() {
				continue
			}
			shared := intersectColumn(prior.columns, columns, guarded)
			if shared == "" {
				continue
			}
			line := lineFromNode(ctx, node)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line,
				"'"+table+"."+shared+"' is read without FOR UPDATE (line "+strconv.Itoa(prior.line)+") and then written back — concurrent calls read the same value and both pass the validation")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Lock the row with SELECT ... FOR UPDATE inside a transaction, or collapse the check into one conditional UPDATE ... WHERE " + shared + " IN (...)")
			v.WithContext("pattern", "select-then-write-race")
			v.WithContext("function", fn.Name.Name)
			v.WithContext("table", table)
			v.WithContext("column", shared)
			v.WithContext("select_line", prior.line)
			*violations = append(*violations, v)
			break
		}
	}
	return reads
}

// checkInsert reports an INSERT of a key that an earlier read of the same
// table looked up: the read-then-insert pair is an upsert split in two, and
// two concurrent calls both find no row and both insert.
func (r *SelectThenWriteRaceRule) checkInsert(ctx *core.FileContext, fn *ast.FuncDecl, node ast.Expr, table string, columns map[string]bool, reads []sqlRead, violations *[]*core.Violation) {
	for _, prior := range reads {
		if prior.table != table || prior.pos >= node.Pos() {
			continue
		}
		key := intersectColumn(prior.keys, columns, nil)
		if key == "" {
			continue
		}
		line := lineFromNode(ctx, node)
		if ctx.IsSuppressed(line, r.Name()) {
			return
		}
		v := r.CreateViolation(ctx.RelPath, line,
			"'"+table+"' is looked up by "+key+" (line "+strconv.Itoa(prior.line)+") and then inserted without ON CONFLICT — two concurrent calls both find no row and both insert")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Make it one statement: INSERT ... ON CONFLICT (" + key + ") DO UPDATE/NOTHING, with a unique index on " + key)
		v.WithContext("pattern", "select-then-insert-race")
		v.WithContext("function", fn.Name.Name)
		v.WithContext("table", table)
		v.WithContext("column", key)
		v.WithContext("select_line", prior.line)
		*violations = append(*violations, v)
		return
	}
}

// parseInsert recognizes a plain INSERT with a column list; an upsert (ON
// CONFLICT) is the fix and is not returned.
func (r *SelectThenWriteRaceRule) parseInsert(query string) (string, map[string]bool, bool) {
	match := r.insertQuery.FindStringSubmatch(query)
	if match == nil || r.onConflict.MatchString(query) {
		return "", nil, false
	}
	columns := r.columnSet(match[2])
	return strings.ToLower(match[1]), columns, len(columns) > 0
}

// whereKeys returns the columns the WHERE clause compares with a parameter.
func (r *SelectThenWriteRaceRule) whereKeys(query string) map[string]bool {
	keys := make(map[string]bool)
	loc := r.whereClause.FindStringIndex(query)
	if loc == nil {
		return keys
	}
	for _, m := range r.keyComparison.FindAllStringSubmatch(query[loc[1]:], -1) {
		if column, ok := r.columnName(m[1]); ok {
			keys[column] = true
		}
	}
	return keys
}

// parseSelect recognizes a SELECT literal that reads concrete columns or
// looks a row up by a parameter, and does not lock the row. SELECT * alone
// is ignored: without an explicit column list the read-modify-write link
// cannot be proven and the rule prefers precision.
func (r *SelectThenWriteRaceRule) parseSelect(query string, lit ast.Expr, ctx *core.FileContext) (sqlRead, bool) {
	match := r.selectQuery.FindStringSubmatch(query)
	if match == nil || r.rowLock.MatchString(query) {
		return sqlRead{}, false
	}
	columns := r.columnSet(match[1])
	keys := r.whereKeys(query)
	if len(columns) == 0 && len(keys) == 0 {
		return sqlRead{}, false
	}
	return sqlRead{
		table:   strings.ToLower(match[2]),
		columns: columns,
		keys:    keys,
		pos:     lit.Pos(),
		line:    lineFromNode(ctx, lit),
	}, true
}

// parseUpdate recognizes an UPDATE literal and returns the SET column set and
// the columns its WHERE clause compares. A column the WHERE compares is a
// compare-and-set: a concurrent change makes the UPDATE match no row instead
// of overwriting it.
func (r *SelectThenWriteRaceRule) parseUpdate(query string) (string, map[string]bool, map[string]bool, bool) {
	match := r.updateQuery.FindStringSubmatch(query)
	if match == nil {
		return "", nil, nil, false
	}
	setClause := match[2]
	guarded := make(map[string]bool)
	if loc := r.whereClause.FindStringIndex(setClause); loc != nil {
		where := r.quotedText.ReplaceAllString(setClause[loc[1]:], "''")
		for _, reference := range r.columnReference.FindAllString(where, -1) {
			if column, ok := r.columnName(reference); ok {
				guarded[column] = true
			}
		}
		setClause = setClause[:loc[0]]
	}
	columns := make(map[string]bool)
	for _, assignment := range strings.Split(setClause, ",") {
		name, _, found := strings.Cut(assignment, "=")
		if !found {
			continue
		}
		if column, ok := r.columnName(name); ok {
			columns[column] = true
		}
	}
	if len(columns) == 0 {
		return "", nil, nil, false
	}
	return strings.ToLower(match[1]), columns, guarded, true
}

// columnSet parses a SELECT list into simple column names. Expressions,
// aggregates, and * are dropped: only a plainly named column proves that the
// later UPDATE rewrites what was read.
func (r *SelectThenWriteRaceRule) columnSet(selectList string) map[string]bool {
	columns := make(map[string]bool)
	for _, item := range strings.Split(selectList, ",") {
		if column, ok := r.columnName(item); ok {
			columns[column] = true
		}
	}
	return columns
}

// columnName normalizes one column reference ("status", "t.status") to its
// bare lowercase name, rejecting anything that is not a plain identifier.
func (r *SelectThenWriteRaceRule) columnName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		name = name[dot+1:]
	}
	if !r.identifier.MatchString(name) {
		return "", false
	}
	return strings.ToLower(name), true
}

// intersectColumn returns the alphabetically first column that is read and
// written back without the UPDATE comparing it, so the reported column does
// not depend on map iteration order.
func intersectColumn(read, written, guarded map[string]bool) string {
	shared := ""
	for column := range read {
		if !written[column] || guarded[column] {
			continue
		}
		if shared == "" || column < shared {
			shared = column
		}
	}
	return shared
}
