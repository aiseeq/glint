package sqlschema

import (
	"regexp"
	"slices"
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
)

// Trigger timing and event bits of CREATE TRIGGER (pg_trigger.tgtype).
const (
	triggerBefore = 1 << 1
	triggerUpdate = 1 << 4
)

// stampAssignment is a trigger function's assignment of the current time to
// a column of the new row: NEW.updated_at = NOW().
var stampAssignment = regexp.MustCompile(`(?i)\bNEW\.(\w+)\s*:?=\s*(?:now\s*\(\s*\)|current_timestamp|localtimestamp|clock_timestamp\s*\(\s*\)|statement_timestamp\s*\(\s*\)|transaction_timestamp\s*\(\s*\))`)

// stampFunc is a trigger function's stamp: the column and whether an IF
// guards the assignment.
type stampFunc struct {
	column      string
	conditional bool
}

// plpgsqlIf and plpgsqlEndIf open and close a PL/pgSQL IF block; IF EXISTS
// of a DDL statement is not one.
var (
	plpgsqlIf    = regexp.MustCompile(`(?i)\b(?:ELS)?IF\b(?:\s+NOT)?(?:\s+EXISTS\b)?`)
	plpgsqlEndIf = regexp.MustCompile(`(?i)\bEND\s+IF\b`)
)

// insideIf reports an offset of a PL/pgSQL body inside an IF block.
func insideIf(body string, offset int) bool {
	before := plpgsqlEndIf.ReplaceAllString(body[:offset], " ENDIF ")
	depth := 0
	for _, m := range plpgsqlIf.FindAllString(before, -1) {
		if strings.HasSuffix(strings.ToUpper(m), "EXISTS") || strings.HasPrefix(strings.ToUpper(m), "ELSIF") {
			continue
		}
		depth++
	}
	return depth > strings.Count(before, " ENDIF ")
}

// function records a trigger function that stamps a column of the new row.
func (s *Schema) function(stmt *pgquery.CreateFunctionStmt) {
	name := qualifiedName(stmt.GetFuncname())
	for _, option := range stmt.GetOptions() {
		def := option.GetDefElem()
		if def == nil || def.GetDefname() != "as" {
			continue
		}
		for _, item := range def.GetArg().GetList().GetItems() {
			body := item.GetString_().GetSval()
			if m := stampAssignment.FindStringSubmatchIndex(body); m != nil {
				if s.stampFuncs == nil {
					s.stampFuncs = make(map[string]stampFunc)
				}
				s.stampFuncs[name] = stampFunc{column: strings.ToLower(body[m[2]:m[3]]), conditional: insideIf(body, m[0])}
				return
			}
		}
	}
	delete(s.stampFuncs, name)
}

// trigger marks the table of a BEFORE UPDATE trigger whose function stamps a
// column of the new row.
func (s *Schema) trigger(stmt *pgquery.CreateTrigStmt) {
	stamp, ok := s.stampFuncs[qualifiedName(stmt.GetFuncname())]
	if !ok || stmt.GetTiming()&triggerBefore == 0 || stmt.GetEvents()&triggerUpdate == 0 {
		return
	}
	if table := s.Table(stmt.GetRelation().GetRelname()); table != nil {
		table.stamped, table.stampConditional = stamp.column, stamp.conditional
	}
}

// qualifiedName returns the last part of a dotted name, lower case.
func qualifiedName(parts []*pgquery.Node) string {
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-1].GetString_().GetSval())
}

// StampedOnUpdate returns the column a trigger sets to the current time on
// every UPDATE of a row of the table, "" for none: whatever value the UPDATE
// writes there, the row comes out stamped with the time of the write.
func (t *Table) StampedOnUpdate() string { return t.stamped }

// AnyStampedOnUpdate reports a table of the schema whose rows a trigger
// stamps on every UPDATE.
func (s *Schema) AnyStampedOnUpdate() bool {
	if s == nil {
		return false
	}
	for _, table := range s.tables {
		if table.stamped != "" {
			return true
		}
	}
	return false
}

// UpdatedTables returns the tables the UPDATEs of a statement write,
// common table expressions included.
func UpdatedTables(sql string) []string {
	result, _, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var tables []string
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			if update, ok := m.(*pgquery.UpdateStmt); ok {
				tables = append(tables, strings.ToLower(update.GetRelation().GetRelname()))
			}
		})
	}
	slices.Sort(tables)
	return slices.Compact(tables)
}

// StampOverwrite is an UPDATE that writes its own value into the column a
// BEFORE UPDATE trigger stamps with the current time: the trigger replaces it.
type StampOverwrite struct {
	Table, Column string
}

// StampOverwrites returns the assignments of a statement's UPDATEs to a
// column stamped on every update with a value other than the current time.
// A stamp under an IF is left out: the write may leave its condition false.
func (s *Schema) StampOverwrites(sql string) []StampOverwrite {
	if s == nil {
		return nil
	}
	result, _, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var overwrites []StampOverwrite
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			update, ok := m.(*pgquery.UpdateStmt)
			if !ok {
				return
			}
			table := s.Table(update.GetRelation().GetRelname())
			if table == nil || table.stamped == "" || table.stampConditional {
				return
			}
			for _, target := range update.GetTargetList() {
				res := target.GetResTarget()
				if strings.EqualFold(res.GetName(), table.stamped) && !isCurrentTime(res.GetVal()) {
					overwrites = append(overwrites, StampOverwrite{Table: table.Name, Column: table.stamped})
				}
			}
		})
	}
	return overwrites
}

// isCurrentTime reports NOW(), CURRENT_TIMESTAMP and their kin: the value the
// trigger writes anyway.
func isCurrentTime(node *pgquery.Node) bool {
	if node.GetSqlvalueFunction() != nil {
		return true
	}
	call := node.GetFuncCall()
	return call != nil && len(call.GetArgs()) == 0 &&
		currentTimeFunc.MatchString(qualifiedName(call.GetFuncname()))
}

var currentTimeFunc = regexp.MustCompile(`^(?:now|clock_timestamp|statement_timestamp|transaction_timestamp)$`)

// voidStatus is a status value that takes a row out of the books: a
// reversed, cancelled or voided record.
var voidStatus = regexp.MustCompile(`(?i)^(?:reversed|reverted|cancell?ed|void|voided|rolled_?back)$`)

// StatusExclusion is a filter that leaves out the rows of a table with void
// status values: status <> 'reversed', status NOT IN ('void', 'cancelled').
type StatusExclusion struct {
	Table, Column string
	Values        []string
}

// StatusExclusions returns the filters of a statement's SELECTs and UPDATEs
// that leave out rows of a table by void status values.
func (s *Schema) StatusExclusions(sql string) []StatusExclusion {
	result, _, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var exclusions []StatusExclusion
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			var where *pgquery.Node
			var tables map[string]string
			switch stmt := m.(type) {
			case *pgquery.SelectStmt:
				where, tables = stmt.GetWhereClause(), levelTables(stmt.GetFromClause())
			case *pgquery.UpdateStmt:
				where, tables = stmt.GetWhereClause(), levelTables([]*pgquery.Node{{Node: &pgquery.Node_RangeVar{RangeVar: stmt.GetRelation()}}})
			default:
				return
			}
			if where == nil || len(tables) == 0 {
				return
			}
			levelExpressions(where, func(expr *pgquery.A_Expr) {
				if exclusion, ok := voidExclusion(expr, tables); ok {
					exclusions = append(exclusions, exclusion)
				}
			})
		})
	}
	return exclusions
}

// voidExclusion reads col <> 'void-value' and col NOT IN ('void-value', ...).
func voidExclusion(expr *pgquery.A_Expr, tables map[string]string) (StatusExclusion, bool) {
	if len(expr.GetName()) != 1 {
		return StatusExclusion{}, false
	}
	op := expr.GetName()[0].GetString_().GetSval()
	var values []string
	switch {
	case expr.GetKind() == pgquery.A_Expr_Kind_AEXPR_OP && (op == "<>" || op == "!="):
		if v, ok := stringConst(expr.GetRexpr()); ok {
			values = []string{v}
		}
	case expr.GetKind() == pgquery.A_Expr_Kind_AEXPR_IN && op == "<>":
		for _, item := range expr.GetRexpr().GetList().GetItems() {
			if v, ok := stringConst(item); ok {
				values = append(values, v)
			}
		}
	}
	var void []string
	for _, v := range values {
		if voidStatus.MatchString(v) {
			void = append(void, v)
		}
	}
	ref, ok := columnOf(expr.GetLexpr())
	if !ok || len(void) == 0 {
		return StatusExclusion{}, false
	}
	table, ok := tables[ref.qualifier]
	if !ok || table == "" {
		return StatusExclusion{}, false
	}
	return StatusExclusion{Table: table, Column: ref.name, Values: void}, true
}

// stringConst returns the value of a string constant, through casts.
func stringConst(node *pgquery.Node) (string, bool) {
	node = unCast(node)
	if c := node.GetAConst(); c != nil && c.GetSval() != nil {
		return c.GetSval().GetSval(), true
	}
	return "", false
}

// ChildRead is a read of a child table's rows that never looks at the parent
// row they belong to.
type ChildRead struct {
	Child, Column, Parent string
	Offset                int
}

// ChildReadsWithoutParent returns the reads of a statement's totals (a sum,
// an average) from a table whose rows always reference (a NOT NULL key) a
// parent the voided set names - a table some rows of which the project
// leaves out by status - when the statement never reads the parent: rows of
// a reversed parent count as live ones. A read of the children of given
// parents (child.parent_id = $1, IN, ANY) is left out: the caller chose them.
func (s *Schema) ChildReadsWithoutParent(sql string, voided map[string]bool) []ChildRead {
	if s == nil || len(voided) == 0 {
		return nil
	}
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var reads []ChildRead
	for _, raw := range result.GetStmts() {
		stmt := raw.GetStmt()
		mentioned := relations(stmt)
		walk(stmt.ProtoReflect(), func(m proto.Message) {
			sel, ok := m.(*pgquery.SelectStmt)
			if !ok {
				return
			}
			if !totals(sel) {
				return
			}
			pinned := chosenColumns(sel.GetWhereClause())
			for _, item := range sel.GetFromClause() {
				rv := item.GetRangeVar()
				if rv == nil {
					continue
				}
				child := s.relation(rv, nil)
				if child == nil {
					continue
				}
				for _, column := range child.columns {
					parent := column.References
					// A nullable reference (a position opened by a transaction)
					// does not make the row a part of its parent.
					if parent == "" || !column.NotNull || !voided[parent] || mentioned[parent] || pinned[column.Name] || parent == child.Name {
						continue
					}
					reads = append(reads, ChildRead{Child: child.Name, Column: column.Name, Parent: parent, Offset: int(rv.GetLocation()) - shift})
				}
			}
		})
	}
	return reads
}

// totals reports a SELECT that sums its rows' amounts up: a sum or an
// average among its columns. A list, a count or an existence check of child
// rows answers another question than a total: a notice of a cancellation is
// still a row to count.
func totals(sel *pgquery.SelectStmt) bool {
	found := false
	for _, target := range sel.GetTargetList() {
		walk(target.ProtoReflect(), func(m proto.Message) {
			if call, ok := m.(*pgquery.FuncCall); ok {
				names := call.GetFuncname()
				name := strings.ToLower(names[len(names)-1].GetString_().GetSval())
				found = found || name == "sum" || name == "avg"
			}
		})
	}
	return found
}

// chosenColumns returns the names of the columns the AND terms of a condition
// match to given values: col = $1, col IN ($1, $2), col = ANY($1).
func chosenColumns(where *pgquery.Node) map[string]bool {
	chosen := make(map[string]bool)
	for _, ref := range pinnedColumns(where) {
		chosen[ref.name] = true
	}
	terms := []*pgquery.Node{where}
	if b := where.GetBoolExpr(); b != nil && b.GetBoolop() == pgquery.BoolExprType_AND_EXPR {
		terms = b.GetArgs()
	}
	for _, term := range terms {
		expr := term.GetAExpr()
		if expr == nil || len(expr.GetName()) != 1 || expr.GetName()[0].GetString_().GetSval() != "=" {
			continue
		}
		if kind := expr.GetKind(); kind != pgquery.A_Expr_Kind_AEXPR_IN && kind != pgquery.A_Expr_Kind_AEXPR_OP_ANY {
			continue
		}
		if ref, ok := columnOf(expr.GetLexpr()); ok {
			chosen[ref.name] = true
		}
	}
	return chosen
}

// nullifiedStatus is a status value of a record that never took effect: a
// refused, cancelled or failed payment moved no money.
var nullifiedStatus = regexp.MustCompile(`(?i)^(?:cancell?ed|rejected|declined|failed|error|void|voided|reversed|reverted|refunded|rolled_?back)$`)

// moneyColumn names a column holding an amount.
var moneyColumn = regexp.MustCompile(`(?i)amount|fee|price|cost|volume|revenue|turnover|balance|_usd|_eur|_rub`)

// UnfilteredSums returns the offsets of the SUMs of money of a SELECT that
// take rows of every status while other aggregates of the same SELECT filter
// theirs by a status the project gives records that never took effect
// (COUNT(*) FILTER (WHERE status = 'rejected'), ... NOT IN ('CANCELLED')):
// the turnover beside them still includes refused and cancelled rows. A
// filter by a lifecycle status alone (active, closed) says nothing of the
// sum; a column summed both with and without a filter is a deliberate total;
// a sum that looks at the status itself (SUM(CASE WHEN status ...)) and a
// WHERE on the status narrow it already.
func UnfilteredSums(sql string) []int {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var offsets []int
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			sel, ok := m.(*pgquery.SelectStmt)
			if !ok || len(sel.GetTargetList()) == 0 {
				return
			}
			filteredBy := ""
			filteredArgs := make(map[string]bool)
			var bare []*pgquery.FuncCall
			for _, target := range sel.GetTargetList() {
				walk(target.ProtoReflect(), func(m proto.Message) {
					call, ok := m.(*pgquery.FuncCall)
					if !ok {
						return
					}
					sum := funcName(call) == "sum"
					if filter := call.GetAggFilter(); filter != nil {
						if column := statusColumn(filter); column != "" && namesNullified(filter) {
							filteredBy = column
						}
						if sum {
							filteredArgs[argColumns(call)] = true
						}
						return
					}
					if sum {
						bare = append(bare, call)
					}
				})
			}
			if filteredBy == "" || statusColumn(sel.GetWhereClause()) == filteredBy {
				return
			}
			for _, call := range bare {
				args := argColumns(call)
				if !filteredArgs[args] && moneyColumn.MatchString(args) && !strings.Contains(args, "status") {
					offsets = append(offsets, int(call.GetLocation())-shift)
				}
			}
		})
	}
	return offsets
}

// funcName returns the lower-case unqualified name of a called function.
func funcName(call *pgquery.FuncCall) string {
	names := call.GetFuncname()
	if len(names) == 0 {
		return ""
	}
	return strings.ToLower(names[len(names)-1].GetString_().GetSval())
}

// argColumns names the columns a call's arguments read, to tell SUM(amount)
// from SUM(fee).
func argColumns(call *pgquery.FuncCall) string {
	var names []string
	for _, arg := range call.GetArgs() {
		walk(arg.ProtoReflect(), func(m proto.Message) {
			if ref, ok := m.(*pgquery.ColumnRef); ok {
				names = append(names, refName(&pgquery.Node{Node: &pgquery.Node_ColumnRef{ColumnRef: ref}}))
			}
		})
	}
	return strings.Join(names, ",")
}

// namesNullified reports a condition holding a string constant that is a
// status of a record that never took effect.
func namesNullified(cond *pgquery.Node) bool {
	found := false
	walk(cond.ProtoReflect(), func(m proto.Message) {
		if c, ok := m.(*pgquery.A_Const); ok && c.GetSval() != nil && nullifiedStatus.MatchString(c.GetSval().GetSval()) {
			found = true
		}
	})
	return found
}

// statusColumn returns the name of a status column a condition compares, or
// "" when it compares none.
func statusColumn(cond *pgquery.Node) string {
	if cond == nil {
		return ""
	}
	found := ""
	walk(cond.ProtoReflect(), func(m proto.Message) {
		expr, ok := m.(*pgquery.A_Expr)
		if !ok || found != "" {
			return
		}
		if ref, ok := columnOf(expr.GetLexpr()); ok && strings.Contains(ref.name, "status") {
			found = ref.name
		}
	})
	return found
}

// relations returns the names of the tables a statement reads or writes.
func relations(stmt *pgquery.Node) map[string]bool {
	names := make(map[string]bool)
	walk(stmt.ProtoReflect(), func(m proto.Message) {
		if rv, ok := m.(*pgquery.RangeVar); ok {
			names[strings.ToLower(rv.GetRelname())] = true
		}
	})
	return names
}

// DeltaExports returns the tables a statement's SELECTs read by a change
// time: WHERE updated_at > $1 (or >=), the read of a delta transfer that
// sees what changed since the last one.
func DeltaExports(sql string) []string {
	result, _, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var tables []string
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			sel, ok := m.(*pgquery.SelectStmt)
			if !ok || sel.GetWhereClause() == nil {
				return
			}
			level := levelTables(sel.GetFromClause())
			levelExpressions(sel.GetWhereClause(), func(expr *pgquery.A_Expr) {
				if table, ok := changeTimeBound(expr, level); ok {
					tables = append(tables, table)
				}
			})
		})
	}
	slices.Sort(tables)
	return slices.Compact(tables)
}

// changeTimeColumn names a row's last change time.
var changeTimeColumn = regexp.MustCompile(`^(?:updated|modified|changed)_at$`)

// changeTimeBound reads updated_at > $n, updated_at >= $n, or $n < updated_at.
func changeTimeBound(expr *pgquery.A_Expr, tables map[string]string) (string, bool) {
	if expr.GetKind() != pgquery.A_Expr_Kind_AEXPR_OP || len(expr.GetName()) != 1 {
		return "", false
	}
	column, bound := expr.GetLexpr(), expr.GetRexpr()
	switch expr.GetName()[0].GetString_().GetSval() {
	case ">", ">=":
	case "<", "<=":
		column, bound = bound, column
	default:
		return "", false
	}
	ref, ok := columnOf(column)
	if !ok || !changeTimeColumn.MatchString(ref.name) || unCast(bound).GetParamRef() == nil {
		return "", false
	}
	table, ok := tables[ref.qualifier]
	return table, ok && table != ""
}

// ParentUnlink is a statement that takes a child row away from a parent:
// DELETE FROM links WHERE parent_id = $1 ..., or UPDATE children SET
// parent_id = NULL WHERE parent_id = $1 ....
type ParentUnlink struct {
	Child, Column, Parent string
	Offset                int
}

// ParentUnlinks returns the child rows a statement takes away from a parent
// it names in its WHERE.
func (s *Schema) ParentUnlinks(sql string) []ParentUnlink {
	if s == nil {
		return nil
	}
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var unlinks []ParentUnlink
	add := func(rv *pgquery.RangeVar, where *pgquery.Node, cleared map[string]bool) {
		child := s.relation(rv, nil)
		if child == nil || where == nil {
			return
		}
		for _, ref := range pinnedColumns(where) {
			column := child.Column(ref.name)
			if column == nil || column.References == "" || column.References == child.Name || (cleared != nil && !cleared[ref.name]) {
				continue
			}
			unlinks = append(unlinks, ParentUnlink{Child: child.Name, Column: ref.name, Parent: column.References, Offset: int(rv.GetLocation()) - shift})
		}
	}
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			switch stmt := m.(type) {
			case *pgquery.DeleteStmt:
				add(stmt.GetRelation(), stmt.GetWhereClause(), nil)
			case *pgquery.UpdateStmt:
				cleared := make(map[string]bool)
				for _, target := range stmt.GetTargetList() {
					res := target.GetResTarget()
					if value := unCast(res.GetVal()); value.GetAConst() != nil && value.GetAConst().GetIsnull() {
						cleared[strings.ToLower(res.GetName())] = true
					}
				}
				if len(cleared) > 0 {
					add(stmt.GetRelation(), stmt.GetWhereClause(), cleared)
				}
			}
		})
	}
	return unlinks
}
