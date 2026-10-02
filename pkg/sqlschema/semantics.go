package sqlschema

import (
	"regexp"
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
)

// UnorderedLimits returns the offsets of the SELECTs of a statement that
// take their first rows by LIMIT with no ORDER BY: which rows come first is
// up to the plan. Not reported are a SELECT under EXISTS, one that returns
// only aggregates (a single row), one that locks its rows (FOR UPDATE SKIP
// LOCKED takes any free rows on purpose), one reading a migration tool's
// table, and one whose WHERE fixes a row of its only table: an id, or with
// the schema any unique key. The schema may be nil.
func (s *Schema) UnorderedLimits(sql string) []int {
	result, ok := parse(sql)
	if !ok {
		return nil
	}
	exists := make(map[*pgquery.SelectStmt]bool)
	var selects []*pgquery.SelectStmt
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			switch node := m.(type) {
			case *pgquery.SubLink:
				if node.GetSubLinkType() == pgquery.SubLinkType_EXISTS_SUBLINK {
					exists[node.GetSubselect().GetSelectStmt()] = true
				}
			case *pgquery.SelectStmt:
				selects = append(selects, node)
			}
		})
	}
	var offsets []int
	for _, sel := range selects {
		if sel.GetLimitCount() == nil || len(sel.GetSortClause()) > 0 || sel.GetOp() != pgquery.SetOperation_SETOP_NONE ||
			exists[sel] || len(sel.GetLockingClause()) > 0 || onlyAggregates(sel) || s.oneRow(sel) {
			continue
		}
		offsets = append(offsets, location(sel.GetLimitCount()))
	}
	return offsets
}

// DateOnlyOrders returns the offsets of the ORDER BY keys of the SELECTs of
// one table that sort by date columns alone: rows of one day come in plan
// order, and a consumer taking them first-in first-out takes another one when
// the plan changes. Not reported: a sort the WHERE and the keys make unique,
// a grouped or distinct SELECT, a join, a table the schema does not know.
func (s *Schema) DateOnlyOrders(sql string) []int {
	if s == nil {
		return nil
	}
	result, ok := parse(sql)
	if !ok {
		return nil
	}
	var offsets []int
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			sel, ok := m.(*pgquery.SelectStmt)
			if !ok || len(sel.GetSortClause()) == 0 || len(sel.GetGroupClause()) > 0 || len(sel.GetDistinctClause()) > 0 {
				return
			}
			tables, joined := s.fromTables(sel)
			if joined || len(tables) != 1 {
				return
			}
			var table *Table
			var alias string
			for name, t := range tables {
				alias, table = name, t
			}
			if table == nil || table.View {
				return
			}
			keys := make(map[string]bool)
			for _, ref := range pinnedColumns(sel.GetWhereClause()) {
				keys[ref.name] = true
			}
			for _, name := range correlatedColumns(sel.GetWhereClause(), alias, table) {
				keys[name] = true
			}
			sorted := make(map[string]bool)
			for _, item := range sel.GetSortClause() {
				ref := item.GetSortBy().GetNode().GetColumnRef()
				if ref == nil {
					return
				}
				fields := ref.GetFields()
				column := table.Column(fields[len(fields)-1].GetString_().GetSval())
				if column == nil || column.Type != "date" {
					return
				}
				keys[column.Name] = true
				sorted[column.Name] = true
			}
			if table.UniqueWithin(keys) || selectsOnly(sel, sorted) {
				return
			}
			offsets = append(offsets, location(sel.GetSortClause()[0].GetSortBy().GetNode()))
		})
	}
	return offsets
}

// correlatedColumns returns the columns of the table the AND terms of a
// condition set equal to a column of another relation: in a subquery per
// outer row (WHERE position_id = dp.id) they are fixed as by a parameter.
func correlatedColumns(where *pgquery.Node, alias string, table *Table) []string {
	if where == nil {
		return nil
	}
	if b := where.GetBoolExpr(); b != nil {
		if b.GetBoolop() != pgquery.BoolExprType_AND_EXPR {
			return nil
		}
		var names []string
		for _, arg := range b.GetArgs() {
			names = append(names, correlatedColumns(arg, alias, table)...)
		}
		return names
	}
	expr := where.GetAExpr()
	if expr == nil || expr.GetKind() != pgquery.A_Expr_Kind_AEXPR_OP || len(expr.GetName()) != 1 ||
		expr.GetName()[0].GetString_().GetSval() != "=" {
		return nil
	}
	own := func(ref pinnedRef) bool {
		return (ref.qualifier == "" || ref.qualifier == alias || ref.qualifier == table.Name) && table.Column(ref.name) != nil
	}
	left, leftOK := columnOf(expr.GetLexpr())
	right, rightOK := columnOf(expr.GetRexpr())
	if !leftOK || !rightOK {
		return nil
	}
	switch {
	case own(left) && right.qualifier != "" && !own(right):
		return []string{left.name}
	case own(right) && left.qualifier != "" && !own(left):
		return []string{right.name}
	}
	return nil
}

// selectsOnly reports a SELECT whose every target is one of the columns:
// rows tied on them read the same.
func selectsOnly(sel *pgquery.SelectStmt, columns map[string]bool) bool {
	if len(sel.GetTargetList()) == 0 {
		return false
	}
	for _, target := range sel.GetTargetList() {
		ref, ok := columnOf(target.GetResTarget().GetVal())
		if !ok || !columns[ref.name] {
			return false
		}
	}
	return true
}

var aggregates = map[string]bool{
	"count": true, "sum": true, "min": true, "max": true, "avg": true,
	"bool_and": true, "bool_or": true, "every": true, "array_agg": true, "string_agg": true, "json_agg": true, "jsonb_agg": true,
}

func onlyAggregates(sel *pgquery.SelectStmt) bool {
	if len(sel.GetTargetList()) == 0 {
		return false
	}
	for _, target := range sel.GetTargetList() {
		call := target.GetResTarget().GetVal().GetFuncCall()
		if call == nil {
			return false
		}
		names := call.GetFuncname()
		if !aggregates[strings.ToLower(names[len(names)-1].GetString_().GetSval())] {
			return false
		}
	}
	return true
}

// ConstantColumns returns the offsets of the constants a SELECT names as a
// column of a table it reads: 'completed' AS status over a table with a
// status column shows one value for every row, whatever the row holds. Not
// reported: NULL or ” (a placeholder in a UNION branch), a column the WHERE pins
// to a value (the constant then says the same), and the SELECT of an INSERT,
// where the constant is the value written. The schema may be nil.
func (s *Schema) ConstantColumns(sql string) []int {
	if s == nil {
		return nil
	}
	result, ok := parse(sql)
	if !ok {
		return nil
	}
	written := make(map[*pgquery.SelectStmt]bool)
	var selects []*pgquery.SelectStmt
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			switch node := m.(type) {
			case *pgquery.InsertStmt:
				written[node.GetSelectStmt().GetSelectStmt()] = true
			case *pgquery.SelectStmt:
				selects = append(selects, node)
			}
		})
	}
	tags := unionTags(selects)
	var offsets []int
	for _, sel := range selects {
		if written[sel] || sel.GetOp() != pgquery.SetOperation_SETOP_NONE {
			continue
		}
		tables, _ := s.fromTables(sel)
		pinned := make(map[string]bool)
		for _, ref := range pinnedColumns(sel.GetWhereClause()) {
			pinned[ref.name] = true
		}
		for i, target := range sel.GetTargetList() {
			res := target.GetResTarget()
			name := strings.ToLower(res.GetName())
			value := constantTarget(target)
			if name == "" || pinned[name] || placeholder(value.GetAConst()) || tags[sel][i] || !anyHasColumn(tables, name) {
				continue
			}
			offsets = append(offsets, location(value))
		}
	}
	return offsets
}

// MigratedTables returns the offsets of the CREATE TABLE statements of the
// text that create a table the migrations already define: a second
// definition that drifts from the real one as migrations change it.
// Temporary tables are work space and are not reported. The schema may be
// nil.
func (s *Schema) MigratedTables(sql string) []int {
	if s == nil {
		return nil
	}
	result, ok := parse(sql)
	if !ok {
		return nil
	}
	var offsets []int
	for _, raw := range result.GetStmts() {
		create := raw.GetStmt().GetCreateStmt()
		if create == nil || create.GetRelation().GetRelpersistence() == "t" || s.relation(create.GetRelation(), nil) == nil {
			continue
		}
		offsets = append(offsets, int(create.GetRelation().GetLocation()))
	}
	return offsets
}

// anyHasColumn reports a table among those of a FROM with the column.
func anyHasColumn(tables map[string]*Table, name string) bool {
	for _, table := range tables {
		if table != nil && table.Column(name) != nil {
			return true
		}
	}
	return false
}

// constantTarget returns a target's value through type casts.
func constantTarget(target *pgquery.Node) *pgquery.Node {
	value := target.GetResTarget().GetVal()
	for value.GetTypeCast() != nil {
		value = value.GetTypeCast().GetArg()
	}
	return value
}

// unionTags returns, for the branches of each UNION, the target positions
// every branch fills with a constant: a tag saying which branch a row came
// from ('client' AS source, 'system' AS source), not a value of the column.
func unionTags(selects []*pgquery.SelectStmt) map[*pgquery.SelectStmt]map[int]bool {
	tags := make(map[*pgquery.SelectStmt]map[int]bool)
	inner := make(map[*pgquery.SelectStmt]bool)
	for _, sel := range selects {
		if sel.GetOp() != pgquery.SetOperation_SETOP_NONE {
			inner[sel.GetLarg()] = true
			inner[sel.GetRarg()] = true
		}
	}
	for _, sel := range selects {
		if sel.GetOp() == pgquery.SetOperation_SETOP_NONE || inner[sel] {
			continue
		}
		var leaves []*pgquery.SelectStmt
		var collect func(*pgquery.SelectStmt)
		collect = func(s *pgquery.SelectStmt) {
			if s.GetOp() == pgquery.SetOperation_SETOP_NONE {
				leaves = append(leaves, s)
				return
			}
			collect(s.GetLarg())
			collect(s.GetRarg())
		}
		collect(sel)
		for i := range leaves[0].GetTargetList() {
			constant := true
			for _, leaf := range leaves {
				if i >= len(leaf.GetTargetList()) || placeholder(constantTarget(leaf.GetTargetList()[i]).GetAConst()) {
					constant = false
					break
				}
			}
			if !constant {
				continue
			}
			for _, leaf := range leaves {
				if tags[leaf] == nil {
					tags[leaf] = make(map[int]bool)
				}
				tags[leaf][i] = true
			}
		}
	}
	return tags
}

// placeholder reports a value that is not a constant, or one that fills a
// column a UNION branch has no value for: NULL or ”.
func placeholder(c *pgquery.A_Const) bool {
	return c == nil || c.GetIsnull() || (c.GetSval() != nil && c.GetSval().GetSval() == "")
}

// fromTables maps the names a SELECT's FROM gives its tables - the alias,
// or the table's own name - to the tables; a table the schema lacks maps to
// nil. joined reports more than one relation.
func (s *Schema) fromTables(sel *pgquery.SelectStmt) (tables map[string]*Table, joined bool) {
	tables = make(map[string]*Table)
	count := 0
	for _, item := range sel.GetFromClause() {
		walk(item.ProtoReflect(), func(m proto.Message) {
			switch node := m.(type) {
			case *pgquery.RangeVar:
				count++
				name := strings.ToLower(node.GetRelname())
				if node.GetAlias() != nil {
					name = node.GetAlias().GetAliasname()
				}
				var table *Table
				if s != nil {
					table = s.relation(node, nil)
				}
				tables[name] = table
			case *pgquery.RangeSubselect, *pgquery.RangeFunction:
				count++
			}
		})
	}
	return tables, count > 1
}

// oneRow reports a SELECT of one table whose WHERE fixes a row: an id, or a
// unique key the schema knows, or a migration tool's table.
func (s *Schema) oneRow(sel *pgquery.SelectStmt) bool {
	tables, joined := s.fromTables(sel)
	if joined {
		return false
	}
	pinned := make(map[string]bool)
	for _, ref := range pinnedColumns(sel.GetWhereClause()) {
		pinned[ref.name] = true
	}
	if pinned["id"] {
		return true
	}
	for name, table := range tables {
		if toolTables[name] || (table != nil && (toolTables[table.Name] || table.UniqueWithin(pinned))) {
			return true
		}
	}
	return false
}

// pinnedRef is a column an AND term of a condition compares with a value.
type pinnedRef struct {
	qualifier string
	name      string
}

// pinnedColumns returns the columns the AND terms of a condition compare
// with a parameter or a constant: col = $1, t.col = 'x', lower(email) = lower($1).
func pinnedColumns(where *pgquery.Node) []pinnedRef {
	if where == nil {
		return nil
	}
	if b := where.GetBoolExpr(); b != nil {
		if b.GetBoolop() != pgquery.BoolExprType_AND_EXPR {
			return nil
		}
		var refs []pinnedRef
		for _, arg := range b.GetArgs() {
			refs = append(refs, pinnedColumns(arg)...)
		}
		return refs
	}
	expr := where.GetAExpr()
	if expr == nil || expr.GetKind() != pgquery.A_Expr_Kind_AEXPR_OP || len(expr.GetName()) != 1 ||
		expr.GetName()[0].GetString_().GetSval() != "=" {
		return nil
	}
	for _, pair := range [][2]*pgquery.Node{{expr.GetLexpr(), expr.GetRexpr()}, {expr.GetRexpr(), expr.GetLexpr()}} {
		if ref, ok := columnOf(caseFolded(pair[0])); ok && isValue(caseFolded(pair[1])) {
			return []pinnedRef{ref}
		}
	}
	return nil
}

// caseFolded unwraps lower() and upper(): a unique index on lower(email)
// fixes the row as a key on email does.
func caseFolded(node *pgquery.Node) *pgquery.Node {
	if call := node.GetFuncCall(); call != nil && len(call.GetArgs()) == 1 {
		names := call.GetFuncname()
		if f := strings.ToLower(names[len(names)-1].GetString_().GetSval()); f == "lower" || f == "upper" {
			return call.GetArgs()[0]
		}
	}
	return node
}

// columnOf returns the qualifier and the name of a column reference, through
// type casts.
func columnOf(node *pgquery.Node) (pinnedRef, bool) {
	for node.GetTypeCast() != nil {
		node = node.GetTypeCast().GetArg()
	}
	var names []string
	for _, field := range node.GetColumnRef().GetFields() {
		if field.GetString_() == nil {
			return pinnedRef{}, false
		}
		names = append(names, strings.ToLower(field.GetString_().GetSval()))
	}
	switch len(names) {
	case 0:
		return pinnedRef{}, false
	case 1:
		return pinnedRef{name: names[0]}, true
	}
	return pinnedRef{qualifier: names[len(names)-2], name: names[len(names)-1]}, true
}

func refName(node *pgquery.Node) string {
	for node.GetTypeCast() != nil {
		node = node.GetTypeCast().GetArg()
	}
	fields := node.GetColumnRef().GetFields()
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(fields[len(fields)-1].GetString_().GetSval())
}

func isValue(node *pgquery.Node) bool {
	for node.GetTypeCast() != nil {
		node = node.GetTypeCast().GetArg()
	}
	return node.GetParamRef() != nil || node.GetAConst() != nil
}

// location is the offset of a value node in the text, or 0.
func location(node *pgquery.Node) int {
	switch {
	case node.GetAConst() != nil:
		return int(node.GetAConst().GetLocation())
	case node.GetParamRef() != nil:
		return int(node.GetParamRef().GetLocation())
	case node.GetFuncCall() != nil:
		return int(node.GetFuncCall().GetLocation())
	case node.GetColumnRef() != nil:
		return int(node.GetColumnRef().GetLocation())
	case node.GetTypeCast() != nil:
		return int(node.GetTypeCast().GetLocation())
	case node.GetSqlvalueFunction() != nil:
		return int(node.GetSqlvalueFunction().GetLocation())
	}
	return 0
}

// schemaStatement is how a statement changing the schema begins; tempTable
// and toolTable are the ones that do not.
var (
	schemaStatement = regexp.MustCompile(`(?i)^\s*(?:create\s+(?:or\s+replace\s+)?(?:unique\s+)?(?:(?:global|local)\s+)?(?:temp\s+|temporary\s+|unlogged\s+)?(?:table|sequence|index|view|materialized\s+view|function|trigger|type)|alter\s+(?:table|sequence|type|index)|drop\s+(?:table|sequence|index|view|materialized\s+view|function|trigger|type))\b`)
	tempTable       = regexp.MustCompile(`(?i)^\s*create\s+(?:(?:global|local)\s+)?temp(?:orary)?\s+table\b`)
	toolTable       = regexp.MustCompile(`(?i)^\s*create\s+table\s+(?:if\s+not\s+exists\s+)?"?(\w+)"?`)
)

// DefinesSchema reports text with a statement that creates, alters or drops
// a table, a sequence, an index, a view, a function, a trigger or a type. It
// reads how each statement begins, so a statement with a value formatted
// into it counts too. A temporary table is work space, and a migration
// tool's own table is the migrator's, not schema.
func DefinesSchema(sql string) bool {
	for _, statement := range strings.Split(sql, ";") {
		if !schemaStatement.MatchString(statement) || tempTable.MatchString(statement) {
			continue
		}
		if m := toolTable.FindStringSubmatch(statement); m != nil && toolTables[strings.ToLower(m[1])] {
			continue
		}
		return true
	}
	return false
}

// GroupedRows reports a SELECT whose outermost level groups rows into
// possibly many - a GROUP BY whose keys the WHERE does not fix, with no
// LIMIT 1. Keys that are columns of a table whose unique key the WHERE fixes
// are one group. The schema may be nil.
func (s *Schema) GroupedRows(sql string) bool {
	result, ok := parse(sql)
	if !ok || len(result.GetStmts()) != 1 {
		return false
	}
	sel := result.GetStmts()[0].GetStmt().GetSelectStmt()
	if sel == nil || len(sel.GetGroupClause()) == 0 {
		return false
	}
	if limit := sel.GetLimitCount().GetAConst(); limit != nil && limit.GetIval().GetIval() == 1 {
		return false
	}
	tables, _ := s.fromTables(sel)
	pinned := make(map[string]bool)              // columns fixed, by name
	pinnedIn := make(map[*Table]map[string]bool) // columns fixed, by table
	for _, ref := range pinnedColumns(sel.GetWhereClause()) {
		pinned[ref.name] = true
		if table := ownerTable(tables, ref); table != nil {
			if pinnedIn[table] == nil {
				pinnedIn[table] = make(map[string]bool)
			}
			pinnedIn[table][ref.name] = true
		}
	}
	for _, key := range sel.GetGroupClause() {
		ref, ok := columnOf(key)
		if !ok {
			return true
		}
		if pinned[ref.name] {
			continue
		}
		table := ownerTable(tables, ref)
		if table == nil || !table.UniqueWithin(pinnedIn[table]) {
			return true
		}
	}
	return false
}

// ownerTable returns the table a column reference reads: by its qualifier, or
// the only FROM table that has the column.
func ownerTable(tables map[string]*Table, ref pinnedRef) *Table {
	if ref.qualifier != "" {
		return tables[ref.qualifier]
	}
	var owner *Table
	for _, table := range tables {
		if table != nil && table.Column(ref.name) != nil {
			if owner != nil {
				return nil
			}
			owner = table
		}
	}
	return owner
}

// ConditionalUpsert reports an INSERT ... ON CONFLICT ... DO UPDATE ... WHERE
// without RETURNING: on a conflict whose row fails the WHERE the statement
// succeeds having written nothing, and only the affected count tells.
func ConditionalUpsert(sql string) bool {
	result, ok := parse(sql)
	if !ok || len(result.GetStmts()) != 1 {
		return false
	}
	insert := result.GetStmts()[0].GetStmt().GetInsertStmt()
	if insert == nil || len(insert.GetReturningList()) > 0 {
		return false
	}
	conflict := insert.GetOnConflictClause()
	return conflict != nil && conflict.GetAction() == pgquery.OnConflictAction_ONCONFLICT_UPDATE && conflict.GetWhereClause() != nil
}

// ConflictParams returns, for an INSERT ... VALUES ... ON CONFLICT (columns)
// DO UPDATE, the parameter number bound to each conflict column, and the
// offset of the ON CONFLICT clause.
func ConflictParams(sql string) (map[string]int, int, bool) {
	result, ok := parse(sql)
	if !ok || len(result.GetStmts()) != 1 {
		return nil, 0, false
	}
	insert := result.GetStmts()[0].GetStmt().GetInsertStmt()
	conflict := insert.GetOnConflictClause()
	if conflict == nil || conflict.GetAction() != pgquery.OnConflictAction_ONCONFLICT_UPDATE {
		return nil, 0, false
	}
	rows := insert.GetSelectStmt().GetSelectStmt().GetValuesLists()
	if len(rows) == 0 {
		return nil, 0, false
	}
	values := rows[0].GetList().GetItems()
	position := make(map[string]int)
	for i, col := range insert.GetCols() {
		position[strings.ToLower(col.GetResTarget().GetName())] = i
	}
	params := make(map[string]int)
	for _, elem := range conflict.GetInfer().GetIndexElems() {
		name := strings.ToLower(elem.GetIndexElem().GetName())
		i, found := position[name]
		if !found || i >= len(values) {
			continue
		}
		value := values[i]
		for value.GetTypeCast() != nil {
			value = value.GetTypeCast().GetArg()
		}
		if ref := value.GetParamRef(); ref != nil {
			params[name] = int(ref.GetNumber())
		}
	}
	return params, int(conflict.GetLocation()), len(params) > 0
}

// SessionDates returns the offsets where a statement takes a date from a
// moment in the session's time zone: CURRENT_DATE, now()::date, and a
// timestamptz column (by the schema) cast to date, passed to date() or
// truncated by date_trunc. AT TIME ZONE around the column fixes the zone
// and is not reported.
func (s *Schema) SessionDates(sql string) []int {
	result, ok := parse(sql)
	if !ok {
		return nil
	}
	var offsets []int
	for _, raw := range result.GetStmts() {
		tables := s.referencedTables(raw.GetStmt())
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			switch node := m.(type) {
			case *pgquery.SQLValueFunction:
				if node.GetOp() == pgquery.SQLValueFunctionOp_SVFOP_CURRENT_DATE {
					offsets = append(offsets, int(node.GetLocation()))
				}
			case *pgquery.TypeCast:
				names := node.GetTypeName().GetNames()
				if len(names) > 0 && names[len(names)-1].GetString_().GetSval() == "date" && momentInSession(node.GetArg(), tables) {
					offsets = append(offsets, int(node.GetLocation()))
				}
			case *pgquery.FuncCall:
				names := node.GetFuncname()
				name := strings.ToLower(names[len(names)-1].GetString_().GetSval())
				args := node.GetArgs()
				if (name == "date" && len(args) == 1 && momentInSession(args[0], tables)) ||
					(name == "date_trunc" && len(args) == 2 && momentInSession(args[1], tables)) {
					offsets = append(offsets, int(node.GetLocation()))
				}
			}
		})
	}
	return offsets
}

// referencedTables returns the tables of the schema a statement names.
func (s *Schema) referencedTables(stmt *pgquery.Node) []*Table {
	var tables []*Table
	walk(stmt.ProtoReflect(), func(m proto.Message) {
		if rv, ok := m.(*pgquery.RangeVar); ok {
			if table := s.relation(rv, nil); table != nil && !table.View {
				tables = append(tables, table)
			}
		}
	})
	return tables
}

// momentInSession reports now() or a column that some named table has as
// timestamptz.
func momentInSession(node *pgquery.Node, tables []*Table) bool {
	if call := node.GetFuncCall(); call != nil {
		names := call.GetFuncname()
		return strings.ToLower(names[len(names)-1].GetString_().GetSval()) == "now"
	}
	if f := node.GetSqlvalueFunction(); f != nil {
		return f.GetOp() == pgquery.SQLValueFunctionOp_SVFOP_CURRENT_TIMESTAMP
	}
	name := refName(node)
	if name == "" || node.GetColumnRef() == nil {
		return false
	}
	for _, table := range tables {
		if column := table.Column(name); column != nil && column.Type == "timestamptz" {
			return true
		}
	}
	return false
}

// RowWrite reports a single UPDATE or DELETE without RETURNING and without
// FROM or USING, whose WHERE fixes one row of its table by a parameter: an
// id, or a unique key the schema knows. An UPDATE whose WHERE also tests a
// column it sets (AND hidden_at IS NULL) is left out: no row there means
// the change is already made. When no row matches, it succeeds having changed
// nothing, and only the count of affected rows tells.
func (s *Schema) RowWrite(sql string) bool {
	result, ok := parse(sql)
	if !ok || len(result.GetStmts()) != 1 {
		return false
	}
	stmt := result.GetStmts()[0].GetStmt()
	var (
		relation *pgquery.RangeVar
		where    *pgquery.Node
	)
	switch {
	case stmt.GetUpdateStmt() != nil:
		update := stmt.GetUpdateStmt()
		if len(update.GetReturningList()) > 0 || len(update.GetFromClause()) > 0 {
			return false
		}
		relation, where = update.GetRelation(), update.GetWhereClause()
		if guardsOwnChange(update) {
			return false
		}
	case stmt.GetDeleteStmt() != nil:
		del := stmt.GetDeleteStmt()
		if len(del.GetReturningList()) > 0 || len(del.GetUsingClause()) > 0 {
			return false
		}
		relation, where = del.GetRelation(), del.GetWhereClause()
	default:
		return false
	}
	// A row named by a constant (WHERE id = 1) is the table's one row of
	// settings, there by the migration.
	params := false
	walk(where.ProtoReflect(), func(m proto.Message) {
		_, isParam := m.(*pgquery.ParamRef)
		params = params || isParam
	})
	if !params {
		return false
	}
	pinned := make(map[string]bool)
	for _, ref := range pinnedColumns(where) {
		pinned[ref.name] = true
	}
	if pinned["id"] {
		return true
	}
	if s == nil {
		return false
	}
	table := s.Table(relation.GetRelname())
	return table != nil && table.UniqueWithin(pinned)
}

// guardsOwnChange reports an UPDATE whose WHERE tests a column its SET
// writes, other than the key it pins the row by: an idempotent change that
// matches no row once made.
func guardsOwnChange(update *pgquery.UpdateStmt) bool {
	set := make(map[string]bool)
	for _, target := range update.GetTargetList() {
		set[strings.ToLower(target.GetResTarget().GetName())] = true
	}
	for _, ref := range pinnedColumns(update.GetWhereClause()) {
		delete(set, ref.name)
	}
	guarded := false
	walk(update.GetWhereClause().ProtoReflect(), func(m proto.Message) {
		if ref, ok := m.(*pgquery.ColumnRef); ok {
			node := &pgquery.Node{Node: &pgquery.Node_ColumnRef{ColumnRef: ref}}
			guarded = guarded || set[refName(node)]
		}
	})
	return guarded
}
