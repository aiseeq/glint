package sqlschema

import (
	"slices"
	"strings"
	"unicode"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
)

// fragmentPrefix wraps a condition written apart from its statement
// (EXISTS (SELECT ...) appended to a WHERE) into one that parses.
const fragmentPrefix = "SELECT 1 WHERE "

// parseCode parses text written in the code: a statement, a condition
// written apart from its statement, or either with sqlx bind variables (?)
// and format verbs after $.
// shift is what the parsed text added before the original one: offsets in
// the result minus shift are offsets in the original text.
func parseCode(sql string) (result *pgquery.ParseResult, shift int, ok bool) {
	// A format verb after $ ($%d) comes out of the code as $$9, which reads
	// as a dollar quote.
	for _, text := range []string{sql, bindVariables(strings.ReplaceAll(sql, "$$9", "$9"))} {
		if result, ok := parse(text); ok {
			return result, 0, true
		}
		if result, ok := parse(fragmentPrefix + text); ok {
			return result, len(fragmentPrefix), true
		}
	}
	return nil, 0, false
}

// bindVariables replaces the bind variables of sqlx outside quotes - ? and
// :name, not a ::type cast - with $9. Offsets after them move, which only
// shifts a finding's column, not its line.
func bindVariables(sql string) string {
	var b strings.Builder
	quoted := false
	runes := []rune(sql)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case r == '\'':
			quoted = !quoted
			b.WriteRune(r)
		case quoted:
			b.WriteRune(r)
		case r == '?':
			b.WriteString("$9")
		case r == ':' && i+1 < len(runes) && (runes[i+1] == '_' || unicode.IsLetter(runes[i+1])) && (i == 0 || runes[i-1] != ':'):
			b.WriteString("$9")
			for i+1 < len(runes) && (runes[i+1] == '_' || unicode.IsLetter(runes[i+1]) || unicode.IsDigit(runes[i+1])) {
				i++
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// SelfComparisons returns the offsets of the unqualified column of a
// comparison alias.col = col whose alias is a relation of the same SELECT:
//
//	EXISTS (SELECT 1 FROM members m WHERE m.org_id = $1 AND m.email = email)
//
// The unqualified name binds to the nearest relation that has the column,
// and m has it: the condition compares the column with itself and is true
// for every row, while the author meant the outer row's email. The text may
// be a statement or a condition written apart from one.
func SelfComparisons(sql string) []int {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var offsets []int
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			sel, ok := m.(*pgquery.SelectStmt)
			if !ok {
				return
			}
			aliases := levelAliases(sel.GetFromClause())
			if len(aliases) == 0 {
				return
			}
			conditions := []*pgquery.Node{sel.GetWhereClause()}
			for _, item := range sel.GetFromClause() {
				conditions = append(conditions, joinQuals(item)...)
			}
			for _, condition := range conditions {
				levelExpressions(condition, func(expr *pgquery.A_Expr) {
					if offset, ok := selfCompared(expr, aliases); ok && offset >= shift {
						offsets = append(offsets, offset-shift)
					}
				})
			}
		})
	}
	slices.Sort(offsets)
	return slices.Compact(offsets)
}

// levelAliases returns the names the relations of a FROM list are known by
// at its own level: aliases, or table names; not those inside subqueries.
func levelAliases(from []*pgquery.Node) map[string]bool {
	aliases := make(map[string]bool)
	for name := range levelTables(from) {
		if name != "" {
			aliases[name] = true
		}
	}
	return aliases
}

// levelTables returns the tables of a FROM list by the names its own level
// knows them by - the alias, or the table name - not those inside
// subqueries; "" names the only relation of a list that has one, which an
// unqualified column belongs to.
func levelTables(from []*pgquery.Node) map[string]string {
	tables := make(map[string]string)
	relations := 0
	var visit func(node *pgquery.Node)
	visit = func(node *pgquery.Node) {
		switch {
		case node.GetRangeVar() != nil:
			relations++
			rv := node.GetRangeVar()
			name := strings.ToLower(rv.GetRelname())
			if rv.GetAlias() != nil {
				tables[strings.ToLower(rv.GetAlias().GetAliasname())] = name
			} else {
				tables[name] = name
			}
			tables[""] = name
		case node.GetJoinExpr() != nil:
			visit(node.GetJoinExpr().GetLarg())
			visit(node.GetJoinExpr().GetRarg())
		case node.GetRangeSubselect() != nil, node.GetRangeFunction() != nil:
			relations++
		}
	}
	for _, item := range from {
		visit(item)
	}
	if relations != 1 {
		delete(tables, "")
	}
	return tables
}

// joinQuals returns the ON conditions of the joins of a FROM item.
func joinQuals(node *pgquery.Node) []*pgquery.Node {
	join := node.GetJoinExpr()
	if join == nil {
		return nil
	}
	quals := []*pgquery.Node{join.GetQuals()}
	quals = append(quals, joinQuals(join.GetLarg())...)
	return append(quals, joinQuals(join.GetRarg())...)
}

// levelExpressions visits the operator expressions of a condition at its own
// level: through AND, OR, NOT, functions and casts, not into subqueries,
// which are SELECTs of their own.
func levelExpressions(node *pgquery.Node, visit func(*pgquery.A_Expr)) {
	if node == nil {
		return
	}
	switch {
	case node.GetAExpr() != nil:
		expr := node.GetAExpr()
		visit(expr)
		levelExpressions(expr.GetLexpr(), visit)
		levelExpressions(expr.GetRexpr(), visit)
	case node.GetBoolExpr() != nil:
		for _, arg := range node.GetBoolExpr().GetArgs() {
			levelExpressions(arg, visit)
		}
	case node.GetFuncCall() != nil:
		for _, arg := range node.GetFuncCall().GetArgs() {
			levelExpressions(arg, visit)
		}
	case node.GetTypeCast() != nil:
		levelExpressions(node.GetTypeCast().GetArg(), visit)
	}
}

// selfCompared reports an equality between alias.col and an unqualified col
// of the same name, alias one of the level's relations, with the offset of
// the unqualified reference.
func selfCompared(expr *pgquery.A_Expr, aliases map[string]bool) (int, bool) {
	if expr.GetKind() != pgquery.A_Expr_Kind_AEXPR_OP || len(expr.GetName()) != 1 || expr.GetName()[0].GetString_().GetSval() != "=" {
		return 0, false
	}
	left, right := caseFolded(expr.GetLexpr()), caseFolded(expr.GetRexpr())
	for _, pair := range [][2]*pgquery.Node{{left, right}, {right, left}} {
		qualified, okQ := columnOf(pair[0])
		bare, okB := columnOf(pair[1])
		if okQ && okB && qualified.qualifier != "" && aliases[qualified.qualifier] && bare.qualifier == "" && bare.name == qualified.name {
			return location(unCast(pair[1])), true
		}
	}
	return 0, false
}

func unCast(node *pgquery.Node) *pgquery.Node {
	for node.GetTypeCast() != nil {
		node = node.GetTypeCast().GetArg()
	}
	return node
}

// LinkUpdate is a column an UPDATE sets to a parameter or NULL while its
// WHERE does not test that column.
type LinkUpdate struct {
	Table  string
	Column string
	// Clears is SET column = NULL.
	Clears bool
	Offset int
}

// UnscopedLinkUpdates returns the reference columns (*_id) the UPDATEs of a
// statement set to a parameter or to NULL with a WHERE that never tests the
// column:
//
//	UPDATE entries SET batch_id = NULL WHERE account_id = $1 AND seq = $2
//
// Clearing the reference of a row by its own key clears it whatever parent
// it belongs to, and setting it moves a row that belongs to another parent.
func UnscopedLinkUpdates(sql string) []LinkUpdate {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var updates []LinkUpdate
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			update, ok := m.(*pgquery.UpdateStmt)
			if !ok || update.GetWhereClause() == nil {
				return
			}
			tested := referencedColumns(update.GetWhereClause())
			for _, target := range update.GetTargetList() {
				res := target.GetResTarget()
				name := strings.ToLower(res.GetName())
				if !strings.HasSuffix(name, "_id") || tested[name] {
					continue
				}
				value := unCast(res.GetVal())
				clears := value.GetAConst() != nil && value.GetAConst().GetIsnull()
				if value.GetParamRef() == nil && !clears {
					continue
				}
				updates = append(updates, LinkUpdate{Table: strings.ToLower(update.GetRelation().GetRelname()), Column: name, Clears: clears, Offset: int(res.GetLocation()) - shift})
			}
		})
	}
	return updates
}

// referencedColumns returns the names of the columns a condition reads,
// subqueries included.
func referencedColumns(node *pgquery.Node) map[string]bool {
	columns := make(map[string]bool)
	walk(node.ProtoReflect(), func(m proto.Message) {
		if ref, ok := m.(*pgquery.ColumnRef); ok {
			fields := ref.GetFields()
			if len(fields) > 0 && fields[len(fields)-1].GetString_() != nil {
				columns[strings.ToLower(fields[len(fields)-1].GetString_().GetSval())] = true
			}
		}
	})
	return columns
}

// PartialKeyReads returns the offsets of the key columns of a single SELECT
// whose WHERE matches a row by the columns of a partial unique index without
// the index's predicate:
//
//	CREATE UNIQUE INDEX ON payments (order_id) WHERE status <> 'void';
//	SELECT * FROM payments WHERE order_id = $1
//
// The key is unique only among the rows the predicate admits: a void row and
// a live one share it, and a read of one row takes either. Not reported: a
// read with LIMIT (a choice is made on purpose), a grouped or aggregate one,
// one whose WHERE also fixes a full unique key, a join.
func (s *Schema) PartialKeyReads(sql string) []int {
	if s == nil {
		return nil
	}
	result, ok := parse(sql)
	if !ok || len(result.GetStmts()) != 1 {
		return nil
	}
	sel := result.GetStmts()[0].GetStmt().GetSelectStmt()
	if sel == nil || sel.GetWhereClause() == nil || sel.GetLimitCount() != nil || len(sel.GetGroupClause()) > 0 || onlyAggregates(sel) {
		return nil
	}
	tables, joined := s.fromTables(sel)
	if joined || len(tables) != 1 {
		return nil
	}
	var table *Table
	for _, t := range tables {
		table = t
	}
	if table == nil {
		return nil
	}
	pinned := make(map[string]bool)
	for _, ref := range pinnedColumns(sel.GetWhereClause()) {
		pinned[ref.name] = true
	}
	if pinned["id"] || table.UniqueWithin(pinned) {
		return nil
	}
	tested := referencedColumns(sel.GetWhereClause())
	for _, key := range table.partial {
		if len(key.columns) == 0 || !allIn(key.columns, pinned) || anyIn(key.predicate, tested) {
			continue
		}
		return []int{columnLocation(sel.GetWhereClause(), key.columns[0])}
	}
	return nil
}

func allIn(names []string, set map[string]bool) bool {
	for _, name := range names {
		if !set[name] {
			return false
		}
	}
	return true
}

// anyIn reports a name of names in set.
func anyIn(names []string, set map[string]bool) bool {
	return slices.ContainsFunc(names, func(name string) bool { return set[name] })
}

// columnLocation returns the offset of the first reference to the column in
// a condition.
func columnLocation(node *pgquery.Node, name string) int {
	offset := -1
	walk(node.ProtoReflect(), func(m proto.Message) {
		if ref, ok := m.(*pgquery.ColumnRef); ok && offset < 0 {
			fields := ref.GetFields()
			if len(fields) > 0 && strings.EqualFold(fields[len(fields)-1].GetString_().GetSval(), name) {
				offset = int(ref.GetLocation())
			}
		}
	})
	return max(offset, 0)
}

// Delete is the table a DELETE removes rows of.
type Delete struct {
	Table  string
	Offset int
}

// Deletes returns the tables the DELETEs of a statement remove rows of.
func Deletes(sql string) []Delete {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var deletes []Delete
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			if del, ok := m.(*pgquery.DeleteStmt); ok {
				rv := del.GetRelation()
				deletes = append(deletes, Delete{Table: strings.ToLower(rv.GetRelname()), Offset: int(rv.GetLocation()) - shift})
			}
		})
	}
	return deletes
}

// Reference is a column of another table that holds the id of a table's
// row by its name, with no foreign key.
type Reference struct {
	Table, Column string
}

// UnkeyedReferences returns the columns of other tables named after the
// table's row - <row>_id or ..._<row>_id, a one-word row also by its usual
// abbreviation (transaction: tx) - of the type of its id, with no foreign
// key: the database lets the table's rows go while they point at them.
func (s *Schema) UnkeyedReferences(table string) []Reference {
	if s == nil {
		return nil
	}
	target := s.Table(table)
	if target == nil || target.View || target.Column("id") == nil {
		return nil
	}
	idType := target.Column("id").Type
	row := singular(target.Name)
	names := []string{row}
	if abbreviation, ok := rowAbbreviations[row]; ok {
		names = append(names, abbreviation...)
	}
	var refs []Reference
	for _, other := range s.tables {
		if other == target || other.View {
			continue
		}
		for _, column := range other.columns {
			if column.References != "" || column.Type != idType || !namesRow(column.Name, names) {
				continue
			}
			refs = append(refs, Reference{Table: other.Name, Column: column.Name})
		}
	}
	slices.SortFunc(refs, func(a, b Reference) int { return strings.Compare(a.Table+"."+a.Column, b.Table+"."+b.Column) })
	return refs
}

// NamesTable reports a column <row>_id of the table that points at a table
// of the schema: a foreign key of the column, or a table whose row it names
// (batch_id: batches). chat_account_id names no table and holds an outside
// identity, not a parent row.
func (s *Schema) NamesTable(table, column string) bool {
	if s == nil {
		return false
	}
	row, ok := strings.CutSuffix(column, "_id")
	if !ok {
		return false
	}
	if t := s.Table(table); t != nil {
		if c := t.Column(column); c != nil && c.References != "" {
			return true
		}
	}
	for _, other := range s.tables {
		if !other.View && singular(other.Name) == row {
			return true
		}
	}
	return false
}

// rowAbbreviations are the usual short names of a one-word row in column
// names.
var rowAbbreviations = map[string][]string{"transaction": {"tx", "txn"}}

// namesRow reports a column <name>_id or ..._<name>_id for one of the names.
func namesRow(column string, names []string) bool {
	prefix, ok := strings.CutSuffix(column, "_id")
	if !ok {
		return false
	}
	for _, name := range names {
		if prefix == name || strings.HasSuffix(prefix, "_"+name) {
			return true
		}
	}
	return false
}

// singular returns the row name of a table name: entries - entry,
// transactions - transaction, statuses - status, batches - batch.
func singular(table string) string {
	switch {
	case strings.HasSuffix(table, "ies"):
		return strings.TrimSuffix(table, "ies") + "y"
	case strings.HasSuffix(table, "sses"), strings.HasSuffix(table, "uses"), strings.HasSuffix(table, "xes"),
		strings.HasSuffix(table, "ches"), strings.HasSuffix(table, "shes"):
		return strings.TrimSuffix(table, "es")
	case strings.HasSuffix(table, "s") && !strings.HasSuffix(table, "ss"):
		return strings.TrimSuffix(table, "s")
	}
	return table
}

// UpdatesOnConflict reports an INSERT ... ON CONFLICT ... DO UPDATE: a
// conflicting row is updated and counted among the affected rows.
func UpdatesOnConflict(sql string) bool {
	result, _, ok := parseCode(sql)
	if !ok || len(result.GetStmts()) != 1 {
		return false
	}
	conflict := result.GetStmts()[0].GetStmt().GetInsertStmt().GetOnConflictClause()
	return conflict != nil && conflict.GetAction() == pgquery.OnConflictAction_ONCONFLICT_UPDATE
}

// ColumnMostlyOfType reports a column name that more than half of the tables
// holding it give the type typ: an id column that is uuid in most tables.
func (s *Schema) ColumnMostlyOfType(name, typ string) bool {
	if s == nil {
		return false
	}
	match, total := 0, 0
	for _, table := range s.tables {
		column := table.Column(name)
		if column == nil || table.View {
			continue
		}
		total++
		if column.Type == typ {
			match++
		}
	}
	return match*2 > total
}

// ColumnTypes returns the types the tables of the schema give a column of
// that name.
func (s *Schema) ColumnTypes(name string) []string {
	if s == nil {
		return nil
	}
	var types []string
	for _, table := range s.tables {
		if column := table.Column(name); column != nil && !table.View && !slices.Contains(types, column.Type) {
			types = append(types, column.Type)
		}
	}
	slices.Sort(types)
	return types
}
