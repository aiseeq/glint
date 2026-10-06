package sqlschema

import (
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
)

// ColumnWrite is a column an UPDATE sets.
type ColumnWrite struct {
	Column string
	// Param is the bind parameter the column is set to as it is (a cast
	// aside), 0 for any other value.
	Param int
	// Literal is the string constant the column is set to, when IsLiteral.
	Literal   string
	IsLiteral bool
	Offset    int
}

// UpdateWrite is an UPDATE of a table and the columns it sets.
type UpdateWrite struct {
	Table string
	Sets  []ColumnWrite
}

// Assignment returns the write of a column, ok false when the UPDATE leaves
// it.
func (u UpdateWrite) Assignment(column string) (ColumnWrite, bool) {
	for _, set := range u.Sets {
		if set.Column == column {
			return set, true
		}
	}
	return ColumnWrite{}, false
}

// Updates returns the UPDATEs of a statement, those of its WITH clause
// included.
func Updates(sql string) []UpdateWrite {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var updates []UpdateWrite
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			update, ok := m.(*pgquery.UpdateStmt)
			if !ok {
				return
			}
			write := UpdateWrite{Table: strings.ToLower(update.GetRelation().GetRelname())}
			for _, target := range update.GetTargetList() {
				res := target.GetResTarget()
				set := ColumnWrite{Column: strings.ToLower(res.GetName()), Offset: int(res.GetLocation()) - shift}
				value := unCast(res.GetVal())
				if ref := value.GetParamRef(); ref != nil {
					set.Param = int(ref.GetNumber())
				}
				set.Literal, set.IsLiteral = stringConst(value)
				write.Sets = append(write.Sets, set)
			}
			updates = append(updates, write)
		})
	}
	return updates
}

// UpsertWrites returns the DO UPDATE SET of an INSERT ... VALUES ... ON
// CONFLICT as UPDATEs of the table. A column set from EXCLUDED.col (as it
// is, or inside an expression such as COALESCE(t.col, EXCLUDED.col)) counts
// as set to the parameter the VALUES row binds to col.
func UpsertWrites(sql string) []UpdateWrite {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var writes []UpdateWrite
	for _, raw := range result.GetStmts() {
		insert := raw.GetStmt().GetInsertStmt()
		conflict := insert.GetOnConflictClause()
		rows := insert.GetSelectStmt().GetSelectStmt().GetValuesLists()
		if conflict == nil || conflict.GetAction() != pgquery.OnConflictAction_ONCONFLICT_UPDATE || len(rows) != 1 {
			continue
		}
		values := rows[0].GetList().GetItems()
		params := make(map[string]int)
		for i, col := range insert.GetCols() {
			if i < len(values) {
				if ref := unCast(values[i]).GetParamRef(); ref != nil {
					params[strings.ToLower(col.GetResTarget().GetName())] = int(ref.GetNumber())
				}
			}
		}
		write := UpdateWrite{Table: strings.ToLower(insert.GetRelation().GetRelname())}
		for _, target := range conflict.GetTargetList() {
			res := target.GetResTarget()
			set := ColumnWrite{Column: strings.ToLower(res.GetName()), Offset: int(res.GetLocation()) - shift}
			set.Literal, set.IsLiteral = stringConst(res.GetVal())
			walk(res.GetVal().ProtoReflect(), func(m proto.Message) {
				if ref, ok := m.(*pgquery.ColumnRef); ok && set.Param == 0 && qualifier(ref) == "excluded" {
					set.Param = params[lastField(ref)]
				}
			})
			write.Sets = append(write.Sets, set)
		}
		writes = append(writes, write)
	}
	return writes
}

// StageRead is a SELECT that takes the rows of a status by the time of a
// column named for that status: status = 'CONFIRMED' AND confirmed_at < $1.
type StageRead struct {
	Table, Column, Status string
	Offset                int
}

// StageReads returns the reads of a statement that compare a <stage>_at
// column (<, >, <=, >=, BETWEEN) while fixing the status to that stage.
func StageReads(sql string) []StageRead {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var reads []StageRead
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			sel, ok := m.(*pgquery.SelectStmt)
			if !ok || sel.GetWhereClause() == nil {
				return
			}
			tables := levelTables(sel.GetFromClause())
			statuses := make(map[string]string)
			var compared []*pgquery.ColumnRef
			for _, term := range andTerms(sel.GetWhereClause()) {
				expr := term.GetAExpr()
				if expr == nil {
					continue
				}
				op := ""
				if len(expr.GetName()) == 1 {
					op = expr.GetName()[0].GetString_().GetSval()
				}
				switch {
				case expr.GetKind() == pgquery.A_Expr_Kind_AEXPR_OP && op == "=":
					ref, value := expr.GetLexpr().GetColumnRef(), expr.GetRexpr()
					if ref == nil {
						ref, value = expr.GetRexpr().GetColumnRef(), expr.GetLexpr()
					}
					if text, ok := stringConst(value); ok && ref != nil && lastField(ref) == "status" && tables[qualifier(ref)] != "" {
						statuses[tables[qualifier(ref)]] = text
					}
				case expr.GetKind() == pgquery.A_Expr_Kind_AEXPR_OP && (op == "<" || op == ">" || op == "<=" || op == ">="),
					expr.GetKind() == pgquery.A_Expr_Kind_AEXPR_BETWEEN:
					for _, side := range []*pgquery.Node{expr.GetLexpr(), expr.GetRexpr()} {
						if ref := unCast(side).GetColumnRef(); ref != nil && strings.HasSuffix(lastField(ref), "_at") {
							compared = append(compared, ref)
						}
					}
				}
			}
			for _, ref := range compared {
				table := tables[qualifier(ref)]
				status, ok := statuses[table]
				column := lastField(ref)
				if table == "" || !ok || !strings.EqualFold(strings.TrimSuffix(column, "_at"), status) {
					continue
				}
				reads = append(reads, StageRead{Table: table, Column: column, Status: status, Offset: int(ref.GetLocation()) - shift})
			}
		})
	}
	return reads
}

// andTerms flattens the AND terms of a condition.
func andTerms(node *pgquery.Node) []*pgquery.Node {
	if b := node.GetBoolExpr(); b != nil && b.GetBoolop() == pgquery.BoolExprType_AND_EXPR {
		var terms []*pgquery.Node
		for _, arg := range b.GetArgs() {
			terms = append(terms, andTerms(arg)...)
		}
		return terms
	}
	return []*pgquery.Node{node}
}

// lastField is the lower-case column name of a reference.
func lastField(ref *pgquery.ColumnRef) string {
	fields := ref.GetFields()
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(fields[len(fields)-1].GetString_().GetSval())
}

// qualifier is the alias or table a reference names, "" for none.
func qualifier(ref *pgquery.ColumnRef) string {
	fields := ref.GetFields()
	if len(fields) < 2 {
		return ""
	}
	return strings.ToLower(fields[len(fields)-2].GetString_().GetSval())
}
