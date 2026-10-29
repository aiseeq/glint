package sqlschema

import (
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
)

// TableRead describes a table read by a SELECT, including reads in nested
// queries. OuterJoin is true when the table is on the null-extended side of
// an outer join.
type TableRead struct {
	Table       string
	Alias       string
	Offset      int
	OuterJoin   bool
	NullChecked bool
}

// ReadTables returns table references in SELECT statements, including
// EXISTS, IN subqueries, and nested SELECTs. It ignores tables targeted by
// UPDATE, DELETE, and INSERT.
func ReadTables(sql string) []TableRead {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var reads []TableRead
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			sel, ok := m.(*pgquery.SelectStmt)
			if !ok {
				return
			}
			var visitFrom func(*pgquery.Node, bool)
			visitFrom = func(node *pgquery.Node, nullable bool) {
				switch {
				case node.GetRangeVar() != nil:
					rv := node.GetRangeVar()
					alias := strings.ToLower(rv.GetRelname())
					if rv.GetAlias() != nil {
						alias = strings.ToLower(rv.GetAlias().GetAliasname())
					}
					reads = append(reads, TableRead{
						Table: strings.ToLower(rv.GetRelname()), Alias: alias, Offset: max(0, int(rv.GetLocation())-shift),
						OuterJoin: nullable, NullChecked: whereNullChecks(sel.GetWhereClause(), alias),
					})
				case node.GetJoinExpr() != nil:
					join := node.GetJoinExpr()
					switch join.GetJointype() {
					case pgquery.JoinType_JOIN_LEFT:
						visitFrom(join.GetLarg(), nullable)
						visitFrom(join.GetRarg(), true)
					case pgquery.JoinType_JOIN_RIGHT:
						visitFrom(join.GetLarg(), true)
						visitFrom(join.GetRarg(), nullable)
					case pgquery.JoinType_JOIN_FULL:
						visitFrom(join.GetLarg(), true)
						visitFrom(join.GetRarg(), true)
					default:
						visitFrom(join.GetLarg(), nullable)
						visitFrom(join.GetRarg(), nullable)
					}
				}
			}
			for _, from := range sel.GetFromClause() {
				visitFrom(from, false)
			}
		})
	}
	return reads
}

func whereNullChecks(node *pgquery.Node, alias string) bool {
	if node == nil {
		return false
	}
	var checked bool
	var visit func(*pgquery.Node)
	visit = func(n *pgquery.Node) {
		if checked || n == nil {
			return
		}
		if test := n.GetNullTest(); test != nil {
			walk(test.GetArg().ProtoReflect(), func(m proto.Message) {
				column, ok := m.(*pgquery.ColumnRef)
				if !ok || len(column.GetFields()) < 2 {
					return
				}
				fields := column.GetFields()
				if strings.EqualFold(fields[len(fields)-2].GetString_().GetSval(), alias) {
					checked = true
				}
			})
			return
		}
		if b := n.GetBoolExpr(); b != nil {
			for _, arg := range b.GetArgs() {
				visit(arg)
			}
		}
	}
	visit(node)
	return checked
}
