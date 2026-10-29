package sqlschema

import (
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
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
	var visitSelect func(*pgquery.SelectStmt, map[string]bool)
	var visitNested func(protoreflect.Message, map[string]bool)
	visitSelect = func(sel *pgquery.SelectStmt, inherited map[string]bool) {
		ctes := make(map[string]bool, len(inherited))
		for name := range inherited {
			ctes[name] = true
		}
		if clause := sel.GetWithClause(); clause != nil {
			for _, item := range clause.GetCtes() {
				if cte := item.GetCommonTableExpr(); cte != nil {
					ctes[strings.ToLower(cte.GetCtename())] = true
				}
			}
		}
		var visitFrom func(*pgquery.Node, bool)
		visitFrom = func(node *pgquery.Node, nullable bool) {
			switch {
			case node.GetRangeVar() != nil:
				rv := node.GetRangeVar()
				if rv.GetSchemaname() == "" && ctes[strings.ToLower(rv.GetRelname())] {
					return
				}
				alias := tableName(rv)
				if rv.GetAlias() != nil {
					alias = strings.ToLower(rv.GetAlias().GetAliasname())
				}
				reads = append(reads, TableRead{
					Table: tableName(rv), Alias: alias, Offset: max(0, int(rv.GetLocation())-shift),
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
		sel.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			if field.Message() == nil || field.IsMap() {
				return true
			}
			if field.IsList() {
				list := value.List()
				for i := 0; i < list.Len(); i++ {
					visitNested(list.Get(i).Message(), ctes)
				}
				return true
			}
			visitNested(value.Message(), ctes)
			return true
		})
	}
	visitNested = func(message protoreflect.Message, ctes map[string]bool) {
		if !message.IsValid() {
			return
		}
		if sel, ok := message.Interface().(*pgquery.SelectStmt); ok {
			visitSelect(sel, ctes)
			return
		}
		message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			if field.Message() == nil || field.IsMap() {
				return true
			}
			if field.IsList() {
				list := value.List()
				for i := 0; i < list.Len(); i++ {
					visitNested(list.Get(i).Message(), ctes)
				}
				return true
			}
			visitNested(value.Message(), ctes)
			return true
		})
	}
	for _, raw := range result.GetStmts() {
		visitNested(raw.GetStmt().ProtoReflect(), nil)
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
