package sqlschema

import (
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
)

// Target is a column of the rows a SELECT returns.
type Target struct {
	// Name is the column name the row has, as PostgreSQL gives it: the
	// alias, the column read, the function called. It is empty where
	// PostgreSQL names the column ?column? or after a type.
	Name string
	// Nullable is a column read as it is that can be NULL: nullable in its
	// table, or from the outer side of a join. An expression, or a column the
	// schema does not know, is not.
	Nullable bool
	// Offset is the offset of the column in the text.
	Offset int
}

// targetSource is a relation of the FROM clause.
type targetSource struct {
	name  string
	table *Table // nil for a subquery, a function or a table the schema lacks
	outer bool   // on the outer side of a join: its columns can be NULL
	// notNull are the columns a condition every row meets keeps NULL out of.
	notNull map[string]bool
}

// SelectTargets returns the columns of a single SELECT, in order. Without a
// schema (nil) the names are known and nullability is not. It returns false
// for any other statement, a set operation, or a SELECT with *.
func SelectTargets(sql string, schema *Schema) ([]Target, bool) {
	result, ok := parse(sql)
	if !ok || len(result.GetStmts()) != 1 {
		return nil, false
	}
	sel := result.GetStmts()[0].GetStmt().GetSelectStmt()
	if sel == nil || sel.GetOp() != pgquery.SetOperation_SETOP_NONE || len(sel.GetTargetList()) == 0 {
		return nil, false
	}
	var sources []targetSource
	var quals []*pgquery.Node
	for _, item := range sel.GetFromClause() {
		sources, quals = appendSources(sources, quals, item, false, schema)
	}
	for _, qual := range append(quals, sel.GetWhereClause()) {
		markNotNull(qual, sources)
	}
	targets := make([]Target, 0, len(sel.GetTargetList()))
	for _, node := range sel.GetTargetList() {
		res := node.GetResTarget()
		if hasStar(res.GetVal()) {
			return nil, false
		}
		name := res.GetName()
		if name == "" {
			name = columnName(res.GetVal())
		}
		targets = append(targets, Target{
			Name:     name,
			Nullable: nullableRead(res.GetVal(), sources),
			Offset:   int(res.GetLocation()),
		})
	}
	return targets, true
}

// appendSources adds the relations of a FROM item, and the ON conditions of
// its inner joins, which every row meets.
func appendSources(sources []targetSource, quals []*pgquery.Node, item *pgquery.Node, outer bool, schema *Schema) ([]targetSource, []*pgquery.Node) {
	switch {
	case item.GetRangeVar() != nil:
		rv := item.GetRangeVar()
		source := targetSource{name: strings.ToLower(rv.GetRelname()), outer: outer}
		if rv.GetAlias() != nil {
			source.name = rv.GetAlias().GetAliasname()
		}
		if schema != nil {
			if table := schema.relation(rv, nil); table != nil && !table.View {
				source.table = table
			}
		}
		return append(sources, source), quals
	case item.GetJoinExpr() != nil:
		join := item.GetJoinExpr()
		kind := join.GetJointype()
		full := kind == pgquery.JoinType_JOIN_FULL
		sources, quals = appendSources(sources, quals, join.GetLarg(), outer || full || kind == pgquery.JoinType_JOIN_RIGHT, schema)
		sources, quals = appendSources(sources, quals, join.GetRarg(), outer || full || kind == pgquery.JoinType_JOIN_LEFT, schema)
		if kind == pgquery.JoinType_JOIN_INNER && !outer {
			quals = append(quals, join.GetQuals())
		}
		return sources, quals
	case item.GetRangeSubselect() != nil:
		return append(sources, targetSource{name: item.GetRangeSubselect().GetAlias().GetAliasname(), outer: outer}), quals
	case item.GetRangeFunction() != nil:
		return append(sources, targetSource{name: item.GetRangeFunction().GetAlias().GetAliasname(), outer: outer}), quals
	}
	return sources, quals
}

// markNotNull records the columns a condition keeps NULL out of: its AND
// terms that are IS NOT NULL or a comparison NULL never passes.
func markNotNull(qual *pgquery.Node, sources []targetSource) {
	if qual == nil {
		return
	}
	if boolExpr := qual.GetBoolExpr(); boolExpr != nil {
		if boolExpr.GetBoolop() == pgquery.BoolExprType_AND_EXPR {
			for _, arg := range boolExpr.GetArgs() {
				markNotNull(arg, sources)
			}
		}
		return
	}
	var operands []*pgquery.Node
	if test := qual.GetNullTest(); test != nil && test.GetNulltesttype() == pgquery.NullTestType_IS_NOT_NULL {
		operands = append(operands, test.GetArg())
	}
	if expr := qual.GetAExpr(); expr != nil {
		switch expr.GetKind() {
		case pgquery.A_Expr_Kind_AEXPR_OP, pgquery.A_Expr_Kind_AEXPR_OP_ANY, pgquery.A_Expr_Kind_AEXPR_OP_ALL,
			pgquery.A_Expr_Kind_AEXPR_IN, pgquery.A_Expr_Kind_AEXPR_LIKE, pgquery.A_Expr_Kind_AEXPR_ILIKE,
			pgquery.A_Expr_Kind_AEXPR_BETWEEN, pgquery.A_Expr_Kind_AEXPR_NOT_BETWEEN, pgquery.A_Expr_Kind_AEXPR_SIMILAR:
			operands = append(operands, expr.GetLexpr(), expr.GetRexpr())
		}
	}
	for _, operand := range operands {
		for operand.GetTypeCast() != nil {
			operand = operand.GetTypeCast().GetArg()
		}
		if source, column, ok := resolveColumn(operand.GetColumnRef(), sources); ok {
			if source.notNull == nil {
				source.notNull = make(map[string]bool)
			}
			source.notNull[column] = true
		}
	}
}

func hasStar(expr *pgquery.Node) bool {
	fields := expr.GetColumnRef().GetFields()
	return len(fields) > 0 && fields[len(fields)-1].GetAStar() != nil
}

// columnName names a column the way PostgreSQL does when the SELECT gives
// no alias; empty where it would say ?column? or name a type.
func columnName(expr *pgquery.Node) string {
	switch {
	case expr.GetColumnRef() != nil:
		fields := expr.GetColumnRef().GetFields()
		return fields[len(fields)-1].GetString_().GetSval()
	case expr.GetFuncCall() != nil:
		names := expr.GetFuncCall().GetFuncname()
		return names[len(names)-1].GetString_().GetSval()
	case expr.GetTypeCast() != nil:
		return columnName(expr.GetTypeCast().GetArg())
	case expr.GetCoalesceExpr() != nil:
		return "coalesce"
	case expr.GetMinMaxExpr() != nil:
		if expr.GetMinMaxExpr().GetOp() == pgquery.MinMaxOp_IS_GREATEST {
			return "greatest"
		}
		return "least"
	case expr.GetCaseExpr() != nil:
		return "case"
	case expr.GetAArrayExpr() != nil:
		return "array"
	case expr.GetRowExpr() != nil:
		return "row"
	case expr.GetAExpr() != nil && expr.GetAExpr().GetKind() == pgquery.A_Expr_Kind_AEXPR_NULLIF:
		return "nullif"
	case expr.GetSubLink() != nil:
		link := expr.GetSubLink()
		switch link.GetSubLinkType() {
		case pgquery.SubLinkType_EXISTS_SUBLINK:
			return "exists"
		case pgquery.SubLinkType_ARRAY_SUBLINK:
			return "array"
		case pgquery.SubLinkType_EXPR_SUBLINK:
			if targets := link.GetSubselect().GetSelectStmt().GetTargetList(); len(targets) == 1 {
				if name := targets[0].GetResTarget().GetName(); name != "" {
					return name
				}
				return columnName(targets[0].GetResTarget().GetVal())
			}
		}
	}
	return ""
}

// nullableRead reports a column read as it is, or through a type cast, that
// can be NULL.
func nullableRead(expr *pgquery.Node, sources []targetSource) bool {
	if cast := expr.GetTypeCast(); cast != nil {
		return nullableRead(cast.GetArg(), sources)
	}
	source, column, ok := resolveColumn(expr.GetColumnRef(), sources)
	if !ok || source.table == nil || source.notNull[column] {
		return false
	}
	found := source.table.Column(column)
	return found != nil && (!found.NotNull || source.outer)
}

// resolveColumn finds the source a column reference reads and the column's
// name; false when the reference is not a column or the source is not
// certain.
func resolveColumn(ref *pgquery.ColumnRef, sources []targetSource) (*targetSource, string, bool) {
	if ref == nil {
		return nil, "", false
	}
	var names []string
	for _, field := range ref.GetFields() {
		names = append(names, field.GetString_().GetSval())
	}
	column := strings.ToLower(names[len(names)-1])
	var candidates []*targetSource
	if len(names) >= 2 {
		qualifier := names[len(names)-2]
		for i := range sources {
			if sources[i].name == qualifier {
				candidates = append(candidates, &sources[i])
			}
		}
	} else {
		for i := range sources {
			if sources[i].table == nil {
				return nil, "", false // a subquery or a function may have the column: unknown
			}
			if sources[i].table.Column(column) != nil {
				candidates = append(candidates, &sources[i])
			}
		}
	}
	if len(candidates) != 1 {
		return nil, "", false
	}
	return candidates[0], column, true
}
