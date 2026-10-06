package sqlschema

import (
	"cmp"
	"strconv"
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
)

// ValueCheck is a CHECK constraint keeping a column within a set of values
// (status IN ('new', 'done')) or a range (score BETWEEN 1 AND 10).
type ValueCheck struct {
	// Name is the constraint's name: the one given, or the one PostgreSQL
	// makes (<table>_<column>_check).
	Name string
	// Values is the set, as written; empty for a range.
	Values []string
	// Low and High are the bounds of a range; empty for a set.
	Low, High string
}

// String renders the condition as the migration writes it.
func (c *ValueCheck) String(column string) string {
	if len(c.Values) > 0 {
		return column + " IN ('" + strings.Join(c.Values, "', '") + "')"
	}
	return column + " BETWEEN " + c.Low + " AND " + c.High
}

// addCheck records a CHECK constraint of the table that keeps one column
// within a set or a range; any other condition is left out.
func (t *Table) addCheck(name, column string, expr *pgquery.Node) {
	aexpr := expr.GetAExpr()
	if aexpr == nil {
		return
	}
	if ref := refName(aexpr.GetLexpr()); ref != "" {
		column = ref
	}
	target := t.Column(column)
	if target == nil {
		return
	}
	check := &ValueCheck{Name: strings.ToLower(cmp.Or(name, t.Name+"_"+target.Name+"_check"))}
	items := aexpr.GetRexpr().GetList().GetItems()
	switch aexpr.GetKind() {
	case pgquery.A_Expr_Kind_AEXPR_IN:
		if operatorName(aexpr) != "=" {
			return // NOT IN
		}
		for _, item := range items {
			value, ok := constantText(item)
			if !ok {
				return
			}
			check.Values = append(check.Values, value)
		}
	case pgquery.A_Expr_Kind_AEXPR_BETWEEN:
		if len(items) != 2 {
			return
		}
		low, okLow := constantText(items[0])
		high, okHigh := constantText(items[1])
		if !okLow || !okHigh {
			return
		}
		check.Low, check.High = low, high
	default:
		return
	}
	if len(check.Values) == 0 && check.Low == "" {
		return
	}
	target.Check = check
}

// dropCheck removes the CHECK constraint of that name.
func (t *Table) dropCheck(name string) {
	name = strings.ToLower(name)
	for _, column := range t.columns {
		if column.Check != nil && column.Check.Name == name {
			column.Check = nil
		}
	}
}

// operatorName returns the operator of an expression: = for IN, <> for NOT IN.
func operatorName(aexpr *pgquery.A_Expr) string {
	names := aexpr.GetName()
	if len(names) == 0 {
		return ""
	}
	return names[len(names)-1].GetString_().GetSval()
}

// constantText returns a string or integer constant as text, a cast aside.
func constantText(node *pgquery.Node) (string, bool) {
	for node.GetTypeCast() != nil {
		node = node.GetTypeCast().GetArg()
	}
	c := node.GetAConst()
	switch {
	case c == nil:
		return "", false
	case c.GetSval() != nil:
		return c.GetSval().GetSval(), true
	case c.GetIval() != nil:
		return strconv.Itoa(int(c.GetIval().GetIval())), true
	case c.GetFval() != nil:
		return c.GetFval().GetFval(), true
	}
	return "", false
}
