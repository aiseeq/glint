package sqlschema

import (
	"regexp"
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
)

// CurrencySum is a SUM of an amount over rows that can be in different
// currencies.
type CurrencySum struct {
	Offset int
	Table  string
	Column string
	// Currency are the currency columns of the table.
	Currency []string
}

// currencyColumn names a column holding the currency of a row's amounts.
var currencyColumn = regexp.MustCompile(`(?:^|_)(?:currency|currency_code|ccy)$`)

// amountTypes are the column types that hold an exact amount.
var amountTypes = map[string]bool{"numeric": true, "decimal": true, "money": true}

// integerTypes hold an amount in minor units when the name says so.
var integerTypes = map[string]bool{"int2": true, "int4": true, "int8": true, "bigint": true, "integer": true, "int": true}

// MixedCurrencySums returns the SUMs of an amount column of a table that has
// currency columns, in a SELECT that neither groups by one of them nor fixes
// one in its WHERE:
//
//	SELECT SUM(amount) FROM transfers WHERE created_at >= $1  -- transfers.currency
//
// Amounts in roubles and dollars add up to a number in no currency. Not
// reported: a sum over the rows of one parent (the WHERE fixes an id or a
// *_id column), a sum inside a subquery of another SELECT's columns, a table
// whose currency columns all have a default (kept in one currency).
func (s *Schema) MixedCurrencySums(sql string) []CurrencySum {
	if s == nil {
		return nil
	}
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var sums []CurrencySum
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			if sel, ok := m.(*pgquery.SelectStmt); ok {
				sums = append(sums, s.mixedSums(sel, shift)...)
			}
		})
	}
	return sums
}

func (s *Schema) mixedSums(sel *pgquery.SelectStmt, shift int) []CurrencySum {
	if len(sel.GetTargetList()) == 0 {
		return nil
	}
	tables, _ := s.fromTables(sel)
	fixed := make(map[string]bool)
	for _, ref := range pinnedColumns(sel.GetWhereClause()) {
		if ref.name == "id" || strings.HasSuffix(ref.name, "_id") {
			return nil
		}
		fixed[ref.name] = true
	}
	for _, item := range sel.GetGroupClause() {
		// GROUP BY 2 groups by the second column of the list.
		if n := int(item.GetAConst().GetIval().GetIval()); n > 0 && n <= len(sel.GetTargetList()) {
			item = sel.GetTargetList()[n-1]
		}
		walk(item.ProtoReflect(), func(m proto.Message) {
			if ref, ok := m.(*pgquery.ColumnRef); ok {
				fields := ref.GetFields()
				fixed[strings.ToLower(fields[len(fields)-1].GetString_().GetSval())] = true
			}
		})
	}
	var sums []CurrencySum
	for _, call := range ownAggregates(sel) {
		if funcName(call) != "sum" {
			continue
		}
		for _, arg := range call.GetArgs() {
			sum, ok := amountSum(tables, arg, fixed)
			if ok {
				sum.Offset = int(call.GetLocation()) - shift
				sums = append(sums, sum)
				break
			}
		}
	}
	return sums
}

// ownAggregates returns the function calls of a SELECT's columns, leaving
// out those of the subqueries among them.
func ownAggregates(sel *pgquery.SelectStmt) []*pgquery.FuncCall {
	nested := make(map[*pgquery.FuncCall]bool)
	var calls []*pgquery.FuncCall
	for _, target := range sel.GetTargetList() {
		walk(target.ProtoReflect(), func(m proto.Message) {
			if link, ok := m.(*pgquery.SubLink); ok {
				walk(link.ProtoReflect(), func(inner proto.Message) {
					if call, ok := inner.(*pgquery.FuncCall); ok {
						nested[call] = true
					}
				})
			}
		})
		walk(target.ProtoReflect(), func(m proto.Message) {
			if call, ok := m.(*pgquery.FuncCall); ok && !nested[call] {
				calls = append(calls, call)
			}
		})
	}
	return calls
}

// amountSum returns the amount column an argument of SUM reads, when its
// table has currency columns none of which fixed holds.
func amountSum(tables map[string]*Table, arg *pgquery.Node, fixed map[string]bool) (CurrencySum, bool) {
	var found CurrencySum
	ok := false
	walk(arg.ProtoReflect(), func(m proto.Message) {
		ref, isRef := m.(*pgquery.ColumnRef)
		if !isRef || ok {
			return
		}
		fields := ref.GetFields()
		name := strings.ToLower(fields[len(fields)-1].GetString_().GetSval())
		table := refTable(tables, fields, name)
		if table == nil {
			return
		}
		column := table.Column(name)
		if column == nil || !amountColumn(column) {
			return
		}
		var currencies []string
		defaulted := true
		for _, other := range table.columns {
			if currencyColumn.MatchString(other.Name) {
				if fixed[other.Name] {
					return
				}
				currencies = append(currencies, other.Name)
				defaulted = defaulted && other.HasDefault
			}
		}
		// A currency every row gets by default (DEFAULT 'USDC') marks a
		// table kept in one currency.
		if len(currencies) > 0 && !defaulted {
			found, ok = CurrencySum{Table: table.Name, Column: name, Currency: currencies}, true
		}
	})
	return found, ok
}

// amountColumn reports a column holding an exact amount: a numeric one, or
// an integer named for an amount (amount_cents).
func amountColumn(column *Column) bool {
	return amountTypes[column.Type] || (integerTypes[column.Type] && moneyColumn.MatchString(column.Name))
}

// refTable returns the table of the FROM clause a column reference reads:
// by its qualifier, or the one table that has the column.
func refTable(tables map[string]*Table, fields []*pgquery.Node, name string) *Table {
	if len(fields) == 2 {
		return tables[fields[0].GetString_().GetSval()]
	}
	var owner *Table
	for _, table := range tables {
		if table != nil && table.Column(name) != nil {
			if owner != nil {
				return nil
			}
			owner = table
		}
	}
	return owner
}
