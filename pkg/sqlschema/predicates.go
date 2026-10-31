package sqlschema

import (
	"fmt"

	"slices"
	"sort"
	"strings"
	"unicode"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Conjunct is one top-level term of a SQL condition.
type Conjunct struct {
	Norm         string
	Alias        string
	Offset       int
	ScopeOffset  int
	HasLiteral   bool
	Params       []int
	Operator     string
	GuardedByKey bool
}

// InList describes a literal membership condition.
type InList struct {
	Column              string
	Table               string
	Values              []string
	Negated             bool
	Offset              int
	ScopeOffset         int
	Operator            string
	GuardedByKey        bool
	UnionOfHandledCases bool
}

// ConditionConjuncts parses a condition fragment or SQL statement and returns
// the top-level conjuncts of its outermost WHERE clause.
func ConditionConjuncts(fragment string) []Conjunct {
	return conjuncts(fragment, true)
}

// Conjuncts returns conjuncts from every WHERE, JOIN ON and HAVING clause,
// including clauses in nested queries and set-operation branches.
func Conjuncts(sql string) []Conjunct { return conjuncts(sql, false) }

func conjuncts(sql string, outer bool) []Conjunct {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var out []Conjunct
	var visitFailure string
	var visitStmt func(*pgquery.Node)
	visitStmt = func(node *pgquery.Node) {
		if node == nil || visitFailure != "" {
			return
		}
		switch {
		case node.GetSelectStmt() != nil:
			s := node.GetSelectStmt()
			tables := levelTables(s.GetFromClause())
			scopeOffset := selectScopeOffset(s.GetFromClause(), shift)
			visitFailure = collectCondition(&out, s.GetWhereClause(), "SELECT", shift, scopeOffset)
			if visitFailure == "" {
				visitFailure = collectJoins(&out, s.GetFromClause(), "SELECT", tables, shift, scopeOffset)
			}
			if visitFailure == "" {
				visitFailure = collectCondition(&out, s.GetHavingClause(), "SELECT", shift, scopeOffset)
			}
			if visitFailure == "" {
				visitFailure = collectAggregateFilters(&out, s.GetTargetList(), shift, scopeOffset)
			}
			if s.GetLarg() != nil {
				visitStmt(&pgquery.Node{Node: &pgquery.Node_SelectStmt{SelectStmt: s.GetLarg()}})
			}
			if s.GetRarg() != nil {
				visitStmt(&pgquery.Node{Node: &pgquery.Node_SelectStmt{SelectStmt: s.GetRarg()}})
			}
			if s.GetWithClause() != nil {
				for _, c := range s.GetWithClause().GetCtes() {
					visitStmt(c.GetCommonTableExpr().GetCtequery())
				}
			}
			if outer {
				return
			}
			walk(node.ProtoReflect(), func(m proto.Message) {
				if sub, ok := m.(*pgquery.SubLink); ok && sub.GetSubselect() != nil {
					visitStmt(sub.GetSubselect())
				}
				if sub, ok := m.(*pgquery.RangeSubselect); ok && sub.GetSubquery() != nil {
					visitStmt(sub.GetSubquery())
				}
			})
		case node.GetUpdateStmt() != nil:
			s := node.GetUpdateStmt()
			visitFailure = collectCondition(&out, s.GetWhereClause(), "UPDATE", shift, 0)
			if !outer && visitFailure == "" {
				visitNested(node, visitStmt)
			}
		case node.GetDeleteStmt() != nil:
			s := node.GetDeleteStmt()
			visitFailure = collectCondition(&out, s.GetWhereClause(), "DELETE", shift, 0)
			if !outer && visitFailure == "" {
				visitNested(node, visitStmt)
			}
		}
	}
	for _, raw := range result.GetStmts() {
		visitStmt(raw.GetStmt())
	}
	if visitFailure != "" {
		// The public API represents normalization failures as an empty result.
		return nil
	}
	seen := make(map[string]bool, len(out))
	unique := out[:0]
	for _, conjunct := range out {
		key := fmt.Sprintf("%s:%d:%s", conjunct.Operator, conjunct.Offset, conjunct.Norm)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, conjunct)
		}
	}
	return unique
}

func collectAggregateFilters(out *[]Conjunct, targets []*pgquery.Node, shift, scopeOffset int) string {
	var failure string
	for _, target := range targets {
		walk(target.ProtoReflect(), func(m proto.Message) {
			if call, ok := m.(*pgquery.FuncCall); ok && call.GetAggFilter() != nil && failure == "" {
				failure = collectCondition(out, call.GetAggFilter(), "SELECT", shift, scopeOffset)
			}
		})
		if failure != "" {
			return failure
		}
	}
	return failure
}

func visitNested(node *pgquery.Node, visit func(*pgquery.Node)) {
	walk(node.ProtoReflect(), func(m proto.Message) {
		switch nested := m.(type) {
		case *pgquery.SubLink:
			if nested.GetSubselect() != nil {
				visit(nested.GetSubselect())
			}
		case *pgquery.RangeSubselect:
			if nested.GetSubquery() != nil {
				visit(nested.GetSubquery())
			}
		case *pgquery.CommonTableExpr:
			if nested.GetCtequery() != nil {
				visit(nested.GetCtequery())
			}
		}
	})
}

func collectJoins(out *[]Conjunct, from []*pgquery.Node, op string, tables map[string]string, shift, scopeOffset int) string {
	for _, n := range from {
		if j := n.GetJoinExpr(); j != nil {
			if failure := collectCondition(out, j.GetQuals(), op, shift, scopeOffset); failure != "" {
				return "collect join condition: " + failure
			}
			if failure := collectJoins(out, []*pgquery.Node{j.GetLarg(), j.GetRarg()}, op, tables, shift, scopeOffset); failure != "" {
				return failure
			}
		}
	}
	return ""
}
func collectCondition(out *[]Conjunct, n *pgquery.Node, op string, shift, scopeOffset int) string {
	if n == nil {
		return ""
	}
	terms := splitAndTerms(n)
	guarded := hasKeyGuard(terms)
	for _, term := range terms {
		norm, err := deparseExpr(term)
		if err != nil {
			return fmt.Sprintf("deparse %s condition at offset %d: %v", op, exprLocation(term), err)
		}
		params, lit := exprParams(term)
		alias := ""
		if comparison := term.GetAExpr(); comparison != nil {
			if column, ok := columnOf(comparison.GetLexpr()); ok {
				alias = column.qualifier
			}
		}
		*out = append(*out, Conjunct{Norm: norm, Alias: alias, Offset: max(0, exprLocation(term)-shift), ScopeOffset: scopeOffset, HasLiteral: lit, Params: params, Operator: op, GuardedByKey: guarded})
	}
	return ""
}
func normalizeDeparsedSQL(text string) string {
	var normalized strings.Builder
	quoted, space := false, false
	runes := []rune(strings.TrimSpace(text))
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if quoted {
			normalized.WriteRune(r)
			if r == '\'' {
				if i+1 < len(runes) && runes[i+1] == '\'' {
					i++
					normalized.WriteRune(runes[i])
				} else {
					quoted = false
				}
			}
			continue
		}
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if space && normalized.Len() > 0 {
			normalized.WriteByte(' ')
		}
		space = false
		if r == '\'' {
			quoted = true
			normalized.WriteRune(r)
		} else {
			normalized.WriteString(strings.ToLower(string(r)))
		}
	}
	return normalized.String()
}

func splitAndTerms(node *pgquery.Node) []*pgquery.Node {
	var terms []*pgquery.Node
	var split func(*pgquery.Node)
	split = func(current *pgquery.Node) {
		if boolean := current.GetBoolExpr(); boolean != nil && boolean.GetBoolop() == pgquery.BoolExprType_AND_EXPR {
			for _, arg := range boolean.GetArgs() {
				split(arg)
			}
			return
		}
		terms = append(terms, current)
	}
	split(node)
	return terms
}

func hasKeyGuard(terms []*pgquery.Node) bool {
	for _, t := range terms {
		a := t.GetAExpr()
		if a == nil || len(a.GetName()) != 1 || a.GetName()[0].GetString_().GetSval() != "=" {
			continue
		}
		col, _ := columnOf(a.GetLexpr())
		param := a.GetRexpr().GetParamRef() != nil
		if param && col.name == "id" {
			return true
		}
	}
	return false
}
func exprParams(n *pgquery.Node) ([]int, bool) {
	var params []int
	literal := false
	walk(n.ProtoReflect(), func(m proto.Message) {
		switch x := m.(type) {
		case *pgquery.ParamRef:
			params = append(params, int(x.GetNumber()))
		case *pgquery.A_Const:
			if x.GetIsnull() {
				return
			}
			if x.GetIval() != nil || x.GetFval() != nil || x.GetSval() != nil || x.GetBoolval() != nil {
				literal = true
			}
		}
	})
	slices.Sort(params)
	params = slices.Compact(params)
	return params, literal
}
func exprLocation(n *pgquery.Node) int {
	switch {
	case n.GetAExpr() != nil:
		return int(n.GetAExpr().GetLocation())
	case n.GetBoolExpr() != nil:
		return int(n.GetBoolExpr().GetLocation())
	case n.GetNullTest() != nil:
		return int(n.GetNullTest().GetLocation())
	case n.GetSubLink() != nil:
		return int(n.GetSubLink().GetLocation())
	case n.GetBooleanTest() != nil:
		return int(n.GetBooleanTest().GetLocation())
	default:
		return 0
	}
}
func deparseExpr(expr *pgquery.Node) (string, error) {
	cloned := proto.Clone(expr)
	clone, ok := cloned.(*pgquery.Node)
	if !ok {
		return "", fmt.Errorf("clone SQL expression: got %T", cloned)
	}
	var conjunctions []*pgquery.BoolExpr
	walk(clone.ProtoReflect(), func(m proto.Message) {
		switch node := m.(type) {
		case *pgquery.ColumnRef:
			if len(node.GetFields()) > 1 {
				node.Fields = []*pgquery.Node{node.Fields[len(node.Fields)-1]}
			}
		case *pgquery.RangeVar:
			node.Alias = nil
		case *pgquery.A_Expr:
			if len(node.GetName()) == 1 && node.GetName()[0].GetString_().GetSval() == "!=" {
				node.Name[0].GetString_().Sval = "<>"
			}
			if node.GetKind() == pgquery.A_Expr_Kind_AEXPR_IN && node.GetRexpr().GetList() != nil {
				items := node.GetRexpr().GetList().GetItems()
				slices.SortFunc(items, func(x, y *pgquery.Node) int {
					xv, _ := literalText(x)
					yv, _ := literalText(y)
					return strings.Compare(xv, yv)
				})
			}
		case *pgquery.BoolExpr:
			if node.GetBoolop() == pgquery.BoolExprType_AND_EXPR {
				conjunctions = append(conjunctions, node)
			}
		}
	})
	for i := len(conjunctions) - 1; i >= 0; i-- {
		if err := sortAndTerms(conjunctions[i]); err != nil {
			return "", fmt.Errorf("normalize AND expression: %w", err)
		}
	}
	return deparseTreeText(clone)
}

func sortAndTerms(expression *pgquery.BoolExpr) error {
	type term struct {
		node *pgquery.Node
		text string
	}
	terms := make([]term, 0, len(expression.GetArgs()))
	for _, arg := range expression.GetArgs() {
		text, err := deparseTreeText(arg)
		if err != nil {
			return fmt.Errorf("deparse AND term: %w", err)
		}
		terms = append(terms, term{node: arg, text: text})
	}
	sort.Slice(terms, func(i, j int) bool { return terms[i].text < terms[j].text })
	for i := range terms {
		expression.Args[i] = terms[i].node
	}
	return nil
}

func deparseTreeText(expression *pgquery.Node) (string, error) {
	seed, err := pgquery.Parse("SELECT 1 WHERE TRUE")
	if err != nil {
		return "", fmt.Errorf("parse SQL deparse seed: %w", err)
	}
	seed.GetStmts()[0].GetStmt().GetSelectStmt().WhereClause = expression
	text, err := pgquery.Deparse(seed)
	if err != nil {
		return "", fmt.Errorf("deparse SQL expression: %w", err)
	}
	text = strings.TrimSpace(strings.TrimPrefix(text, "SELECT 1 WHERE "))
	return normalizeDeparsedSQL(text), nil
}

// InLists returns literal IN and ANY membership lists found in SQL.
func InLists(sql string) []InList {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var out []InList
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			switch stmt := m.(type) {
			case *pgquery.SelectStmt:
				tables := levelTables(stmt.GetFromClause())
				scopeOffset := selectScopeOffset(stmt.GetFromClause(), shift)
				start := len(out)
				equalities := selectLiteralEqualities(stmt, tables)
				collectInLists(&out, stmt.GetWhereClause(), tables, shift)
				collectInLists(&out, stmt.GetHavingClause(), tables, shift)
				collectJoinInLists(&out, stmt.GetFromClause(), tables, shift)
				collectTargetInLists(&out, stmt.GetTargetList(), tables, shift)
				for i := start; i < len(out); i++ {
					in := &out[i]
					in.ScopeOffset = scopeOffset
					handled := equalities[in.Table+"\x00"+in.Column]
					if len(handled) == 0 {
						continue
					}
					in.UnionOfHandledCases = true
					for _, value := range in.Values {
						if !handled[value] {
							in.UnionOfHandledCases = false
							break
						}
					}
				}
			case *pgquery.UpdateStmt:
				collectInLists(&out, stmt.GetWhereClause(), relationTables(stmt.GetRelation()), shift)
			case *pgquery.DeleteStmt:
				collectInLists(&out, stmt.GetWhereClause(), relationTables(stmt.GetRelation()), shift)
			}
		})
	}
	return out
}

func collectTargetInLists(out *[]InList, targets []*pgquery.Node, tables map[string]string, shift int) {
	for _, target := range targets {
		if value := target.GetResTarget().GetVal(); value != nil {
			walkTargetExpressions(value.ProtoReflect(), func(expr *pgquery.A_Expr) {
				appendInList(out, expr, tables, shift, false)
			})
		}
	}
}

func selectLiteralEqualities(stmt *pgquery.SelectStmt, tables map[string]string) map[string]map[string]bool {
	equalities := make(map[string]map[string]bool)
	collect := func(node *pgquery.Node) {
		walkTargetExpressions(node.ProtoReflect(), func(expr *pgquery.A_Expr) {
			if expr.GetKind() != pgquery.A_Expr_Kind_AEXPR_OP || len(expr.GetName()) != 1 || expr.GetName()[0].GetString_().GetSval() != "=" {
				return
			}
			for _, pair := range [][2]*pgquery.Node{{expr.GetLexpr(), expr.GetRexpr()}, {expr.GetRexpr(), expr.GetLexpr()}} {
				column, ok := columnOf(pair[0])
				value, literal := literalText(pair[1])
				if !ok || !literal {
					continue
				}
				table := tables[column.qualifier]
				key := table + "\x00" + column.name
				if equalities[key] == nil {
					equalities[key] = make(map[string]bool)
				}
				equalities[key][value] = true
			}
		})
	}
	for _, target := range stmt.GetTargetList() {
		if value := target.GetResTarget().GetVal(); value != nil {
			collect(value)
		}
	}
	collect(stmt.GetWhereClause())
	collect(stmt.GetHavingClause())
	var collectJoins func([]*pgquery.Node)
	collectJoins = func(from []*pgquery.Node) {
		for _, node := range from {
			if join := node.GetJoinExpr(); join != nil {
				collect(join.GetQuals())
				collectJoins([]*pgquery.Node{join.GetLarg(), join.GetRarg()})
			}
		}
	}
	collectJoins(stmt.GetFromClause())
	return equalities
}

func walkTargetExpressions(message protoreflect.Message, visit func(*pgquery.A_Expr)) {
	if !message.IsValid() {
		return
	}
	switch message.Interface().(type) {
	case *pgquery.SubLink, *pgquery.RangeSubselect:
		return
	case *pgquery.A_Expr:
		if expr, ok := message.Interface().(*pgquery.A_Expr); ok {
			visit(expr)
		}
	}
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Message() == nil || field.IsMap() {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := range list.Len() {
				walkTargetExpressions(list.Get(i).Message(), visit)
			}
			return true
		}
		walkTargetExpressions(value.Message(), visit)
		return true
	})
}

func relationTables(relation *pgquery.RangeVar) map[string]string {
	if relation == nil {
		return nil
	}
	name := strings.ToLower(relation.GetRelname())
	tables := map[string]string{"": name, name: name}
	if relation.GetAlias() != nil {
		tables[strings.ToLower(relation.GetAlias().GetAliasname())] = name
	}
	return tables
}

func collectJoinInLists(out *[]InList, from []*pgquery.Node, tables map[string]string, shift int) {
	for _, node := range from {
		if join := node.GetJoinExpr(); join != nil {
			collectInLists(out, join.GetQuals(), tables, shift)
			collectJoinInLists(out, []*pgquery.Node{join.GetLarg(), join.GetRarg()}, tables, shift)
		}
	}
}

func collectInLists(out *[]InList, condition *pgquery.Node, tables map[string]string, shift int) {
	if condition == nil {
		return
	}
	terms := splitAndTerms(condition)
	guarded := hasKeyGuard(terms)
	levelExpressions(condition, func(expr *pgquery.A_Expr) {
		appendInList(out, expr, tables, shift, guarded)
	})
}

func appendInList(out *[]InList, expr *pgquery.A_Expr, tables map[string]string, shift int, guarded bool) {
	op := ""
	negated := false
	if expr.GetKind() == pgquery.A_Expr_Kind_AEXPR_IN {
		op = "IN"
		if len(expr.GetName()) > 0 {
			negated = expr.GetName()[0].GetString_().GetSval() == "<>"
		}
	} else if expr.GetKind() == pgquery.A_Expr_Kind_AEXPR_OP_ANY && len(expr.GetName()) == 1 && expr.GetName()[0].GetString_().GetSval() == "=" {
		op = "ANY"
	} else {
		return
	}
	column, ok := columnOf(expr.GetLexpr())
	if !ok {
		return
	}
	values := literalList(expr.GetRexpr())
	if len(values) == 0 {
		return
	}
	slices.Sort(values)
	*out = append(*out, InList{Column: column.name, Table: tables[column.qualifier], Values: values, Negated: negated, Offset: max(0, int(expr.GetLocation())-shift), Operator: op, GuardedByKey: guarded})
}
func literalList(n *pgquery.Node) []string {
	var vals []string
	if l := n.GetList(); l != nil {
		for _, item := range l.GetItems() {
			s, ok := literalText(item)
			if !ok {
				return nil
			}
			vals = append(vals, s)
		}
	} else if ar := n.GetArrayExpr(); ar != nil {
		for _, item := range ar.GetElements() {
			s, ok := literalText(item)
			if !ok {
				return nil
			}
			vals = append(vals, s)
		}
	} else if ar := n.GetAArrayExpr(); ar != nil {
		for _, item := range ar.GetElements() {
			s, ok := literalText(item)
			if !ok {
				return nil
			}
			vals = append(vals, s)
		}
	} else if c := n.GetAConst(); c != nil {
		if s, ok := literalText(n); ok {
			for v := range strings.SplitSeq(strings.Trim(s, "{}"), ",") {
				vals = append(vals, strings.Trim(strings.TrimSpace(v), `"`))
			}
		}
	}
	return vals
}
func literalText(n *pgquery.Node) (string, bool) {
	c := n.GetAConst()
	if c == nil {
		return "", false
	}
	if s := c.GetSval(); s != nil {
		return s.GetSval(), true
	}
	if i := c.GetIval(); i != nil {
		return fmt.Sprint(i.GetIval()), true
	}
	if f := c.GetFval(); f != nil {
		return f.GetFval(), true
	}
	return "", false
}
