package sqlschema

import (
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	parser "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Problem is a reference of a query the schema does not have.
type Problem struct {
	// Kind is unknown_table, unknown_column or missing_not_null.
	Kind string
	// Name is the table or the column.
	Name string
	// Table is the table the column was looked up in, when one was.
	Table string
	// Offset is the byte offset of the reference in the query text.
	Offset int
}

// source is a relation a statement reads or writes, under the name its
// columns are qualified with.
type source struct {
	name  string
	table *Table // nil: its columns are not known (a CTE, a subquery, a function, a view, a catalog)
}

// queryRefs are the references of a statement, collected in one pass over
// its tree. Scopes are flattened: a name bound anywhere in the statement
// resolves everywhere in it, which only ever hides a problem.
type queryRefs struct {
	ctes       map[string]bool
	sources    []source
	opaque     bool
	outputs    map[string]bool
	columns    []*pgquery.ColumnRef
	relations  []*pgquery.RangeVar
	written    []writtenColumn
	inserts    []*pgquery.InsertStmt
	insertInto string
}

// writtenColumn is a column an INSERT lists or an UPDATE sets.
type writtenColumn struct {
	table    string
	name     string
	location int32
}

// CheckQuery parses a statement and returns the references to tables and
// columns the schema does not have, and the NOT NULL columns without a
// default an INSERT leaves out. It returns false for text that is not a
// whole statement.
func (s *Schema) CheckQuery(sql string) ([]Problem, bool) {
	result, ok := parse(sql)
	if !ok || len(result.GetStmts()) == 0 {
		return nil, false
	}
	var problems []Problem
	for _, raw := range result.GetStmts() {
		if !isQuery(raw.GetStmt()) {
			continue
		}
		refs := s.collect(raw.GetStmt())
		problems = append(problems, s.check(refs)...)
	}
	return problems, true
}

// parse parses text written in the code. Text that does not parse is not a
// statement — a message, a fragment of one — which is the answer, not a
// failure: the parser's error says only where the grammar stopped.
func parse(sql string) (*pgquery.ParseResult, bool) {
	if result, err := parser.Parse(sql); err == nil {
		return result, true
	}
	return nil, false
}

// isQuery reports a statement that reads or writes rows; DDL written in the
// code is not checked.
func isQuery(stmt *pgquery.Node) bool {
	return stmt.GetSelectStmt() != nil || stmt.GetInsertStmt() != nil || stmt.GetUpdateStmt() != nil || stmt.GetDeleteStmt() != nil
}

func (s *Schema) collect(stmt *pgquery.Node) *queryRefs {
	refs := &queryRefs{ctes: make(map[string]bool), outputs: make(map[string]bool)}
	// FOR UPDATE OF names sources of the FROM clause, by alias or by name.
	locked := make(map[*pgquery.RangeVar]bool)
	walk(stmt.ProtoReflect(), func(m proto.Message) {
		switch node := m.(type) {
		case *pgquery.CommonTableExpr:
			refs.ctes[strings.ToLower(node.GetCtename())] = true
		case *pgquery.LockingClause:
			for _, rel := range node.GetLockedRels() {
				locked[rel.GetRangeVar()] = true
			}
		}
	})
	walk(stmt.ProtoReflect(), func(m proto.Message) {
		switch node := m.(type) {
		case *pgquery.RangeVar:
			if locked[node] {
				return
			}
			refs.relations = append(refs.relations, node)
			name := strings.ToLower(node.GetRelname())
			alias := name
			if node.GetAlias() != nil {
				alias = strings.ToLower(node.GetAlias().GetAliasname())
			}
			table := s.relation(node, refs.ctes)
			if table == nil || table.View {
				refs.opaque = true
				table = nil
			}
			refs.sources = append(refs.sources, source{name: alias, table: table})
		case *pgquery.RangeSubselect, *pgquery.RangeFunction, *pgquery.RangeTableFunc, *pgquery.JsonTable:
			refs.opaque = true
		case *pgquery.ColumnRef:
			refs.columns = append(refs.columns, node)
		case *pgquery.ResTarget:
			if node.GetName() != "" {
				refs.outputs[strings.ToLower(node.GetName())] = true
			}
		case *pgquery.InsertStmt:
			refs.inserts = append(refs.inserts, node)
			table := strings.ToLower(node.GetRelation().GetRelname())
			refs.insertInto = table
			for _, col := range node.GetCols() {
				target := col.GetResTarget()
				refs.written = append(refs.written, writtenColumn{table: table, name: target.GetName(), location: target.GetLocation()})
			}
			for _, elem := range node.GetOnConflictClause().GetInfer().GetIndexElems() {
				if name := elem.GetIndexElem().GetName(); name != "" {
					refs.written = append(refs.written, writtenColumn{table: table, name: name, location: node.GetRelation().GetLocation()})
				}
			}
		case *pgquery.UpdateStmt:
			table := strings.ToLower(node.GetRelation().GetRelname())
			for _, target := range node.GetTargetList() {
				res := target.GetResTarget()
				refs.written = append(refs.written, writtenColumn{table: table, name: res.GetName(), location: res.GetLocation()})
			}
		}
	})
	// ON CONFLICT ... DO UPDATE reads the proposed row as excluded.
	if refs.insertInto != "" {
		refs.sources = append(refs.sources, source{name: "excluded", table: s.Table(refs.insertInto)})
	}
	return refs
}

// relation returns the table of the schema a range variable names, or nil
// for a CTE, a catalog relation or a table the schema does not have.
func (s *Schema) relation(rv *pgquery.RangeVar, ctes map[string]bool) *Table {
	if !inUserSchema(rv) || ctes[strings.ToLower(rv.GetRelname())] {
		return nil
	}
	return s.Table(rv.GetRelname())
}

// toolTables are the tables migration tools keep their state in.
var toolTables = map[string]bool{
	"schema_migrations": true, "goose_db_version": true, "gorp_migrations": true,
	"flyway_schema_history": true, "atlas_schema_revisions": true,
}

// inUserSchema reports a relation of the application's own schema: not the
// catalog, information_schema, a pg_ relation or a migration tool's table.
func inUserSchema(rv *pgquery.RangeVar) bool {
	schema := strings.ToLower(rv.GetSchemaname())
	if schema != "" && schema != "public" {
		return false
	}
	name := strings.ToLower(rv.GetRelname())
	return !strings.HasPrefix(name, "pg_") && !toolTables[name]
}

func (s *Schema) check(refs *queryRefs) []Problem {
	var problems []Problem
	for _, rv := range refs.relations {
		name := strings.ToLower(rv.GetRelname())
		if inUserSchema(rv) && !refs.ctes[name] && s.Table(name) == nil {
			problems = append(problems, Problem{Kind: "unknown_table", Name: name, Offset: int(rv.GetLocation())})
		}
	}
	for _, ref := range refs.columns {
		if problem, ok := refs.checkColumn(ref); ok {
			problems = append(problems, problem)
		}
	}
	for _, written := range refs.written {
		table := s.Table(written.table)
		if table != nil && !table.View && table.Column(written.name) == nil {
			problems = append(problems, Problem{Kind: "unknown_column", Name: strings.ToLower(written.name), Table: table.Name, Offset: int(written.location)})
		}
	}
	for _, insert := range refs.inserts {
		problems = append(problems, s.missingNotNull(insert)...)
	}
	return problems
}

// checkColumn looks a column reference up: a qualified one in the source it
// names, a bare one in every source when all of them are known.
func (refs *queryRefs) checkColumn(ref *pgquery.ColumnRef) (Problem, bool) {
	var names []string
	for _, field := range ref.GetFields() {
		if field.GetAStar() != nil {
			return Problem{}, false
		}
		names = append(names, strings.ToLower(field.GetString_().GetSval()))
	}
	switch len(names) {
	case 1:
		name := names[0]
		if refs.opaque || refs.outputs[name] || len(refs.sources) == 0 {
			return Problem{}, false
		}
		for _, src := range refs.sources {
			if src.table == nil || src.table.Column(name) != nil {
				return Problem{}, false
			}
		}
		return Problem{Kind: "unknown_column", Name: name, Table: refs.sources[0].table.Name, Offset: int(ref.GetLocation())}, true
	case 2, 3:
		qualifier, name := names[len(names)-2], names[len(names)-1]
		for _, src := range refs.sources {
			if src.name != qualifier {
				continue
			}
			if src.table == nil || src.table.Column(name) != nil {
				return Problem{}, false
			}
			return Problem{Kind: "unknown_column", Name: name, Table: src.table.Name, Offset: int(ref.GetLocation())}, true
		}
	}
	return Problem{}, false
}

// missingNotNull returns the NOT NULL columns without a default an INSERT
// with a column list leaves out.
func (s *Schema) missingNotNull(insert *pgquery.InsertStmt) []Problem {
	table := s.relation(insert.GetRelation(), nil)
	if table == nil || table.View || len(insert.GetCols()) == 0 {
		return nil
	}
	listed := make(map[string]bool)
	for _, col := range insert.GetCols() {
		listed[strings.ToLower(col.GetResTarget().GetName())] = true
	}
	var problems []Problem
	for _, column := range table.columns {
		if column.NotNull && !column.HasDefault && !listed[column.Name] {
			problems = append(problems, Problem{Kind: "missing_not_null", Name: column.Name, Table: table.Name, Offset: int(insert.GetRelation().GetLocation())})
		}
	}
	return problems
}

// NotNullBinds returns, for an INSERT ... VALUES or an UPDATE ... SET, the
// NOT NULL column each bind parameter is written to, by parameter number: a
// NULL bound there fails the statement whatever the column's default.
func (s *Schema) NotNullBinds(sql string) map[int]string {
	binds := make(map[int]string)
	for param, column := range s.Binds(sql) {
		if column.NotNull {
			binds[param] = column.Name
		}
	}
	return binds
}

// Binds returns, for an INSERT ... VALUES or an UPDATE ... SET, the column
// each bind parameter is written to as it is (a cast aside), by parameter
// number.
func (s *Schema) Binds(sql string) map[int]*Column {
	result, ok := parse(sql)
	if !ok || len(result.GetStmts()) != 1 {
		return nil
	}
	binds := make(map[int]*Column)
	bind := func(table *Table, column string, value *pgquery.Node) {
		for value.GetTypeCast() != nil {
			value = value.GetTypeCast().GetArg()
		}
		ref := value.GetParamRef()
		if table == nil || ref == nil {
			return
		}
		if col := table.Column(column); col != nil {
			binds[int(ref.GetNumber())] = col
		}
	}
	stmt := result.GetStmts()[0].GetStmt()
	if insert := stmt.GetInsertStmt(); insert != nil {
		table := s.relation(insert.GetRelation(), nil)
		for _, row := range insert.GetSelectStmt().GetSelectStmt().GetValuesLists() {
			items := row.GetList().GetItems()
			for i, col := range insert.GetCols() {
				if i < len(items) {
					bind(table, strings.ToLower(col.GetResTarget().GetName()), items[i])
				}
			}
		}
	}
	if update := stmt.GetUpdateStmt(); update != nil {
		table := s.relation(update.GetRelation(), nil)
		for _, target := range update.GetTargetList() {
			res := target.GetResTarget()
			bind(table, strings.ToLower(res.GetName()), res.GetVal())
		}
	}
	return binds
}

// walk calls visit for every message of a parse tree.
func walk(m protoreflect.Message, visit func(proto.Message)) {
	if !m.IsValid() {
		return
	}
	visit(m.Interface())
	m.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Message() == nil || field.IsMap() {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := range list.Len() {
				walk(list.Get(i).Message(), visit)
			}
			return true
		}
		walk(value.Message(), visit)
		return true
	})
}

// Shape is what a single INSERT, UPDATE or SELECT writes or reads of one
// table.
type Shape struct {
	// Kind is insert, update or select.
	Kind  string
	Table string
	// Columns are the columns listed, in order; a selected expression counts
	// under its alias, or under the one column it reads.
	Columns []string
	// LastOffset is the offset of the last column in the text.
	LastOffset int
}

// Shape returns the table and the columns of an INSERT with a column list, of
// an UPDATE (the columns it sets), or of a SELECT reading one table of the
// schema without *. It returns false for any other statement.
func (s *Schema) Shape(sql string) (*Shape, bool) {
	result, ok := parse(sql)
	if !ok || len(result.GetStmts()) != 1 {
		return nil, false
	}
	stmt := result.GetStmts()[0].GetStmt()
	if insert := stmt.GetInsertStmt(); insert != nil {
		table := s.relation(insert.GetRelation(), nil)
		if table == nil || table.View || len(insert.GetCols()) == 0 {
			return nil, false
		}
		shape := &Shape{Kind: "insert", Table: table.Name}
		for _, col := range insert.GetCols() {
			shape.Columns = append(shape.Columns, strings.ToLower(col.GetResTarget().GetName()))
			shape.LastOffset = int(col.GetResTarget().GetLocation())
		}
		return shape, true
	}
	if update := stmt.GetUpdateStmt(); update != nil {
		table := s.relation(update.GetRelation(), nil)
		if table == nil || table.View {
			return nil, false
		}
		shape := &Shape{Kind: "update", Table: table.Name}
		for _, target := range update.GetTargetList() {
			shape.Columns = append(shape.Columns, strings.ToLower(target.GetResTarget().GetName()))
			shape.LastOffset = int(target.GetResTarget().GetLocation())
		}
		return shape, true
	}
	sel := stmt.GetSelectStmt()
	if sel == nil || len(sel.GetFromClause()) != 1 || sel.GetFromClause()[0].GetRangeVar() == nil {
		return nil, false
	}
	table := s.relation(sel.GetFromClause()[0].GetRangeVar(), nil)
	if table == nil || table.View {
		return nil, false
	}
	shape := &Shape{Kind: "select", Table: table.Name}
	for _, target := range sel.GetTargetList() {
		res := target.GetResTarget()
		name := strings.ToLower(res.GetName())
		if name == "" {
			var refs []*pgquery.ColumnRef
			walk(res.GetVal().ProtoReflect(), func(m proto.Message) {
				if ref, ok := m.(*pgquery.ColumnRef); ok {
					refs = append(refs, ref)
				}
			})
			if len(refs) != 1 {
				return nil, false
			}
			fields := refs[0].GetFields()
			last := fields[len(fields)-1]
			if last.GetAStar() != nil {
				return nil, false
			}
			name = strings.ToLower(last.GetString_().GetSval())
		}
		shape.Columns = append(shape.Columns, name)
		shape.LastOffset = int(res.GetLocation())
	}
	return shape, len(shape.Columns) > 0
}
