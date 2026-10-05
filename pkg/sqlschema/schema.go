// Package sqlschema builds the database schema a project's migrations leave:
// the tables, their columns in order, which columns are NOT NULL and which
// have a default. Rules check the SQL written in the code against it.
//
// Migrations are PostgreSQL, parsed with the PostgreSQL grammar. Up files are
// applied in version order: golang-migrate's NNN_name.up.sql, plain NNN.sql,
// goose's -- +goose Up section. DDL run from a DO block or EXECUTE is not
// followed; neither are views' columns, which rules treat as unknown.
package sqlschema

import (
	"cmp"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	parser "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/proto"
)

// Schema is the set of tables the migrations create.
type Schema struct {
	tables map[string]*Table
	// Faults are statements of the migrations that fail on a fresh database.
	Faults []Fault

	// pending holds the ALTERs of tables not created yet, applied when a
	// later migration creates the table.
	pending map[string][]*pgquery.AlterTableStmt
	// stampFuncs are the trigger functions that set a column of the new row
	// to the current time (NEW.updated_at = NOW()), by function name.
	stampFuncs map[string]stampFunc
	// file and text are the migration being applied.
	file, text string
}

// Fault is a migration statement that fails on a fresh database: an ALTER of
// a table only a later migration creates.
type Fault struct {
	Path  string
	Line  int
	Table string
}

// Table is a table or a view of the schema.
type Table struct {
	Name string
	// View is a view or a table created from a query: its columns are not
	// known.
	View    bool
	columns []*Column
	// unique are the table's unique keys: its primary key, UNIQUE
	// constraints, unique indexes without a WHERE.
	unique []uniqueKey
	// partial are the unique indexes with a WHERE: the columns are unique
	// only among the rows the predicate admits.
	partial []partialKey
	// foreign are the columns of each named foreign key constraint, to undo
	// the references when a migration drops it.
	foreign map[string][]string
	// stamped is the column a BEFORE UPDATE trigger sets to the current time
	// on every update of a row, "" for none.
	stamped string
	// stampConditional marks a stamp the trigger makes only under an IF
	// (a changed status): a write that leaves the condition false keeps its
	// own value.
	stampConditional bool
}

// partialKey is a unique index with a WHERE: no two rows the predicate
// admits share its columns.
type partialKey struct {
	name    string
	columns []string
	// predicate are the columns the WHERE tests other than by IS NOT NULL,
	// which a lookup by the key's columns already implies.
	predicate []string
}

// uniqueKey is a set of columns no two rows share, by the name of the
// constraint or index that makes it so.
type uniqueKey struct {
	name    string
	columns []*Column
}

// UniqueWithin reports whether the given columns include every column of one
// of the table's unique keys: a row is fixed by them.
func (t *Table) UniqueWithin(columns map[string]bool) bool {
	for _, key := range t.unique {
		all := len(key.columns) > 0
		for _, column := range key.columns {
			all = all && columns[column.Name]
		}
		if all {
			return true
		}
	}
	return false
}

// addUnique records a unique key over the named columns; a column the table
// lacks leaves the key out.
func (t *Table) addUnique(name string, columns []string) {
	key := uniqueKey{name: strings.ToLower(name)}
	for _, columnName := range columns {
		column := t.Column(columnName)
		if column == nil {
			return
		}
		key.columns = append(key.columns, column)
	}
	t.unique = append(t.unique, key)
}

func (t *Table) dropUnique(name string) {
	name = strings.ToLower(name)
	for _, columnName := range t.foreign[name] {
		if column := t.Column(columnName); column != nil {
			column.References = ""
		}
	}
	delete(t.foreign, name)
	t.unique = slices.DeleteFunc(t.unique, func(k uniqueKey) bool { return k.name == name })
	t.partial = slices.DeleteFunc(t.partial, func(k partialKey) bool { return k.name == name })
}

// Column is a column of a table.
type Column struct {
	Name       string
	NotNull    bool
	HasDefault bool
	// GeneratedDefault is a default the database makes for each row — a
	// sequence, an identity, now(), gen_random_uuid() — which code never
	// supplies.
	GeneratedDefault bool
	// Type is the type name as written, lower case: text, numeric, uuid.
	Type string
	// References is the table a foreign key of the column points to, "" for
	// a column without one.
	References string
}

// Table returns the table or view named name, or nil.
func (s *Schema) Table(name string) *Table {
	return s.tables[strings.ToLower(name)]
}

// TablesWith returns the tables, not views, that have every one of the
// columns, in name order.
func (s *Schema) TablesWith(columns []string) []*Table {
	var tables []*Table
	for _, table := range s.tables {
		if table.View {
			continue
		}
		hasAll := true
		for _, name := range columns {
			if table.Column(name) == nil {
				hasAll = false
				break
			}
		}
		if hasAll {
			tables = append(tables, table)
		}
	}
	slices.SortFunc(tables, func(a, b *Table) int { return strings.Compare(a.Name, b.Name) })
	return tables
}

// Columns returns the names of the table's columns in order.
func (t *Table) Columns() []string {
	names := make([]string, len(t.columns))
	for i, column := range t.columns {
		names[i] = column.Name
	}
	return names
}

// Column returns the column named name, or nil.
func (t *Table) Column(name string) *Column {
	name = strings.ToLower(name)
	for _, column := range t.columns {
		if column.Name == name {
			return column
		}
	}
	return nil
}

func (t *Table) dropColumn(name string) {
	name = strings.ToLower(name)
	t.columns = slices.DeleteFunc(t.columns, func(c *Column) bool { return c.Name == name })
	t.unique = slices.DeleteFunc(t.unique, func(k uniqueKey) bool {
		return slices.ContainsFunc(k.columns, func(c *Column) bool { return c.Name == name })
	})
	t.partial = slices.DeleteFunc(t.partial, func(k partialKey) bool {
		return slices.Contains(k.columns, name) || slices.Contains(k.predicate, name)
	})
}

// skippedDirs are directories whose migrations are not the project's schema:
// dependencies, and test DDL that exists only for tests.
var skippedDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "testdata": true, "test": true, "tests": true,
	"testing": true, "e2e": true, "fixtures": true,
}

// Load reads the migrations under root: the directories given, relative to
// root, or else every directory named migrations. It returns nil for a
// project without migrations and an error naming the file that does not
// parse.
func Load(root string, dirs []string) (*Schema, error) {
	if len(dirs) == 0 {
		found, err := findMigrationDirs(root)
		if err != nil {
			return nil, err
		}
		dirs = found
	} else {
		joined := make([]string, len(dirs))
		for i, dir := range dirs {
			joined[i] = filepath.Join(root, dir)
		}
		dirs = joined
	}
	schema := &Schema{tables: make(map[string]*Table)}
	loaded := false
	for _, dir := range dirs {
		files, err := upMigrations(dir)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if err := schema.applyFile(file); err != nil {
				return nil, err
			}
			loaded = true
		}
	}
	if !loaded {
		return nil, nil
	}
	return schema, nil
}

func findMigrationDirs(root string) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if !entry.IsDir() {
			return nil
		}
		if path != root && skippedDirs[entry.Name()] {
			return filepath.SkipDir
		}
		if entry.Name() == "migrations" {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find migrations under %s: %w", root, err)
	}
	return dirs, nil
}

var versionPrefix = regexp.MustCompile(`^(\d+)`)

// upMigrations returns the SQL files of a directory that migrate up, in
// version order.
func upMigrations(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations %s: %w", dir, err)
	}
	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".down.sql") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	slices.SortFunc(files, compareVersions)
	return files, nil
}

// compareVersions orders migration files by the number their name starts
// with, of any length; a file without one comes first; equal numbers go by
// name.
func compareVersions(a, b string) int {
	va, vb := versionPrefix.FindString(filepath.Base(a)), versionPrefix.FindString(filepath.Base(b))
	if (va == "") != (vb == "") {
		return cmp.Compare(len(va), len(vb))
	}
	va, vb = strings.TrimLeft(va, "0"), strings.TrimLeft(vb, "0")
	if c := cmp.Compare(len(va), len(vb)); c != 0 {
		return c
	}
	if c := strings.Compare(va, vb); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

var gooseDown = regexp.MustCompile(`(?m)^--\s*\+goose\s+Down\b`)

func (s *Schema) applyFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return &MigrationError{Path: path, Err: err}
	}
	text := string(content)
	if loc := gooseDown.FindStringIndex(text); loc != nil {
		text = text[:loc[0]]
	}
	result, err := parser.Parse(text)
	if err != nil {
		return &MigrationError{Path: path, Err: err}
	}
	s.file, s.text = path, text
	for _, raw := range result.GetStmts() {
		s.apply(raw.GetStmt())
	}
	s.file, s.text = "", ""
	return nil
}

// With returns the schema with the tables the statements create added:
// tables the code itself creates, a temporary one for instance. Text that is
// not a CREATE TABLE adds nothing; the schema itself is left as it is.
func (s *Schema) With(statements []string) *Schema {
	clone := &Schema{tables: maps.Clone(s.tables)}
	for _, sql := range statements {
		result, ok := parse(sql)
		if !ok {
			continue
		}
		for _, raw := range result.GetStmts() {
			if create := raw.GetStmt().GetCreateStmt(); create != nil {
				clone.create(create)
			}
		}
	}
	return clone
}

func (s *Schema) apply(stmt *pgquery.Node) {
	switch {
	case stmt.GetCreateStmt() != nil:
		s.create(stmt.GetCreateStmt())
	case stmt.GetAlterTableStmt() != nil:
		s.alter(stmt.GetAlterTableStmt())
	case stmt.GetRenameStmt() != nil:
		s.rename(stmt.GetRenameStmt())
	case stmt.GetDropStmt() != nil:
		s.drop(stmt.GetDropStmt())
	case stmt.GetIndexStmt() != nil:
		s.index(stmt.GetIndexStmt())
	case stmt.GetViewStmt() != nil:
		name := strings.ToLower(stmt.GetViewStmt().GetView().GetRelname())
		s.tables[name] = &Table{Name: name, View: true}
	case stmt.GetCreateTableAsStmt() != nil:
		name := strings.ToLower(stmt.GetCreateTableAsStmt().GetInto().GetRel().GetRelname())
		s.tables[name] = &Table{Name: name, View: true}
	case stmt.GetCreateFunctionStmt() != nil:
		s.function(stmt.GetCreateFunctionStmt())
	case stmt.GetCreateTrigStmt() != nil:
		s.trigger(stmt.GetCreateTrigStmt())
	}
}

func (s *Schema) create(stmt *pgquery.CreateStmt) {
	name := strings.ToLower(stmt.GetRelation().GetRelname())
	if _, exists := s.tables[name]; exists && stmt.GetIfNotExists() {
		return
	}
	table := &Table{Name: name}
	// A table inheriting or a partition takes its parent's columns.
	for _, parent := range stmt.GetInhRelations() {
		if source := s.Table(parent.GetRangeVar().GetRelname()); source != nil {
			for _, column := range source.columns {
				copied := *column
				table.columns = append(table.columns, &copied)
			}
			table.View = table.View || source.View
		}
	}
	for _, elt := range stmt.GetTableElts() {
		switch {
		case elt.GetColumnDef() != nil:
			table.addColumn(elt.GetColumnDef())
		case elt.GetConstraint() != nil:
			table.applyConstraint(elt.GetConstraint())
		}
	}
	for _, constraint := range stmt.GetConstraints() {
		table.applyConstraint(constraint.GetConstraint())
	}
	s.tables[name] = table
	for _, alter := range s.pending[name] {
		s.alter(alter)
	}
	delete(s.pending, name)
}

// serialTypes are the pseudo-types that give a column a sequence default.
var serialTypes = map[string]bool{
	"serial": true, "bigserial": true, "smallserial": true, "serial2": true, "serial4": true, "serial8": true,
}

func newColumn(def *pgquery.ColumnDef) *Column {
	column := &Column{Name: strings.ToLower(def.GetColname()), NotNull: def.GetIsNotNull()}
	if names := def.GetTypeName().GetNames(); len(names) > 0 {
		column.Type = strings.ToLower(names[len(names)-1].GetString_().GetSval())
	}
	column.HasDefault = serialTypes[column.Type] || def.GetRawDefault() != nil || def.GetIdentity() != "" || def.GetGenerated() != ""
	column.GeneratedDefault = serialTypes[column.Type] || def.GetIdentity() != "" || def.GetGenerated() != "" ||
		isGeneratedExpr(def.GetRawDefault())
	if serialTypes[column.Type] {
		column.NotNull = true
	}
	for _, node := range def.GetConstraints() {
		constraint := node.GetConstraint()
		switch constraint.GetContype() {
		case pgquery.ConstrType_CONSTR_NOTNULL, pgquery.ConstrType_CONSTR_PRIMARY:
			column.NotNull = true
		case pgquery.ConstrType_CONSTR_DEFAULT:
			column.HasDefault = true
			column.GeneratedDefault = isGeneratedExpr(constraint.GetRawExpr())
		case pgquery.ConstrType_CONSTR_IDENTITY, pgquery.ConstrType_CONSTR_GENERATED:
			column.HasDefault, column.GeneratedDefault = true, true
			if constraint.GetContype() == pgquery.ConstrType_CONSTR_IDENTITY {
				column.NotNull = true
			}
		}
	}
	return column
}

// isGeneratedExpr reports a default the database computes per row: a call
// (now(), gen_random_uuid(), nextval(...)) or CURRENT_TIMESTAMP and its kin.
func isGeneratedExpr(expr *pgquery.Node) bool {
	if expr == nil {
		return false
	}
	if cast := expr.GetTypeCast(); cast != nil {
		return isGeneratedExpr(cast.GetArg())
	}
	return expr.GetFuncCall() != nil || expr.GetSqlvalueFunction() != nil
}

// applyConstraint marks the columns of a table-level primary key NOT NULL.
func (t *Table) applyConstraint(constraint *pgquery.Constraint) {
	var columns []string
	for _, key := range constraint.GetKeys() {
		columns = append(columns, key.GetString_().GetSval())
	}
	switch constraint.GetContype() {
	case pgquery.ConstrType_CONSTR_PRIMARY:
		for _, name := range columns {
			if column := t.Column(name); column != nil {
				column.NotNull = true
			}
		}
		t.addUnique(cmp.Or(constraint.GetConname(), t.Name+"_pkey"), columns)
	case pgquery.ConstrType_CONSTR_UNIQUE:
		t.addUnique(cmp.Or(constraint.GetConname(), t.Name+"_"+strings.Join(columns, "_")+"_key"), columns)
	case pgquery.ConstrType_CONSTR_FOREIGN:
		var attrs []string
		for _, attr := range constraint.GetFkAttrs() {
			attrs = append(attrs, strings.ToLower(attr.GetString_().GetSval()))
		}
		t.addForeign(constraint, attrs)
	}
}

// addForeign records a foreign key of the columns to the table it references.
func (t *Table) addForeign(constraint *pgquery.Constraint, columns []string) {
	target := strings.ToLower(constraint.GetPktable().GetRelname())
	for _, name := range columns {
		if column := t.Column(name); column != nil {
			column.References = target
		}
	}
	if name := strings.ToLower(constraint.GetConname()); name != "" {
		if t.foreign == nil {
			t.foreign = make(map[string][]string)
		}
		t.foreign[name] = columns
	}
}

// addColumn adds a column and the unique key its own constraints make.
func (t *Table) addColumn(def *pgquery.ColumnDef) {
	column := newColumn(def)
	t.columns = append(t.columns, column)
	for _, node := range def.GetConstraints() {
		constraint := node.GetConstraint()
		switch constraint.GetContype() {
		case pgquery.ConstrType_CONSTR_PRIMARY:
			t.addUnique(cmp.Or(constraint.GetConname(), t.Name+"_pkey"), []string{column.Name})
		case pgquery.ConstrType_CONSTR_UNIQUE:
			t.addUnique(cmp.Or(constraint.GetConname(), t.Name+"_"+column.Name+"_key"), []string{column.Name})
		case pgquery.ConstrType_CONSTR_FOREIGN:
			t.addForeign(constraint, []string{column.Name})
		}
	}
}

// index records a unique index without a WHERE as a unique key; a key
// part lower(col) or upper(col) counts as the column.
func (s *Schema) index(stmt *pgquery.IndexStmt) {
	table := s.Table(stmt.GetRelation().GetRelname())
	if table == nil || !stmt.GetUnique() {
		return
	}
	var columns []string
	for _, param := range stmt.GetIndexParams() {
		elem := param.GetIndexElem()
		name := elem.GetName()
		if call := elem.GetExpr().GetFuncCall(); name == "" && call != nil && len(call.GetArgs()) == 1 {
			fn := call.GetFuncname()
			if f := strings.ToLower(fn[len(fn)-1].GetString_().GetSval()); f == "lower" || f == "upper" {
				name = refName(call.GetArgs()[0])
			}
		}
		if name == "" {
			return
		}
		columns = append(columns, name)
	}
	// A WHERE that only leaves out NULL keys, or tests only the key's own
	// values (email <> ''), makes no difference to a lookup by a key value
	// the predicate admits: an equality is never true of NULL, and the
	// caller picks the value.
	predicate := slices.DeleteFunc(predicateColumns(stmt.GetWhereClause()), func(name string) bool { return slices.Contains(columns, name) })
	if len(predicate) > 0 {
		table.partial = append(table.partial, partialKey{name: strings.ToLower(stmt.GetIdxname()), columns: columns, predicate: predicate})
		return
	}
	table.addUnique(stmt.GetIdxname(), columns)
}

// predicateColumns returns the columns a partial index's WHERE tests other
// than by IS NOT NULL.
func predicateColumns(where *pgquery.Node) []string {
	if where == nil {
		return nil
	}
	var columns []string
	visit := func(node *pgquery.Node) {
		if test := node.GetNullTest(); test != nil && test.GetNulltesttype() == pgquery.NullTestType_IS_NOT_NULL && refName(test.GetArg()) != "" {
			return
		}
		walk(node.ProtoReflect(), func(m proto.Message) {
			if ref, ok := m.(*pgquery.ColumnRef); ok {
				fields := ref.GetFields()
				if len(fields) > 0 && fields[len(fields)-1].GetString_() != nil {
					name := strings.ToLower(fields[len(fields)-1].GetString_().GetSval())
					if !slices.Contains(columns, name) {
						columns = append(columns, name)
					}
				}
			}
		})
	}
	if b := where.GetBoolExpr(); b != nil && b.GetBoolop() == pgquery.BoolExprType_AND_EXPR {
		for _, arg := range b.GetArgs() {
			visit(arg)
		}
		return columns
	}
	visit(where)
	return columns
}

func (s *Schema) alter(stmt *pgquery.AlterTableStmt) {
	table := s.Table(stmt.GetRelation().GetRelname())
	if table == nil {
		if !stmt.GetMissingOk() && stmt.GetObjtype() == pgquery.ObjectType_OBJECT_TABLE && inUserSchema(stmt.GetRelation()) {
			s.deferAlter(stmt)
		}
		return
	}
	for _, node := range stmt.GetCmds() {
		cmd := node.GetAlterTableCmd()
		column := table.Column(cmd.GetName())
		switch cmd.GetSubtype() {
		case pgquery.AlterTableType_AT_AddColumn:
			def := cmd.GetDef().GetColumnDef()
			if table.Column(def.GetColname()) == nil {
				table.addColumn(def)
			}
		case pgquery.AlterTableType_AT_DropColumn:
			table.dropColumn(cmd.GetName())
		case pgquery.AlterTableType_AT_SetNotNull:
			if column != nil {
				column.NotNull = true
			}
		case pgquery.AlterTableType_AT_DropNotNull:
			if column != nil {
				column.NotNull = false
			}
		case pgquery.AlterTableType_AT_ColumnDefault:
			if column != nil {
				column.HasDefault = cmd.GetDef() != nil
				column.GeneratedDefault = isGeneratedExpr(cmd.GetDef())
			}
		case pgquery.AlterTableType_AT_AddIdentity:
			if column != nil {
				column.HasDefault, column.NotNull, column.GeneratedDefault = true, true, true
			}
		case pgquery.AlterTableType_AT_AddConstraint:
			table.applyConstraint(cmd.GetDef().GetConstraint())
		case pgquery.AlterTableType_AT_DropConstraint:
			table.dropUnique(cmd.GetName())
		case pgquery.AlterTableType_AT_AlterColumnType:
			if names := cmd.GetDef().GetColumnDef().GetTypeName().GetNames(); column != nil && len(names) > 0 {
				column.Type = strings.ToLower(names[len(names)-1].GetString_().GetSval())
			}
		}
	}
}

// deferAlter records an ALTER of a table no migration has created yet as a
// fault, one per migration and table, and keeps it for the migration that creates the table.
func (s *Schema) deferAlter(stmt *pgquery.AlterTableStmt) {
	name := strings.ToLower(stmt.GetRelation().GetRelname())
	offset := min(max(int(stmt.GetRelation().GetLocation()), 0), len(s.text))
	if !slices.ContainsFunc(s.Faults, func(f Fault) bool { return f.Path == s.file && f.Table == name }) {
		s.Faults = append(s.Faults, Fault{Path: s.file, Line: strings.Count(s.text[:offset], "\n") + 1, Table: name})
	}
	if s.pending == nil {
		s.pending = make(map[string][]*pgquery.AlterTableStmt)
	}
	s.pending[name] = append(s.pending[name], stmt)
}

func (s *Schema) rename(stmt *pgquery.RenameStmt) {
	switch stmt.GetRenameType() {
	case pgquery.ObjectType_OBJECT_TABLE, pgquery.ObjectType_OBJECT_VIEW:
		old := strings.ToLower(stmt.GetRelation().GetRelname())
		if table, ok := s.tables[old]; ok {
			delete(s.tables, old)
			table.Name = strings.ToLower(stmt.GetNewname())
			s.tables[table.Name] = table
		}
	case pgquery.ObjectType_OBJECT_COLUMN:
		if table := s.Table(stmt.GetRelation().GetRelname()); table != nil {
			if column := table.Column(stmt.GetSubname()); column != nil {
				column.Name = strings.ToLower(stmt.GetNewname())
			}
		}
	}
}

func (s *Schema) drop(stmt *pgquery.DropStmt) {
	switch stmt.GetRemoveType() {
	case pgquery.ObjectType_OBJECT_TABLE, pgquery.ObjectType_OBJECT_VIEW, pgquery.ObjectType_OBJECT_MATVIEW:
	case pgquery.ObjectType_OBJECT_INDEX:
		for _, object := range stmt.GetObjects() {
			if items := object.GetList().GetItems(); len(items) > 0 {
				name := items[len(items)-1].GetString_().GetSval()
				for _, table := range s.tables {
					table.dropUnique(name)
				}
			}
		}
		return
	default:
		return
	}
	for _, object := range stmt.GetObjects() {
		items := object.GetList().GetItems()
		if len(items) == 0 {
			continue
		}
		delete(s.tables, strings.ToLower(items[len(items)-1].GetString_().GetSval()))
	}
}

// MigrationError is a migration that could not be read or parsed.
type MigrationError struct {
	Path string
	Err  error
}

func (e *MigrationError) Error() string { return fmt.Sprintf("migration %s: %v", e.Path, e.Err) }

func (e *MigrationError) Unwrap() error { return e.Err }

type cacheEntry struct {
	once   sync.Once
	schema *Schema
	err    error
}

var (
	cacheMu sync.Mutex
	cache   = make(map[string]*cacheEntry)
)

// LoadCached is Load done once per root and directories for the process:
// every file of a project checks against the same schema.
func LoadCached(root string, dirs []string) (*Schema, error) {
	key := root + "\x00" + strings.Join(dirs, "\x00")
	cacheMu.Lock()
	entry, ok := cache[key]
	if !ok {
		entry = &cacheEntry{}
		cache[key] = entry
	}
	cacheMu.Unlock()
	entry.once.Do(func() { entry.schema, entry.err = Load(root, dirs) })
	return entry.schema, entry.err
}
