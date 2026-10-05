package sqlschema

import (
	"regexp"
	"slices"
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
)

// RestrictingReferences returns the columns whose foreign key to the table
// has no ON DELETE action (or RESTRICT): while one of them points at a row,
// a DELETE of that row fails with a foreign key violation.
func (s *Schema) RestrictingReferences(table string) []Reference {
	if s == nil || s.Table(table) == nil {
		return nil
	}
	var refs []Reference
	for _, other := range s.tables {
		for _, column := range other.columns {
			if column.References == table && column.RestrictsDelete {
				refs = append(refs, Reference{Table: other.Name, Column: column.Name})
			}
		}
	}
	slices.SortFunc(refs, func(a, b Reference) int { return strings.Compare(a.Table+"."+a.Column, b.Table+"."+b.Column) })
	return refs
}

// UniqueConflict is a unique key an INSERT writes every column of, with no
// ON CONFLICT clause: a row already holding the values fails the INSERT
// with a unique violation.
type UniqueConflict struct {
	Table string
	Key   []string
	// Offset is where the INSERT names its table.
	Offset int
}

// UniqueConflicts returns the unique keys the INSERTs of a statement can
// violate: keys whose every column the INSERT's column list supplies, none
// of them made by the database (a serial or generated id) or holding a value
// the program generates (a token hash, a session id), of an INSERT without
// ON CONFLICT.
func (s *Schema) UniqueConflicts(sql string) []UniqueConflict {
	if s == nil {
		return nil
	}
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var conflicts []UniqueConflict
	for _, raw := range result.GetStmts() {
		walk(raw.GetStmt().ProtoReflect(), func(m proto.Message) {
			insert, ok := m.(*pgquery.InsertStmt)
			if !ok || insert.GetOnConflictClause() != nil || len(insert.GetCols()) == 0 {
				return
			}
			table := s.relation(insert.GetRelation(), nil)
			if table == nil || table.View {
				return
			}
			listed := make(map[string]bool)
			for _, col := range insert.GetCols() {
				listed[strings.ToLower(col.GetResTarget().GetName())] = true
			}
			for _, key := range table.unique {
				if suppliedKey(key, listed) && !generatedKey(table.Name, key) {
					conflicts = append(conflicts, UniqueConflict{Table: table.Name, Key: keyColumns(key), Offset: int(insert.GetRelation().GetLocation()) - shift})
				}
			}
		})
	}
	return conflicts
}

// suppliedKey reports a key whose every column the INSERT lists and none of
// which the database makes itself. A lone uuid column is an id the code
// generates, which never repeats.
func suppliedKey(key uniqueKey, listed map[string]bool) bool {
	if len(key.columns) == 0 || (len(key.columns) == 1 && key.columns[0].Type == "uuid") {
		return false
	}
	for _, column := range key.columns {
		if !listed[column.Name] || column.GeneratedDefault {
			return false
		}
	}
	return true
}

// generatedColumn names a column whose value the program makes or receives
// rather than a user types: a token or its hash, a session id, a nonce, an
// id or address another system issued.
var generatedColumn = regexp.MustCompile(`(^|_)(token|hash|session|nonce|secret|salt|foreign|external|deposit)(_|$)`)

// generatedKey reports a key with a column of a generated value - a random
// one never repeats, another system's id repeats only by its fault - or the
// code column of a table of codes the program issues (link_codes).
func generatedKey(table string, key uniqueKey) bool {
	for _, column := range key.columns {
		if generatedColumn.MatchString(column.Name) || (column.Name == "code" && strings.Contains(table, "code")) {
			return true
		}
	}
	return false
}

// keyColumns returns the names of a key's columns.
func keyColumns(key uniqueKey) []string {
	names := make([]string, 0, len(key.columns))
	for _, column := range key.columns {
		names = append(names, column.Name)
	}
	return names
}
