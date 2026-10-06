package sqlschema

import (
	"slices"
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
)

// blockingAdvisoryLocks are the advisory lock functions that wait for the
// lock.
var blockingAdvisoryLocks = map[string]bool{
	"pg_advisory_lock": true, "pg_advisory_xact_lock": true,
	"pg_advisory_lock_shared": true, "pg_advisory_xact_lock_shared": true,
}

// LockedReads returns the offsets of the blocking advisory locks a
// statement takes while it also reads a table: WITH locked AS (SELECT
// pg_advisory_xact_lock(1)), next AS (SELECT ... FROM locked, orders ...).
// The statement's snapshot is taken when it starts, before the lock wait, so
// the rows a neighbour wrote while this one waited stay invisible to its
// read - the lock serializes nothing it reads.
func LockedReads(sql string) []int {
	result, shift, ok := parseCode(sql)
	if !ok {
		return nil
	}
	var offsets []int
	for _, raw := range result.GetStmts() {
		stmt := raw.GetStmt()
		ctes := make(map[string]bool)
		var locks []int
		// Only a lock taken inside a part of the statement - a WITH query,
		// a subquery - sits beside a read; a SELECT whose own target list
		// locks per row reads only the keys it locks by.
		nested := func(m proto.Message) {
			walk(m.ProtoReflect(), func(inner proto.Message) {
				call, ok := inner.(*pgquery.FuncCall)
				if !ok || len(call.GetFuncname()) == 0 {
					return
				}
				parts := call.GetFuncname()
				if blockingAdvisoryLocks[strings.ToLower(parts[len(parts)-1].GetString_().GetSval())] {
					locks = append(locks, int(call.GetLocation())-shift)
				}
			})
		}
		walk(stmt.ProtoReflect(), func(m proto.Message) {
			switch node := m.(type) {
			case *pgquery.CommonTableExpr:
				ctes[strings.ToLower(node.GetCtename())] = true
				nested(node.GetCtequery())
			case *pgquery.RangeSubselect:
				nested(node.GetSubquery())
			case *pgquery.SubLink:
				nested(node.GetSubselect())
			}
		})
		if len(locks) == 0 {
			continue
		}
		reads := false
		for name := range relations(stmt) {
			if !ctes[name] {
				reads = true
			}
		}
		if reads {
			offsets = append(offsets, locks...)
		}
	}
	slices.Sort(offsets)
	return slices.Compact(offsets)
}
