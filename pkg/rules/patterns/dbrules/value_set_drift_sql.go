package dbrules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/aiseeq/glint/pkg/sqlschema"
	"github.com/aiseeq/glint/pkg/valueset"
)

type sqlValueSet struct {
	path       string
	line       int
	literalPos int
	table      string
	column     string
	values     []string
	order      int
}

func sqlColumnKey(set sqlValueSet) string {
	return set.table + "\x00" + set.column
}

func sqlValuesKey(set sqlValueSet) string {
	return sqlColumnKey(set) + "\x00" + strings.Join(set.values, "\x00")
}

func indexSQLValueSetGroups(sets []sqlValueSet) (map[string][]sqlValueSet, map[string][]sqlValueSet) {
	exact := make(map[string][]sqlValueSet)
	columns := make(map[string][]sqlValueSet)
	for i, set := range sets {
		set.order = i
		sets[i] = set
		exact[sqlValuesKey(set)] = append(exact[sqlValuesKey(set)], set)
		columns[sqlColumnKey(set)] = append(columns[sqlColumnKey(set)], set)
	}
	return exact, columns
}

func indexSQLValueSets(files []*core.FileContext) []sqlValueSet {
	var sets []sqlValueSet
	seen := make(map[string]struct{})
	for _, ctx := range files {
		if !patternkit.ProductionGoFile(ctx) || ctx.IsGenerated() || patternkit.IsE2EPath(ctx.RelPath) {
			continue
		}
		for _, literal := range patternkit.SqlLiterals(ctx.GoAST) {
			for _, in := range sqlschema.InLists(literal.Text) {
				if len(in.Values) < 2 || in.Negated || in.GuardedByKey || in.UnionOfHandledCases || in.Table == "" || in.Column == "" {
					continue
				}
				values := slices.Clone(in.Values)
				slices.Sort(values)
				values = slices.Compact(values)
				if len(values) < 2 {
					continue
				}
				set := sqlValueSet{
					path: ctx.RelPath, line: literal.LineAt(ctx, in.Offset), literalPos: int(literal.PiecePosAt(in.Offset)),
					table: in.Table, column: in.Column, values: values,
				}
				key := fmt.Sprintf("%s\x00%d\x00%s", set.path, set.literalPos, sqlValuesKey(set))
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				sets = append(sets, set)
			}
		}
	}
	slices.SortFunc(sets, func(a, b sqlValueSet) int {
		if a.path != b.path {
			return strings.Compare(a.path, b.path)
		}
		if a.line != b.line {
			return a.line - b.line
		}
		return a.literalPos - b.literalPos
	})
	return sets
}

func (r *ValueSetDriftRule) sqlValueSetFindings(ctx *core.FileContext) []*core.Violation {
	var findings []*core.Violation
	for index, set := range r.sqlSets {
		if set.path != ctx.RelPath || ctx.IsSuppressed(set.line, r.Name()) {
			continue
		}
		set.order = index
		if group := r.sqlGoGroup(set); group != nil {
			message := fmt.Sprintf("Go group %s is already declared at %s:%d; use the backend value (a response field or generated constant) instead of keeping a copy", group.name, group.path, group.line)
			v := r.CreateViolation(set.path, set.line, message)
			v.WithCode(strings.TrimSpace(ctx.GetLine(set.line)))
			v.WithSuggestion("Build the SQL list from the Go group and pass it as a parameter (for example, ANY($1))")
			findings = append(findings, v)
			continue
		}
		message := r.sqlSetMessage(set)
		if message == "" {
			continue
		}
		v := r.CreateViolation(set.path, set.line, message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(set.line)))
		v.WithSuggestion("Keep one source of the SQL value set and pass it to each query, or use a shared constant predicate")
		findings = append(findings, v)
	}
	return findings
}

func (r *ValueSetDriftRule) sqlGoGroup(set sqlValueSet) *goValueGroup {
	for i := range r.tables.valueGroups {
		group := &r.tables.valueGroups[i]
		if group.path != set.path && slices.Equal(group.members, set.values) {
			return group
		}
	}
	return nil
}

func (r *ValueSetDriftRule) sqlSetMessage(set sqlValueSet) string {
	exact := r.sqlExact[sqlValuesKey(set)]
	if len(exact) >= 3 {
		if set.order == exact[0].order || set.order == exact[1].order {
			return ""
		}
		first, second := exact[0], exact[1]
		advice := "declare it once (a Go constant passed as $N, or a constant predicate)"
		if list := r.sqlGoListName(set.values); list != "" {
			advice = "use the Go list " + list
		}
		return fmt.Sprintf("the set {%s} of %s.%s is written by hand in %d queries (%s:%d, %s:%d) — %s",
			strings.Join(set.values, ", "), set.table, set.column, len(exact),
			first.path, first.line, second.path, second.line, advice)
	}

	for _, other := range r.sqlColumns[sqlColumnKey(set)] {
		if slices.Equal(other.values, set.values) {
			continue
		}
		diff, ok := oneValueDifference(set.values, other.values)
		if !ok {
			continue
		}
		copies := r.sqlExact[sqlValuesKey(other)]
		if len(copies) < 2 {
			continue
		}
		return fmt.Sprintf("the set {%s} of %s.%s differs by one value (%s) from the set {%s} written in %d queries (%s:%d, %s:%d) — one of them is stale",
			strings.Join(set.values, ", "), set.table, set.column, diff,
			strings.Join(other.values, ", "), len(copies), copies[0].path, copies[0].line, copies[1].path, copies[1].line)
	}
	return ""
}

func oneValueDifference(a, b []string) (string, bool) {
	if len(a) == len(b) {
		return "", false
	}
	if len(a) == len(b)+1 {
		for _, value := range b {
			if !slices.Contains(a, value) {
				return "", false
			}
		}
		for _, value := range a {
			if !slices.Contains(b, value) {
				return value, true
			}
		}
	}
	if len(b) == len(a)+1 {
		for _, value := range a {
			if !slices.Contains(b, value) {
				return "", false
			}
		}
		for _, value := range b {
			if !slices.Contains(a, value) {
				return value, true
			}
		}
	}
	return "", false
}

func (r *ValueSetDriftRule) sqlGoListName(values []string) string {
	if r.index == nil {
		return ""
	}
	for _, candidate := range r.index.Sets {
		if candidate.Kind == valueset.List && candidate.Name != "" && slices.Equal(candidate.Members, values) {
			return candidate.Name
		}
	}
	return ""
}
