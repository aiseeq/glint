package patterns

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/valueset"
)

// tableIndex holds what a project spells through named constants: the
// constants themselves, the sets and translation tables written with them,
// and the values the backend gives each JSON field.
type tableIndex struct {
	consts map[string][]valueset.ConstDecl // by name
	groups map[string][]string             // the constant names of each set
	// sets are the constant sets written in the code, resolved; copies
	// counts each set's spellings by its key.
	sets   []constSet
	copies map[string][]constSet
	maps   []constMapping
	// switches are the switches over constants with a made-up default.
	switches []valueset.DerivedDefaultSwitch
	// fieldValues are the values given to each struct's field sent as JSON
	// (Struct.json), with where.
	fieldValues map[string]map[string]string
	unions      []valueset.PropUnion
}

type constSet struct {
	path  string
	line  int
	names []string // sorted
	key   string
}

type constMapping struct {
	path  string
	line  int
	pairs map[valueset.Pair]bool
}

// sentinelConst names a constant standing for no value: KindUnknown.
var sentinelConst = regexp.MustCompile(`(?:Unknown|Unspecified|Invalid|Undefined|None)$`)

// minCopiedSet is the least size of a set of constants whose exact copy is
// reported: a few related constants (the exact rules, the failed statuses)
// are written together in many places on purpose.
const minCopiedSet = 4

// minSharedPairs is the least number of translations two tables share to be
// one table kept twice.
const minSharedPairs = 3

func newTableIndex(files []*core.FileContext) *tableIndex {
	idx := &tableIndex{
		consts:      make(map[string][]valueset.ConstDecl),
		groups:      make(map[string][]string),
		copies:      make(map[string][]constSet),
		fieldValues: make(map[string]map[string]string),
	}
	// Files in path order: the first place of a value, and the table a copy
	// is compared with first, do not depend on the walk.
	files = slices.SortedFunc(slices.Values(files), func(a, b *core.FileContext) int { return cmp.Compare(a.RelPath, b.RelPath) })
	var tables []valueset.Tables
	for _, file := range files {
		if file.IsTestFile() || isE2EPath(file.RelPath) || file.IsGenerated() {
			continue
		}
		t := valueset.FileTables(file)
		tables = append(tables, t)
		for _, c := range t.Consts {
			idx.consts[c.Name] = append(idx.consts[c.Name], c)
			idx.groups[c.Group] = append(idx.groups[c.Group], c.Name)
		}
	}
	// A field is followed by its name alone: only a name one struct of the
	// project declares says which struct an assignment fills.
	owners := make(map[string][]valueset.JSONField)
	for _, t := range tables {
		for _, f := range t.Fields {
			owners[f.Field] = append(owners[f.Field], f)
		}
	}
	for _, t := range tables {
		for _, s := range t.Sets {
			idx.addSet(s)
		}
		for _, m := range t.Mappings {
			pairs := make(map[valueset.Pair]bool)
			for _, p := range m.Pairs {
				if _, ok := idx.constValue(p.Ref); ok {
					pairs[p] = true
				}
			}
			if len(pairs) >= minSharedPairs {
				idx.maps = append(idx.maps, constMapping{path: m.Path, line: m.Line, pairs: pairs})
			}
		}
		idx.switches = append(idx.switches, t.Switches...)
		idx.unions = append(idx.unions, t.Unions...)
		for _, a := range t.Assigns {
			fields := owners[a.Field]
			if len(fields) != 1 || fields[0].JSON == "" {
				continue
			}
			value := a.Literal
			if a.Ref != "" {
				v, ok := idx.constValue(a.Ref)
				if !ok {
					continue
				}
				value = v
			}
			if value == "" {
				continue
			}
			key := fields[0].Struct + "." + fields[0].JSON
			if idx.fieldValues[key] == nil {
				idx.fieldValues[key] = make(map[string]string)
			}
			if _, seen := idx.fieldValues[key][value]; !seen {
				idx.fieldValues[key][value] = fmt.Sprintf("%s:%d", a.Path, a.Line)
			}
		}
	}
	return idx
}

// constValue is the value of a constant declared once under that name.
func (idx *tableIndex) constValue(name string) (string, bool) {
	decls := idx.consts[name]
	if len(decls) == 0 {
		return "", false
	}
	for _, d := range decls[1:] {
		if d.Value != decls[0].Value {
			return "", false
		}
	}
	return decls[0].Value, true
}

// constGroup is the set a constant belongs to, if its name is not ambiguous.
func (idx *tableIndex) constGroup(name string) (string, bool) {
	decls := idx.consts[name]
	if len(decls) != 1 {
		return "", false
	}
	return decls[0].Group, true
}

// addSet resolves a written set into sets of constants. A list or a clause
// is a set when every member is a constant; a run of call arguments gives
// its runs of consecutive constants (an alias or an id list between them
// ends a run).
func (idx *tableIndex) addSet(s valueset.RefSet) {
	if !s.Args {
		var names []string
		for _, r := range s.Refs {
			if _, ok := idx.constGroup(r.Name); !ok {
				return
			}
			names = append(names, r.Name)
		}
		idx.keep(s.Path, s.Line, names)
		return
	}
	var run []valueset.Ref
	flush := func() {
		if len(run) > 1 {
			names := make([]string, 0, len(run))
			for _, r := range run {
				names = append(names, r.Name)
			}
			idx.keep(s.Path, run[0].Line, names)
		}
		run = nil
	}
	for _, r := range s.Refs {
		if _, ok := idx.constGroup(r.Name); !ok {
			flush()
			continue
		}
		run = append(run, r)
	}
	flush()
}

func (idx *tableIndex) keep(path string, line int, names []string) {
	names = slices.Clone(names)
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) < 2 {
		return
	}
	set := constSet{path: path, line: line, names: names, key: strings.Join(names, ",")}
	idx.sets = append(idx.sets, set)
	idx.copies[set.key] = append(idx.copies[set.key], set)
}

// wholeGroup reports a set of every constant of one declared set: it follows
// the declaration.
func (idx *tableIndex) wholeGroup(names []string) bool {
	group, ok := idx.constGroup(names[0])
	if !ok {
		return false
	}
	for _, n := range names[1:] {
		if g, _ := idx.constGroup(n); g != group {
			return false
		}
	}
	all := slices.Clone(idx.groups[group])
	slices.Sort(all)
	return slices.Equal(slices.Compact(all), names)
}

func setBefore(a, b constSet) bool {
	return cmp.Or(cmp.Compare(a.path, b.path), cmp.Compare(a.line, b.line)) < 0
}

// tableFindings are the findings of the constant tables in one file.
func (idx *tableIndex) tableFindings(relPath string) []tableFinding {
	var out []tableFinding
	for _, set := range idx.sets {
		if set.path != relPath || idx.wholeGroup(set.names) {
			continue
		}
		if msg := idx.copiedSet(set); msg != "" {
			out = append(out, tableFinding{line: set.line, message: msg})
		}
	}
	for _, m := range idx.maps {
		if m.path != relPath {
			continue
		}
		if msg := idx.copiedMapping(m); msg != "" {
			out = append(out, tableFinding{line: m.line, message: msg})
		}
	}
	for _, sw := range idx.switches {
		if sw.Path != relPath {
			continue
		}
		if msg := idx.derivedDefault(sw); msg != "" {
			out = append(out, tableFinding{line: sw.Line, message: msg})
		}
	}
	for _, u := range idx.unions {
		if u.Path != relPath {
			continue
		}
		if msg := idx.unionLacksValues(u); msg != "" {
			out = append(out, tableFinding{line: u.Line, message: msg})
		}
	}
	return out
}

type tableFinding struct {
	line    int
	message string
}

// copiedSet reports a later exact copy of a set of constants, or a set one
// member short of a set written the same way in two other places.
func (idx *tableIndex) copiedSet(set constSet) string {
	same := idx.copies[set.key]
	if len(set.names) >= minCopiedSet && len(same) > 1 {
		first := same[0]
		for _, s := range same[1:] {
			if setBefore(s, first) {
				first = s
			}
		}
		if !samePlace(first, set) {
			return fmt.Sprintf("Same set of constants as %s:%d - two copies kept by hand drift apart when a constant is added", first.path, first.line)
		}
	}
	if len(same) > 1 {
		return ""
	}
	for _, key := range slices.Sorted(maps.Keys(idx.copies)) {
		spellings := idx.copies[key]
		if len(spellings) < 2 || key == set.key {
			continue
		}
		canonical := spellings[0].names
		if len(canonical) != len(set.names)+1 || len(canonical) < 3 {
			continue
		}
		var missing []string
		for _, n := range canonical {
			if !slices.Contains(set.names, n) {
				missing = append(missing, n)
			}
		}
		if len(missing) != 1 || !idx.declaredAfter(missing[0], set.names) {
			continue
		}
		return fmt.Sprintf("Set of constants misses %s, which the same set at %s:%d and %s:%d has - the constant added there did not reach this copy",
			missing[0], spellings[0].path, spellings[0].line, spellings[1].path, spellings[1].line)
	}
	return ""
}

// declaredAfter reports a constant declared in the same file after every
// one of names: the newest member, the one a copy written before it lacks.
func (idx *tableIndex) declaredAfter(name string, names []string) bool {
	last := idx.consts[name][0]
	for _, n := range names {
		d := idx.consts[n][0]
		if d.Path != last.Path || d.Line >= last.Line {
			return false
		}
	}
	return true
}

func samePlace(a, b constSet) bool { return a.path == b.path && a.line == b.line }

// copiedMapping reports a translation table that shares translations with a
// larger one (or an equal one written earlier) and differs from it.
func (idx *tableIndex) copiedMapping(m constMapping) string {
	for _, other := range idx.maps {
		if other.path == m.path && other.line == m.line {
			continue
		}
		shared := 0
		for p := range m.pairs {
			if other.pairs[p] {
				shared++
			}
		}
		if shared < minSharedPairs {
			continue
		}
		// The smaller copy is reported; of two equal ones the later.
		if len(m.pairs) > len(other.pairs) ||
			(len(m.pairs) == len(other.pairs) && cmp.Or(cmp.Compare(m.path, other.path), cmp.Compare(m.line, other.line)) < 0) {
			continue
		}
		var missing, extra []string
		for p := range other.pairs {
			if !m.pairs[p] {
				missing = append(missing, p.Ref+"="+p.Literal)
			}
		}
		for p := range m.pairs {
			if !other.pairs[p] {
				extra = append(extra, p.Ref+"="+p.Literal)
			}
		}
		slices.Sort(missing)
		slices.Sort(extra)
		where := fmt.Sprintf("%s:%d", other.path, other.line)
		if len(missing) == 0 && len(extra) == 0 {
			return "Same translation table as " + where + " - two copies kept by hand drift apart on the next entry"
		}
		var diff []string
		if len(missing) > 0 {
			diff = append(diff, "missing here: "+strings.Join(missing, ", "))
		}
		if len(extra) > 0 {
			diff = append(diff, "only here: "+strings.Join(extra, ", "))
		}
		return fmt.Sprintf("Translation table copies %d entries of %s but differs (%s)", shared, where, strings.Join(diff, "; "))
	}
	return ""
}

// derivedDefault reports a switch over some constants of one set whose
// default makes the value up from the input for the others.
func (idx *tableIndex) derivedDefault(sw valueset.DerivedDefaultSwitch) string {
	group := ""
	for _, label := range sw.Labels {
		g, ok := idx.constGroup(label)
		if !ok || (group != "" && g != group) {
			return ""
		}
		group = g
	}
	var missing []string
	for _, name := range idx.groups[group] {
		if sentinelConst.MatchString(name) {
			continue // a placeholder for no value is not a member to handle
		}
		if !slices.Contains(sw.Labels, name) && !slices.Contains(missing, name) {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	slices.Sort(missing)
	return "Switch handles some constants of a set and its default makes the value up from the input for the rest (" +
		strings.Join(missing, ", ") + ") - a constant added to the set gets an invented value instead of an error"
}

// unionLacksValues reports a TS union of a property that lacks values the
// backend gives the field sent under that name.
func (idx *tableIndex) unionLacksValues(u valueset.PropUnion) string {
	values := idx.fieldValues[u.Owner+"."+u.Prop]
	if len(values) == 0 {
		return ""
	}
	shared := 0
	var missing []string
	for v := range values {
		if slices.Contains(u.Members, v) {
			shared++
		} else {
			missing = append(missing, v)
		}
	}
	if shared < 2 || len(missing) == 0 {
		return ""
	}
	slices.Sort(missing)
	var where []string
	for _, v := range missing {
		where = append(where, v+" ("+values[v]+")")
	}
	return fmt.Sprintf("TS union of %s lacks values the backend sends in that field: %s", u.Prop, strings.Join(where, ", "))
}
