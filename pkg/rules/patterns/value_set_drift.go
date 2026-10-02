package patterns

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/valueset"
)

func init() {
	rules.Register(NewValueSetDriftRule())
}

// ValueSetDriftRule detects a set of values kept by hand in two places:
//
//	// backend: the statuses a withdrawal has
//	const ( WithdrawalStatusPending WithdrawalStatus = "pending"; ... WithdrawalStatusFailed ... )
//
//	// frontend: a badge for each of them - but "failed" was added later
//	const styles = { pending: '...', approved: '...', processing: '...', rejected: '...', completed: '...' }
//
// One copy gets a new member and the other does not: a status the backend
// sends has no badge, a validation map rejects a strategy the switch next to
// it knows, a TS union keeps a status the Go type renamed.
//
// Reported are a list (a list literal, the keys of a membership map) or a
// keyed set (the keys or values of an object, the labels of a switch) that
// copies most of a declared set or of a list but differs from it; a list
// that another list or a keyed set repeats exactly; a declared set declared
// again under the same name; and a TS union or enum that differs from the Go
// type of the same name. The constants of a Go type are a declared set, and
// so are untyped constants of one declaration sharing a name prefix
// (WithdrawalStatusPending, WithdrawalStatusFailed). Keyed sets are not
// compared with each other - two label maps overlap on common words as often
// as they share a domain - and an object typed Record<Union, V> is kept to
// the union by the compiler. A switch counts only as an exact copy: it
// leaves values to its default on purpose; and a switch the compiler checks
// for missing cases is held to its union, not kept by hand. A drifted copy is in another file
// (variants declared side by side differ on purpose) and shares at least four
// values and three quarters of the larger set; a list that takes only a part
// of a set - the terminal statuses - is its own set.
//
// Sets written with named constants are compared by the constants: a set of
// four or more (a list, a case clause, the arguments filling an SQL IN list)
// copied exactly, and a set one constant short of a set written the same way
// in two other places, the missing one declared after the others - the
// constant added there did not reach this copy. A translation table (a map
// of literals to constants or back, a switch returning one value per case)
// sharing three or more entries with another one is the same table kept
// twice. A switch over some constants of a set whose default makes the value
// up from its input invents a value for every constant added later. A TS
// union of a property lacks a value the backend assigns to the field of the
// struct of the same name sent under that JSON name.
type ValueSetDriftRule struct {
	*rules.BaseRule
	// index holds the sets of the root under analysis; the check flow sets it
	// before it analyzes any file and resets it between roots.
	index *valueset.Index
	// tables holds the root's sets and tables of named constants.
	tables *tableIndex
}

// NewValueSetDriftRule creates the rule
func NewValueSetDriftRule() *ValueSetDriftRule {
	return &ValueSetDriftRule{BaseRule: rules.NewBaseRule(
		"value-set-drift",
		"duplication",
		"Detects a set of values (statuses, networks, currencies) kept by hand in two places, and the copies that already differ",
		core.SeverityMedium,
	)}
}

// UseProjectFiles indexes the sets of every file of the root.
func (r *ValueSetDriftRule) UseProjectFiles(files []*core.FileContext) {
	r.index = valueset.IndexFiles(files)
	r.tables = newTableIndex(files)
}

// ResetState drops the sets of the previous root.
func (r *ValueSetDriftRule) ResetState() { r.index, r.tables = nil, nil }

type setMatch struct {
	other  valueset.Set
	shared int
	rank   int // 3 a renamed contract, 2 a drifted copy, 1 an exact copy
}

// AnalyzeFile reports the sets of a file that copy another set.
func (r *ValueSetDriftRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.ProjectRoot == "" || ctx.IsTestFile() || ctx.IsGenerated() || isE2EPath(ctx.RelPath) {
		return nil
	}
	if r.index == nil || r.tables == nil {
		v := r.CreateViolation(ctx.RelPath, 1, "The project's files were not handed to the rule, so value sets were not compared")
		v.Severity = core.SeverityCritical
		return []*core.Violation{v}
	}
	sets := valueset.FileSets(ctx)
	var violations []*core.Violation
	for _, set := range sets {
		match, ok := bestMatch(r.index, set)
		if !ok || ctx.IsSuppressed(set.Line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, set.Line, valueSetMessage(set, match))
		v.WithCode(strings.TrimSpace(ctx.GetLine(set.Line)))
		v.WithSuggestion("Keep one source of the set - the declared type, a shared constant list, a generated contract - and derive the others from it")
		violations = append(violations, v)
	}
	for _, f := range r.tables.tableFindings(ctx.RelPath) {
		if ctx.IsSuppressed(f.line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, f.line, f.message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(f.line)))
		v.WithSuggestion("Keep one source of the set or table - a shared list, map or function the other places call - and derive the others from it")
		violations = append(violations, v)
	}
	return violations
}

// bestMatch finds the set this one copies, if any.
func bestMatch(idx *valueset.Index, set valueset.Set) (setMatch, bool) {
	var best setMatch
	found := false
	for i, shared := range idx.Overlapping(set, 1) {
		other := idx.Sets[i]
		m := setMatch{other: other, shared: shared}
		same := slices.Equal(set.Members, other.Members)
		switch {
		case set.Kind == valueset.Enum && other.Kind == valueset.Enum:
			// Two declared sets are distinct domains, unless they have one
			// name: a TS type mirroring the Go type, or one type declared
			// twice.
			if set.Name != other.Name {
				continue
			}
			switch {
			case !set.Go && other.Go && !same:
				m.rank = 3
			case set.Go == other.Go && same && before(other, set):
				m.rank = 1
			default:
				continue
			}
		case set.Kind == valueset.Enum:
			continue // the list copying it is reported
		case set.Exhaustive || other.Exhaustive:
			continue // the compiler holds the switch to its union
		case same:
			// A list repeating another: a copy kept by hand. A label or a
			// handler for each value of a set is not a copy, and a list
			// equal to a declared set is in step with it.
			if other.Kind == valueset.Enum {
				// In step with a declared set: it mirrors that one, and
				// the near sets are other domains.
				return setMatch{}, false
			}
			if set.Kind == valueset.Keyed && other.Kind == valueset.Keyed {
				continue
			}
			if !before(other, set) {
				continue // the first copy is the one kept
			}
			m.rank = 1
		case set.Kind == valueset.Keyed && other.Kind == valueset.Keyed:
			continue // two label maps overlap on common words as often as they share a domain
		case set.Switch || other.Switch:
			continue // a switch leaves values to its default on purpose
		case set.Path == other.Path:
			continue // variants declared side by side differ on purpose
		case shared > valueset.MinMembers && 4*shared >= 3*max(len(set.Members), len(other.Members)):
			m.rank = 2
		default:
			continue
		}
		if !found || better(m, best) {
			best, found = m, true
		}
	}
	return best, found
}

func before(a, b valueset.Set) bool {
	return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Line, b.Line)) < 0
}

func better(a, b setMatch) bool {
	if a.rank != b.rank {
		return a.rank > b.rank
	}
	if a.shared != b.shared {
		return a.shared > b.shared
	}
	if (a.other.Kind == valueset.Enum) != (b.other.Kind == valueset.Enum) {
		return a.other.Kind == valueset.Enum
	}
	return before(a.other, b.other)
}

func valueSetMessage(set valueset.Set, m setMatch) string {
	where := fmt.Sprintf("%s:%d", m.other.Path, m.other.Line)
	if m.other.Name != "" {
		where = m.other.Name + " at " + where
	}
	if m.rank == 1 {
		return "Same set of values as " + where + " - two copies kept by hand drift apart on the next change"
	}
	var missing, extra []string
	for _, v := range m.other.Members {
		if !slices.Contains(set.Members, v) {
			missing = append(missing, v)
		}
	}
	for _, v := range set.Members {
		if !slices.Contains(m.other.Members, v) {
			extra = append(extra, v)
		}
	}
	var diff []string
	if len(missing) > 0 {
		diff = append(diff, "missing here: "+strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		diff = append(diff, "only here: "+strings.Join(extra, ", "))
	}
	if m.rank == 3 {
		return fmt.Sprintf("TS type %s differs from the Go type %s (%s)", set.Name, where, strings.Join(diff, "; "))
	}
	return fmt.Sprintf("Set of values copies %s but differs (%s)", where, strings.Join(diff, "; "))
}
