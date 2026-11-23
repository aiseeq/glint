package gorules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mapOrderProject(t *testing.T, source string) *core.GoProjectContext {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/order\n\ngo 1.24\n"), 0o644))
	path := filepath.Join(root, "order.go")
	require.NoError(t, os.WriteFile(path, []byte(source), 0o644))

	ctx, err := core.NewFileContextChecked(path, root, []byte(source), core.DefaultConfig())
	require.NoError(t, err)

	project, err := core.LoadGoProject(root, []*core.FileContext{ctx}, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	return project
}

func analyzeMapOrder(t *testing.T, source string) []*core.Violation {
	t.Helper()
	violations, err := NewMapIterationOrderRule().AnalyzeGoProject(mapOrderProject(t, source))
	require.NoError(t, err)
	return violations
}

// Repro from glint itself: the responsibility areas of a struct were collected
// by ranging over a map and then printed in the finding's message, so the same
// code produced different text on every run.
func TestMapIterationOrderReportsUnsortedCollect(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Areas(detected map[string]bool) []string {
	var areas []string
	for area := range detected {
		areas = append(areas, area)
	}
	return areas
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Contains(t, violations[0].Message, "areas")
}

// Sorting before the value leaves the function makes the order deterministic.
func TestMapIterationOrderAcceptsSortedCollect(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "sort"

func Areas(detected map[string]bool) []string {
	areas := make([]string, 0, len(detected))
	for area := range detected {
		areas = append(areas, area)
	}
	sort.Strings(areas)
	return areas
}
`)

	assert.Empty(t, violations)
}

func TestMapIterationOrderAcceptsSlicesSort(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

func Areas(detected map[string]int) []string {
	var areas []string
	for area := range detected {
		areas = append(areas, area)
	}
	slices.Sort(areas)
	return areas
}
`)

	assert.Empty(t, violations)
}

// A slice that never leaves the function cannot leak the order to a caller.
func TestMapIterationOrderIgnoresLocalOnlySlice(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Count(detected map[string]bool) int {
	var areas []string
	for area := range detected {
		areas = append(areas, area)
	}
	return len(areas)
}
`)

	assert.Empty(t, violations)
}

// Ranging over a slice keeps its order; only maps are unordered.
func TestMapIterationOrderIgnoresSliceRange(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Copy(items []string) []string {
	var out []string
	for _, item := range items {
		out = append(out, item)
	}
	return out
}
`)

	assert.Empty(t, violations)
}

// Building a message by concatenating map entries has the same problem.
func TestMapIterationOrderReportsStringAccumulation(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Describe(detected map[string]bool) string {
	message := ""
	for area := range detected {
		message += area + ", "
	}
	return message
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "message")
}

// Aggregation does not depend on the order the map is walked in.
func TestMapIterationOrderIgnoresOrderIndependentAggregation(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Total(counts map[string]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}
`)

	assert.Empty(t, violations)
}

// Collecting into a map keeps no order to leak.
func TestMapIterationOrderIgnoresMapToMap(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Invert(source map[string]string) map[string]string {
	result := make(map[string]string)
	for key, value := range source {
		result[value] = key
	}
	return result
}
`)

	assert.Empty(t, violations)
}

func TestMapIterationOrderMetadata(t *testing.T) {
	rule := NewMapIterationOrderRule()
	assert.Equal(t, "map-iteration-order", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.False(t, rule.RequiresSSA())
}

// Сортировка через собственный хелпер — та же гарантия порядка, что и sort.Strings.
// Репро из projectC: scheduler/xe_refresher.go собирает пары и зовёт sortOrderPairs.
func TestMapIterationOrderAcceptsSortHelper(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "sort"

func sortPairs(pairs [][2]string) {
	sort.Slice(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
}

func Pairs(unique map[[2]string]bool) [][2]string {
	pairs := make([][2]string, 0, len(unique))
	for pair := range unique {
		pairs = append(pairs, pair)
	}
	sortPairs(pairs)
	return pairs
}
`)
	assert.Empty(t, violations, "срез отсортирован перед возвратом: %v", violations)
}

// Repro from a real project: the configuration was chosen by walking a map and
// returning the first entry whose key matched loosely, so the same binary got a
// different configuration from run to run.
func TestMapIterationOrderReportsFirstMatchReturn(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "strings"

func Config(profiles map[string]int, binary string) int {
	for name, profile := range profiles {
		if strings.Contains(binary, name) {
			return profile
		}
	}
	return 0
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[0].Message, "picks")
}

// The same choice made through an outer variable and a break.
func TestMapIterationOrderReportsFirstMatchBreak(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Pick(profiles map[string]int, limit int) int {
	chosen := 0
	for _, profile := range profiles {
		if profile < limit {
			chosen = profile
			break
		}
	}
	return chosen
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
}

// A lookup by key equality picks the one entry that can match: map keys are
// unique, so the walk order changes nothing.
func TestMapIterationOrderAcceptsKeyEqualityLookup(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Lookup(profiles map[string]int, want string) int {
	for name, profile := range profiles {
		if name == want {
			return profile
		}
	}
	return 0
}
`)

	assert.Empty(t, violations)
}

// An existence check returns the same answer whatever the order.
func TestMapIterationOrderAcceptsExistenceCheck(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func AnyOver(profiles map[string]int, limit int) bool {
	for _, profile := range profiles {
		if profile > limit {
			return true
		}
	}
	return false
}
`)

	assert.Empty(t, violations)
}

// Picking the maximum is order-independent: the comparison, not the walk,
// decides the winner.
func TestMapIterationOrderAcceptsMaximumSearch(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Best(profiles map[string]int) int {
	best := 0
	for _, profile := range profiles {
		if profile > best {
			best = profile
		}
	}
	return best
}
`)

	assert.Empty(t, violations)
}

// False positive from a real project: a duplicate is found by comparing an
// identity field of the value. Such a field is treated as unique, the way a map
// key is, so the walk order does not decide the answer.
func TestMapIterationOrderAcceptsValueIdentityLookup(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Article struct {
	URL string
}

func Find(seen map[string]*Article, want *Article) *Article {
	for _, existing := range seen {
		if existing.URL == want.URL {
			return existing
		}
	}
	return nil
}
`)

	assert.Empty(t, violations)
}

// False positive from a real project: the function has already refused every
// case but one, so the loop takes the single entry left — there is nothing to
// choose between.
func TestMapIterationOrderAcceptsSingleEntryTake(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "errors"

func Only(matches map[string]int) (int, error) {
	if len(matches) > 1 {
		return 0, errors.New("ambiguous")
	}
	for _, match := range matches {
		return match, nil
	}
	return 0, errors.New("empty")
}
`)

	assert.Empty(t, violations)
}

// Passing the collected keys to a call hands their order on as surely as
// returning them does.
func TestMapIterationOrderReportsCollectPassedToCall(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"fmt"
	"strings"
)

func Print(m map[string]int) {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	fmt.Println(strings.Join(keys, ","))
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "keys")
}

// Printing inside the loop writes the entries in walk order.
func TestMapIterationOrderReportsPrintInsideLoop(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"fmt"
	"io"
)

func Dump(w io.Writer, m map[string]int) {
	for k, v := range m {
		fmt.Fprintf(w, "%s=%d\n", k, v)
	}
}

func Show(m map[string]int) {
	for k := range m {
		fmt.Println(k)
	}
}
`)

	require.Len(t, violations, 2)
	assert.Equal(t, "map_iteration_output", violations[0].Context["pattern"])
	assert.Equal(t, "map_iteration_output", violations[1].Context["pattern"])
}

// A builder filled in walk order and returned carries the order out.
func TestMapIterationOrderReportsBuilderThatLeaves(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "strings"

func Render(m map[string]int) string {
	var sb strings.Builder
	for k := range m {
		sb.WriteString(k)
	}
	return sb.String()
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, "map_iteration_output", violations[0].Context["pattern"])
}

// A builder whose content never leaves the function keeps the order inside.
func TestMapIterationOrderIgnoresBuilderThatStays(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "strings"

func Width(m map[string]int) int {
	var sb strings.Builder
	for k := range m {
		sb.WriteString(k)
	}
	return sb.Len()
}

func Quiet(m map[string]int) {
	for range m {
		println()
	}
}
`)

	assert.Empty(t, violations)
}

// Concatenating string variables is text as much as concatenating literals.
func TestMapIterationOrderReportsConcatenationOfKeys(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Join(m map[string]int) string {
	out := ""
	for k := range m {
		out += k
	}
	return out
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "out")
}

func sortableKeys(t *testing.T, gomod, source string) []any {
	t.Helper()
	project := rulestest.Project(t, map[string]string{"go.mod": gomod, "order/order.go": source})
	violations, err := NewMapIterationOrderRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	marks := make([]any, 0, len(violations))
	for _, v := range violations {
		marks = append(marks, v.Context["sortable_keys"])
	}
	return marks
}

const orderGoMod = "module example.com/order\n\ngo 1.24\n"

// The fixer sorts the keys with slices.Sorted(maps.Keys(m)); the rule marks the
// loops where that compiles and keeps the meaning.
func TestMapIterationOrderMarksSortableKeys(t *testing.T) {
	collect := func(keyType, body string) string {
		return `package order

type point struct{ X, Y int }

type accountID int64

func Keys(m map[` + keyType + `]int) []` + keyType + ` {
	var out []` + keyType + `
	for k, v := range m {
		out = append(out, k)
		_ = v
` + body + `	}
	return out
}
`
	}

	assert.Equal(t, []any{true}, sortableKeys(t, orderGoMod, collect("string", "")))
	assert.Equal(t, []any{true}, sortableKeys(t, orderGoMod, collect("accountID", "")))
	assert.Equal(t, []any{nil}, sortableKeys(t, orderGoMod, collect("point", "")), "a struct key is not cmp.Ordered")
	assert.Equal(t, []any{nil}, sortableKeys(t, orderGoMod, collect("string", "\t\tdelete(m, k)\n")), "a loop that edits the map sees the edits")
	assert.Equal(t, []any{nil}, sortableKeys(t, orderGoMod, collect("string", "\t\tv := 1\n\t\t_ = v\n")), "the value lookup would clash with the body's own v")
	assert.Equal(t, []any{nil}, sortableKeys(t, "module example.com/order\n\ngo 1.22\n", collect("string", "")), "slices.Sorted needs Go 1.23")
	assert.Equal(t, []any{nil}, sortableKeys(t, orderGoMod, `package order

var slices = 1

func Keys(m map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
`), "slices must name the package")
}

// The column pins the loop for the fixer.
func TestMapIterationOrderReportsColumn(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Keys(m map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
`)
	require.Len(t, violations, 1)
	assert.Equal(t, 2, violations[0].Column)
}

// A predicate over the collected values answers yes or no; the walk order
// cannot come out of it.
func TestMapIterationOrderIgnoresCollectPassedToPredicate(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func anyLong(names []string) bool {
	for _, name := range names {
		if len(name) > 10 {
			return true
		}
	}
	return false
}

func HasLong(m map[string]int) bool {
	var names []string
	for k := range m {
		names = append(names, k)
	}
	return anyLong(names)
}
`)

	assert.Empty(t, violations)
}

// Keys collected to fetch or update a batch go to a callee that treats them as
// a set: a lookup keyed by id or a query with `= ANY($1)` answers the same
// whatever order the ids come in. Only a call that writes the values out
// carries their order to the outside.
func TestMapIterationOrderIgnoresCollectPassedToBatchCall(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "context"

type priceClient interface {
	Prices(ctx context.Context, ids []string) (map[string]float64, error)
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (int64, error)
}

func Refresh(ctx context.Context, client priceClient, wanted map[string]bool) (map[string]float64, error) {
	ids := make([]string, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	return client.Prices(ctx, ids)
}

func Relabel(ctx context.Context, db execer, labels map[string]string) error {
	addresses := make([]string, 0, len(labels))
	names := make([]string, 0, len(labels))
	for address, label := range labels {
		addresses = append(addresses, address)
		names = append(names, label)
	}
	_, err := db.ExecContext(ctx, "UPDATE t SET label = v.label FROM unnest($1, $2) AS v(address, label)", addresses, names)
	return err
}
`)

	assert.Empty(t, violations)
}

// Handing the collected keys to a writer that leaves the function prints them
// in walk order.
func TestMapIterationOrderReportsCollectWrittenOut(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"fmt"
	"io"
	"strings"
)

func Dump(w io.Writer, m map[string]int) {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	fmt.Fprintln(w, strings.Join(keys, ","))
}

func Local(m map[string]int) int {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	var sb strings.Builder
	fmt.Fprint(&sb, keys)
	return sb.Len()
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "keys")
	assert.Equal(t, 11, violations[0].Line)
}

// A loop over the keys reads the entry through a local bound to it: the
// choice and the output still follow the walk.
func TestMapIterationOrderFollowsEntryBoundByKey(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"fmt"
	"io"
)

func Pick(profiles map[string]int, limit int) int {
	chosen := 0
	for k := range profiles {
		p := profiles[k]
		if p < limit {
			chosen = p
			break
		}
	}
	return chosen
}

func Dump(w io.Writer, counts map[string]int) {
	for k := range counts {
		v := counts[k]
		fmt.Fprintln(w, v)
	}
}
`)

	var lines []int
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{10, 21}, lines)
}

// A slice declared inside the map loop lives one iteration: it holds the
// entries of one map value, which the walk order does not touch. Repro from an
// inventory that joined the commands of each hook event, sorted in the loop
// body.
func TestMapIterationOrderIgnoresSliceOfOneIteration(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"sort"
	"strings"
)

type entry struct{ Extra string }

type group struct{ Commands []string }

func Describe(hooks map[string][]group, out map[string]*entry) {
	for event, groups := range hooks {
		var cmds []string
		for _, g := range groups {
			cmds = append(cmds, g.Commands...)
		}
		sort.Strings(cmds)
		out[event].Extra = strings.Join(cmds, "; ")
	}
	for event, groups := range hooks {
		var first []string
		for _, g := range groups {
			first = append(first, g.Commands[0])
		}
		out[event].Extra = strings.Join(first, "; ")
	}
}
`)

	assert.Empty(t, violations)
}

// The same slice filled by an inner walk over a map still takes that walk's
// order.
func TestMapIterationOrderReportsSliceOfOneIterationFilledFromInnerMap(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "strings"

type entry struct{ Extra string }

func Describe(hooks map[string]map[string]bool, out map[string]*entry) {
	for event, commands := range hooks {
		var cmds []string
		for cmd := range commands {
			cmds = append(cmds, cmd)
		}
		out[event].Extra = strings.Join(cmds, "; ")
	}
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 10, violations[0].Line)
	assert.Contains(t, violations[0].Message, "cmds")
}

// Repro of a real finding: a closure keeps the first report for each line and
// the loop over a map of owners feeds it messages naming the owner. Two owners
// sharing a line race for it, and the walk decides whose name the report
// carries - the order of the reports is sorted, their text is not stable.
func TestMapIterationOrderReportsDedupWinnerInClosure(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"cmp"
	"slices"
)

type Report struct {
	Line int
	Text string
}

func Collect(owners map[string][]int) []Report {
	taken := make(map[int]bool)
	var out []Report
	add := func(line int, text string) {
		if taken[line] {
			return
		}
		taken[line] = true
		out = append(out, Report{Line: line, Text: text})
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, "line is written by "+owner)
		}
	}
	slices.SortFunc(out, func(a, b Report) int { return cmp.Compare(a.Line, b.Line) })
	return out
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 25, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
	assert.Equal(t, "add", violations[0].Context["variable"])
}

// The same race through a method: the first owner noted at a position keeps it.
func TestMapIterationOrderReportsDedupWinnerInMethod(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type collector struct {
	byPos map[string]string
}

func (c *collector) note(pos, owner string) {
	if _, ok := c.byPos[pos]; ok {
		return
	}
	c.byPos[pos] = owner
}

func Owners(files map[string]string) map[string]string {
	c := &collector{byPos: map[string]string{}}
	for name, pos := range files {
		c.note(pos, name)
	}
	return c.byPos
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 17, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// A guard that only lets the first value in, written into a map the caller
// passed: the caller sees the winner.
func TestMapIterationOrderReportsDedupWinnerInFunctionOnParameter(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func remember(seen map[int]string, pos int, who string) {
	if seen[pos] == "" {
		seen[pos] = who
	}
}

func Claim(claims map[string]int, seen map[int]string) {
	for who, pos := range claims {
		remember(seen, pos, who)
	}
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 11, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// Deduplicating on the map key itself: a map holds a key once, so no two
// entries race for the same slot.
func TestMapIterationOrderAcceptsDedupOnMapKey(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Report struct {
	Owner string
	Text  string
}

func Collect(owners map[string]string) []Report {
	taken := make(map[string]bool)
	var out []Report
	add := func(owner, text string) {
		if taken[owner] {
			return
		}
		taken[owner] = true
		out = append(out, Report{Owner: owner, Text: text})
	}
	for owner, text := range owners {
		add(owner, text)
	}
	return out
}
`)

	for _, v := range violations {
		assert.NotEqual(t, "map_iteration_dedup_winner", v.Context["pattern"])
	}
}

// Walking the keys in a defined order makes the first one the same every run.
func TestMapIterationOrderAcceptsDedupOverSortedKeys(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"maps"
	"slices"
)

type Report struct {
	Line int
	Text string
}

func Collect(owners map[string][]int) []Report {
	taken := make(map[int]bool)
	var out []Report
	add := func(line int, text string) {
		if taken[line] {
			return
		}
		taken[line] = true
		out = append(out, Report{Line: line, Text: text})
	}
	for _, owner := range slices.Sorted(maps.Keys(owners)) {
		for _, line := range owners[owner] {
			add(line, "line is written by "+owner)
		}
	}
	return out
}
`)

	assert.Empty(t, violations)
}

// The kept value carries nothing of the entry beyond the deduplication key:
// whichever entry wins, the report reads the same.
func TestMapIterationOrderAcceptsDedupWithoutEntryInValue(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"cmp"
	"slices"
)

type Report struct {
	Line int
	Text string
}

type Site struct{ Line int }

func Collect(sites map[string]Site) []Report {
	taken := make(map[int]bool)
	var out []Report
	add := func(line int, text string) {
		if taken[line] {
			return
		}
		taken[line] = true
		out = append(out, Report{Line: line, Text: text})
	}
	for _, site := range sites {
		add(site.Line, "line is written twice")
	}
	slices.SortFunc(out, func(a, b Report) int { return cmp.Compare(a.Line, b.Line) })
	return out
}
`)

	assert.Empty(t, violations)
}

// Without a deduplication every entry lands in the result, and a sort on the
// whole value leaves nothing to the walk.
func TestMapIterationOrderAcceptsSortedCollectWithoutDedup(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"cmp"
	"slices"
)

type Report struct {
	Line int
	Text string
}

func Collect(owners map[string][]int) []Report {
	var out []Report
	add := func(line int, text string) {
		out = append(out, Report{Line: line, Text: text})
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, "line is written by "+owner)
		}
	}
	slices.SortFunc(out, func(a, b Report) int {
		return cmp.Or(cmp.Compare(a.Line, b.Line), cmp.Compare(a.Text, b.Text))
	})
	return out
}
`)

	assert.Empty(t, violations)
}

// A winner nobody reads after the loop is not output.
func TestMapIterationOrderAcceptsDedupThatStaysLocal(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Count(owners map[string][]int) int {
	taken := make(map[int]string)
	n := 0
	add := func(line int, text string) {
		if _, ok := taken[line]; ok {
			return
		}
		taken[line] = text
		n++
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, owner)
		}
	}
	return n
}
`)

	assert.Empty(t, violations)
}

// A lookup in a map the callee never fills is a filter, not a claim: every
// entry that passes it is kept.
func TestMapIterationOrderAcceptsLookupWithoutClaim(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

func Collect(owners map[string][]int, allowed map[int]bool) []string {
	var out []string
	add := func(line int, text string) {
		if allowed[line] {
			out = append(out, text)
		}
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, owner)
		}
	}
	slices.Sort(out)
	return out
}
`)

	assert.Empty(t, violations)
}

// A seen map the callee makes itself starts empty on every call: no entry
// claims a slot another one could want.
func TestMapIterationOrderAcceptsSeenMapOfOneCall(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type pair struct {
	line  int
	owner string
}

type book struct {
	pairs map[pair]bool
}

func (b *book) record(lines []int, owner string) {
	seen := map[int]bool{}
	for _, line := range lines {
		if seen[line] {
			continue
		}
		seen[line] = true
		b.pairs[pair{line, owner}] = true
	}
}

func Record(owners map[string][]int) map[pair]bool {
	b := &book{pairs: map[pair]bool{}}
	for owner, lines := range owners {
		b.record(lines, owner)
	}
	return b.pairs
}
`)

	for _, v := range violations {
		assert.NotEqual(t, "map_iteration_dedup_winner", v.Context["pattern"])
	}
}

// A seen map of one iteration only deduplicates the entry's own values: the
// entries of the map never meet in it.
func TestMapIterationOrderAcceptsDedupWithinOneIteration(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "fmt"

func remember(seen map[int]string, pos int, who string) {
	if seen[pos] == "" {
		seen[pos] = who
	}
}

func Claim(claims map[string][]int) {
	for who, positions := range claims {
		seen := map[int]string{}
		for _, pos := range positions {
			remember(seen, pos, who)
		}
		fmt.Println(who, seen)
	}
}
`)

	for _, v := range violations {
		assert.NotEqual(t, "map_iteration_dedup_winner", v.Context["pattern"])
	}
}

// The winner kept in package state outlives the call that chose it.
func TestMapIterationOrderReportsDedupWinnerInPackageState(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

var claimed = map[int]string{}

func Load(claims map[string]int) {
	for who, pos := range claims {
		claim(pos, who)
	}
}

func claim(pos int, who string) {
	if _, ok := claimed[pos]; ok {
		return
	}
	claimed[pos] = who
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 7, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// A slot claimed by a counter: the first call raises it, the later ones
// return.
func TestMapIterationOrderReportsDedupWinnerOnCounterClaim(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

func Collect(owners map[string][]int) []string {
	counts := map[int]int{}
	var out []string
	add := func(line int, text string) {
		if counts[line] > 0 {
			return
		}
		counts[line]++
		out = append(out, text)
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, owner)
		}
	}
	slices.Sort(out)
	return out
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 17, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// The slot is computed inside the callee from what the call passes, and the
// value is built in a local first.
func TestMapIterationOrderReportsDedupWinnerThroughDerivedSlot(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Site struct{ Line int }

type Report struct {
	Line int
	Text string
}

func Collect(owners map[string][]Site) []Report {
	taken := map[int]bool{}
	var out []Report
	add := func(at Site, text string) {
		line := at.Line
		if taken[line] {
			return
		}
		taken[line] = true
		report := Report{Line: line, Text: text}
		out = append(out, report)
	}
	for owner, sites := range owners {
		for _, site := range sites {
			add(site, "written by "+owner)
		}
	}
	return out
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 24, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// Keeping the largest value of a slot is a comparison, not a claim: the
// result is the same in any order.
func TestMapIterationOrderAcceptsBestPerSlot(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type File struct{ Line, Size int }

func keep(best map[int]int, line, size int) {
	if best[line] < size {
		best[line] = size
	}
}

func Largest(files map[string]File) map[int]int {
	best := map[int]int{}
	for _, f := range files {
		keep(best, f.Line, f.Size)
	}
	return best
}
`)

	assert.Empty(t, violations)
}

// A test of the slot that does not stop the write - here it counts the
// repeats - keeps every entry.
func TestMapIterationOrderAcceptsCountedDuplicates(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"cmp"
	"slices"
)

type Report struct {
	Line int
	Text string
}

func Collect(owners map[string][]int) ([]Report, int) {
	seen := map[int]bool{}
	dups := 0
	var out []Report
	add := func(line int, text string) {
		if seen[line] {
			dups++
		}
		seen[line] = true
		out = append(out, Report{Line: line, Text: text})
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, owner)
		}
	}
	slices.SortFunc(out, func(a, b Report) int {
		return cmp.Or(cmp.Compare(a.Line, b.Line), cmp.Compare(a.Text, b.Text))
	})
	return out, dups
}
`)

	assert.Empty(t, violations)
}

// A callee's own variable that happens to share a name with an escaping one
// of the caller is not the caller's.
func TestMapIterationOrderAcceptsCalleeLocalTarget(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func note(seen map[int]bool, line int, who string) {
	if seen[line] {
		return
	}
	seen[line] = true
	var out string
	out = who
	_ = out
}

func Collect(claims map[string]int) []string {
	seen := map[int]bool{}
	var out []string
	for who, line := range claims {
		note(seen, line, who)
	}
	return out
}
`)

	assert.Empty(t, violations)
}

// The entry reaches the kept value through a variadic parameter.
func TestMapIterationOrderReportsDedupWinnerThroughVariadic(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "strings"

func Collect(owners map[string][]int) map[int]string {
	taken := map[int]string{}
	add := func(line int, parts ...string) {
		if _, ok := taken[line]; ok {
			return
		}
		taken[line] = strings.Join(parts, "")
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, "written by ", owner)
		}
	}
	return taken
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 15, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// The winner is kept as a key: which owners make it into the set is the walk.
func TestMapIterationOrderReportsDedupWinnerKeptAsIndex(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func Winners(owners map[string][]int) map[string]bool {
	claimed := map[int]bool{}
	winners := map[string]bool{}
	claim := func(line int, owner string) {
		if claimed[line] {
			return
		}
		claimed[line] = true
		winners[owner] = true
	}
	for owner, lines := range owners {
		for _, line := range lines {
			claim(line, owner)
		}
	}
	return winners
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 15, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// The callee walks what it is given and skips a claimed slot with continue;
// the entry reaches the kept value only through that walk.
func TestMapIterationOrderReportsDedupWinnerInCalleeLoop(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Site struct {
	Line  int
	Owner string
}

type book struct {
	seen   map[int]bool
	owners map[int]string
}

func (b *book) claim(sites []Site) {
	for _, s := range sites {
		if b.seen[s.Line] {
			continue
		}
		b.seen[s.Line] = true
		b.owners[s.Line] = s.Owner
	}
}

func Claim(bySource map[string][]Site) map[int]string {
	b := &book{seen: map[int]bool{}, owners: map[int]string{}}
	for _, sites := range bySource {
		b.claim(sites)
	}
	return b.owners
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 26, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// A method of the entry claims a slot in shared state: the slot is one field
// of the entry, the kept value another.
func TestMapIterationOrderReportsDedupWinnerInEntryMethod(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type File struct {
	Line int
	Name string
}

func (f *File) claim(owners map[int]string) {
	if _, ok := owners[f.Line]; ok {
		return
	}
	owners[f.Line] = f.Name
}

func Owners(files map[string]*File) map[int]string {
	owners := map[int]string{}
	for _, f := range files {
		f.claim(owners)
	}
	return owners
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 18, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// State of the entry itself is claimed only by that entry: the entries of the
// map never meet in it.
func TestMapIterationOrderAcceptsPerEntryState(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "fmt"

type File struct {
	firsts map[int]string
}

func (f *File) note(line int, who string) {
	if _, ok := f.firsts[line]; ok {
		return
	}
	f.firsts[line] = who
}

func Note(files map[string]*File, hits map[string][]int) {
	for name, f := range files {
		for _, line := range hits[name] {
			f.note(line, name)
		}
		fmt.Println(f.firsts)
	}
}
`)

	for _, v := range violations {
		assert.NotEqual(t, "map_iteration_dedup_winner", v.Context["pattern"])
	}
}

// A write before the test of the slot runs on every call.
func TestMapIterationOrderAcceptsWriteBeforeGuard(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

func Collect(owners map[string][]int) ([]string, int) {
	seen := map[int]bool{}
	unique := 0
	var all []string
	add := func(line int, text string) {
		all = append(all, text)
		if seen[line] {
			return
		}
		seen[line] = true
		unique++
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, owner)
		}
	}
	slices.Sort(all)
	return all, unique
}
`)

	assert.Empty(t, violations)
}

// The kept value is the field the slot is built from: whoever wins, the same
// value is kept.
func TestMapIterationOrderAcceptsValueOfTheSlotField(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

type Site struct {
	Line  int
	Owner string
}

func Lines(bySource map[string][]Site) []int {
	taken := map[int]bool{}
	var out []int
	add := func(site Site) {
		if taken[site.Line] {
			return
		}
		taken[site.Line] = true
		out = append(out, site.Line)
	}
	for _, sites := range bySource {
		for _, site := range sites {
			add(site)
		}
	}
	slices.Sort(out)
	return out
}
`)

	assert.Empty(t, violations)
}

// The seen map is the entry's group, shared by every entry of that group: the
// comma-ok test reads the group's slot, and the entries of one group race.
func TestMapIterationOrderReportsDedupWinnerInSharedGroupMap(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Hit struct {
	Group string
	Line  int
}

func claim(seen map[int]string, line int, who string) {
	if _, ok := seen[line]; ok {
		return
	}
	seen[line] = who
}

func Claim(hits map[string]Hit, index map[string]map[int]string) {
	for who, h := range hits {
		claim(index[h.Group], h.Line, who)
	}
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 17, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// The seen map is picked by the loop key: each entry fills a map of its own,
// and no two entries meet in one.
func TestMapIterationOrderAcceptsSeenMapOfTheKey(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type pkgState struct {
	firsts map[string]string
}

func resolve(firsts map[string]string, byName map[string][]string) {
	for name, callees := range byName {
		if _, done := firsts[name]; done {
			continue
		}
		firsts[name] = callees[0]
	}
}

func Resolve(dirs map[string]*pkgState, decls map[string]map[string][]string) {
	for dir, byName := range decls {
		resolve(dirs[dir].firsts, byName)
	}
}
`)

	for _, v := range violations {
		assert.NotEqual(t, "map_iteration_dedup_winner", v.Context["pattern"])
	}
}

// The entry is written only in the branch where the slot is already taken:
// every later entry overwrites it, so the last one wins - an overwrite, not a
// first-wins claim.
func TestMapIterationOrderAcceptsWriteInTakenBranch(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type queue struct {
	pending map[int]bool
	again   map[int]string
}

func (q *queue) Queue(src map[string]int) {
	for name, slot := range src {
		q.push(slot, name)
	}
}

func (q *queue) push(slot int, name string) {
	if q.pending[slot] {
		q.again[slot] = name
		return
	}
	q.pending[slot] = true
}
`)

	for _, v := range violations {
		assert.NotEqual(t, "map_iteration_dedup_winner", v.Context["pattern"])
	}
}

// A test that leaves an else branch: the else branch is where the slot is
// free, and the entry kept there is the first one.
func TestMapIterationOrderReportsDedupWinnerInElseBranch(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

func Collect(owners map[string][]int) ([]string, int) {
	seen := map[int]bool{}
	dups := 0
	var out []string
	add := func(line int, text string) {
		if seen[line] {
			dups++
		} else {
			seen[line] = true
			out = append(out, text)
		}
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, owner)
		}
	}
	slices.Sort(out)
	return out, dups
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 19, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// The kept value is built from the slot alone, through a local: whoever wins,
// the same value is kept.
func TestMapIterationOrderAcceptsValueOfTheSlotThroughLocal(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type File struct{ Path string }

type Entry struct{ Path string }

type tree struct{ entries map[string]*Entry }

func (t *tree) Load(files map[string]File) {
	for _, f := range files {
		t.adopt(f.Path)
	}
}

func (t *tree) adopt(p string) {
	if t.entries[p] != nil {
		return
	}
	e := &Entry{Path: p}
	t.entries[p] = e
}
`)

	for _, v := range violations {
		assert.NotEqual(t, "map_iteration_dedup_winner", v.Context["pattern"])
	}
}

// The slot is built from the map key in a local of the loop: unique per entry.
func TestMapIterationOrderAcceptsSlotFromKeyThroughCallerLocal(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Entry struct {
	Path string
	Name string
}

type tree struct{ entries map[string]*Entry }

func (t *tree) Load(names map[string]string) {
	for dir, n := range names {
		p := dir + "/" + n
		t.adopt(p, n)
	}
}

func (t *tree) adopt(p, name string) {
	if t.entries[p] != nil {
		return
	}
	t.entries[p] = &Entry{Path: p, Name: name}
}
`)

	for _, v := range violations {
		assert.NotEqual(t, "map_iteration_dedup_winner", v.Context["pattern"])
	}
}

// The entry reaches the call through an element of the map value's slice.
func TestMapIterationOrderReportsDedupWinnerFromNestedElement(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "sort"

type Hit struct {
	Line int
	Who  string
}

func Owners(bySource map[string][]Hit) []string {
	seen := map[int]bool{}
	var out []string
	add := func(line int, who string) {
		if seen[line] {
			return
		}
		seen[line] = true
		out = append(out, who)
	}
	for _, hits := range bySource {
		for _, h := range hits {
			add(h.Line, h.Who)
		}
	}
	sort.Strings(out)
	return out
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 22, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// A generic callee is found through its origin.
func TestMapIterationOrderReportsDedupWinnerInGenericFunction(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func keep[K comparable, V any](dst map[K]V, k K, v V) {
	if _, ok := dst[k]; ok {
		return
	}
	dst[k] = v
}

func Owners(src map[string]int) map[int]string {
	out := map[int]string{}
	for name, slot := range src {
		keep(out, slot, name)
	}
	return out
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 13, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// A closure bound with var x = func(...) is the same callee.
func TestMapIterationOrderReportsDedupWinnerInVarClosure(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "sort"

func Pick(src map[string]int) []string {
	seen := map[int]bool{}
	var out []string
	var add = func(slot int, name string) {
		if seen[slot] {
			return
		}
		seen[slot] = true
		out = append(out, name)
	}
	for name, slot := range src {
		add(slot, name)
	}
	sort.Strings(out)
	return out
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 16, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// A value looked up by the key is not the key: two entries can hold the same
// line, so the slot is shared.
func TestMapIterationOrderReportsDedupWinnerOnValueLookedUpByKey(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

type Site struct{ Line int }

func Owners(sites map[string]Site) []string {
	seen := map[int]bool{}
	var out []string
	add := func(line int, who string) {
		if seen[line] {
			return
		}
		seen[line] = true
		out = append(out, who)
	}
	for owner := range sites {
		site := sites[owner]
		add(site.Line, owner)
	}
	slices.Sort(out)
	return out
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 19, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// A local built up from itself is followed once: the entry still reaches the
// kept value through it.
func TestMapIterationOrderReportsDedupWinnerThroughReassignedLocal(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

func Owners(owners map[string][]int) []string {
	seen := map[int]bool{}
	var out []string
	add := func(line int, who string) {
		if seen[line] {
			return
		}
		seen[line] = true
		label := "by "
		label = label + who
		out = append(out, label)
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, owner)
		}
	}
	slices.Sort(out)
	return out
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 19, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// The entry reaches the call through a local the loop declares from it.
func TestMapIterationOrderReportsDedupWinnerThroughLoopLocal(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

func Owners(claims map[string]int) []string {
	seen := map[int]bool{}
	var out []string
	add := func(line int, label string) {
		if seen[line] {
			return
		}
		seen[line] = true
		out = append(out, label)
	}
	for owner, line := range claims {
		label := "by " + owner
		add(line, label)
	}
	slices.Sort(out)
	return out
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 17, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// The write after a guard that marks the slot in its branch and goes on runs
// for every entry: every value is kept, none wins.
func TestMapIterationOrderAcceptsWriteAfterGuardBranch(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "slices"

func Collect(owners map[string][]int) ([]string, int) {
	seen := map[int]bool{}
	unique := 0
	var all []string
	add := func(line int, text string) {
		if !seen[line] {
			seen[line] = true
			unique++
		}
		all = append(all, text)
	}
	for owner, lines := range owners {
		for _, line := range lines {
			add(line, owner)
		}
	}
	slices.Sort(all)
	return all, unique
}
`)

	assert.Empty(t, violations)
}

// The claim reads the target through comma-ok in the guard's init: the value
// written while the slot is free is the first entry's.
func TestMapIterationOrderReportsDedupWinnerOnCommaOkClaim(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func first(dst map[int]string, slot int, val string) {
	if _, ok := dst[slot]; !ok {
		dst[slot] = val
	}
}

func Fill(dst map[int]string, src map[string]int) {
	for name, slot := range src {
		first(dst, slot, name)
	}
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 11, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// The caller passes the slot's own value as the kept value (p := n; adopt(p,
// n)): whoever wins, the same value is kept.
func TestMapIterationOrderAcceptsValueThatIsTheSlotArgument(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Entry struct {
	Path string
	Name string
}

type Tree struct{ entries map[string]*Entry }

func (t *Tree) Reconcile(listing map[string][]string) {
	for dir, names := range listing {
		for _, n := range names {
			p := n
			_ = dir
			t.adopt(p, n)
		}
	}
}

func (t *Tree) adopt(p, name string) {
	if t.entries[p] != nil {
		return
	}
	t.entries[p] = &Entry{Path: p, Name: name}
}
`)

	assert.Empty(t, violations)
}

// A value filled from the same argument as a field of the slot is more than
// the slot: adopt(e, e) keyed by e.ID keeps e.Name of the first entry.
func TestMapIterationOrderReportsDedupWinnerOnFieldOfSlotArgument(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Item struct {
	ID   int
	Name string
}

type Index struct{ names map[int]string }

func (x *Index) Fill(groups map[string]Item) {
	for _, it := range groups {
		x.adopt(it, it)
	}
}

func (x *Index) adopt(key, item Item) {
	if _, ok := x.names[key.ID]; ok {
		return
	}
	x.names[key.ID] = item.Name
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 12, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// A copy of the slot's value written again (p = strings.ToLower(p)) is no
// longer that value: "A" and "a" share the slot and keep different names.
func TestMapIterationOrderReportsDedupWinnerOnRewrittenSlotCopy(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import "strings"

type Tree struct{ names map[string]string }

func (t *Tree) Reconcile(listing map[string][]string) {
	for _, names := range listing {
		for _, n := range names {
			p := n
			p = strings.ToLower(p)
			t.adopt(p, n)
		}
	}
}

func (t *Tree) adopt(p, name string) {
	if _, ok := t.names[p]; ok {
		return
	}
	t.names[p] = name
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 12, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// A variadic value filled from the slot and from more of the entry keeps the
// rest: adopt(n, dir, n) keeps the dir of the first entry with that n.
func TestMapIterationOrderReportsDedupWinnerOnVariadicBesideSlotArgument(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Tree struct{ parts map[string][]string }

func (t *Tree) Reconcile(listing map[string][]string) {
	for dir, names := range listing {
		for _, n := range names {
			t.adopt(n, dir, n)
		}
	}
}

func (t *Tree) adopt(p string, parts ...string) {
	if t.parts[p] != nil {
		return
	}
	t.parts[p] = parts
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 8, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}

// The slot is the name the previous entry left (last = n after the call):
// a copy assigned after the call is not the value it is called with.
func TestMapIterationOrderReportsDedupWinnerOnSlotOfPreviousEntry(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Tree struct {
	next    map[string]string
	ignored map[string]bool
}

func (t *Tree) Reconcile(listing map[string][]string) {
	var last string
	for _, names := range listing {
		for _, n := range names {
			if _, skip := t.ignored[n]; skip {
				continue
			}
			t.adopt(last, n)
			last = n
		}
	}
}

func (t *Tree) adopt(p, name string) {
	if _, ok := t.next[p]; ok {
		return
	}
	t.next[p] = name
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 15, violations[0].Line)
	assert.Equal(t, "map_iteration_dedup_winner", violations[0].Context["pattern"])
}
