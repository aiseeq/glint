package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Collecting the keys of any map whose key type is ordered and sorting them is
// slices.Sorted(maps.Keys(m)), whatever the key type, the range form, the
// result form or the sort call; the advice names the map the code ranges over.
func TestReimplementedStdlibSortedMapKeysAnyOrderedKey(t *testing.T) {
	run := func(body string) []*core.Violation {
		source := "package helpers\n\nimport (\"slices\"; \"sort\")\n\nvar _ = slices.Sort[[]int]\nvar _ = sort.Ints\n\ntype ID int\ntype pair struct{ a, b int }\ntype store struct{ items map[string]int }\n\n" + body
		return rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
			"go.mod":     "module example.com/helpers\n\ngo 1.23\n",
			"helpers.go": source,
		})
	}
	for name, body := range map[string]string{
		"blank value": `func sortedKeys(m map[string]int) []string {
	var keys []string
	for k, _ := range m { keys = append(keys, k) }
	sort.Strings(keys)
	return keys
}
`,
		"named key type": `func sortedIDs(m map[ID]string) []ID {
	ids := make([]ID, 0, len(m))
	for id := range m { ids = append(ids, id) }
	slices.Sort(ids)
	return ids
}
`,
		"int64 key": `func sortedIDs(m map[int64]bool) []int64 {
	ids := make([]int64, 0, len(m))
	for id := range m { ids = append(ids, id) }
	slices.Sort(ids)
	return ids
}
`,
		"named result": `func sortedKeys(m map[string]int) (keys []string) {
	keys = nil
	for k := range m { keys = append(keys, k) }
	sort.Strings(keys)
	return keys
}
`,
		"sort.Sort of a StringSlice": `func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m { keys = append(keys, k) }
	sort.Sort(sort.StringSlice(keys))
	return keys
}
`,
	} {
		assert.Len(t, run(body), 1, name)
	}

	// A struct key has no order: sorting by a field is not slices.Sorted.
	assert.Empty(t, run(`func sortedPairs(m map[pair]bool) []pair {
	keys := make([]pair, 0, len(m))
	for k := range m { keys = append(keys, k) }
	sort.Slice(keys, func(i, j int) bool { return keys[i].a < keys[j].a })
	return keys
}
`), "struct key")

	violations := run(`func (s *store) sortedKeys() []string {
	keys := make([]string, 0, len(s.items))
	for k := range s.items { keys = append(keys, k) }
	sort.Strings(keys)
	return keys
}
`)
	if assert.Len(t, violations, 1, "map in a field") {
		assert.Contains(t, violations[0].Message, "slices.Sorted(maps.Keys(s.items))")
	}
}

// The same three statements - an empty keys slice, a range appending every
// key, an ascending sort - inside a longer function or a nested block are
// slices.Sorted(maps.Keys(m)) too; the finding is on the declaration.
func TestReimplementedStdlibSortedMapKeysInsideLongerFunction(t *testing.T) {
	run := func(goVersion, body string) []*core.Violation {
		source := "package helpers\n\nimport (\"fmt\"; \"slices\"; \"sort\")\n\nvar _ = slices.Sort[[]int]\nvar _ = sort.Ints\nvar _ = fmt.Println\n\ntype pair struct{ a, b int }\n\n" + body
		return rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
			"go.mod":     "module example.com/helpers\n\ngo " + goVersion + "\n",
			"helpers.go": source,
		})
	}

	violations := run("1.23", `func report(m map[string]int) {
	fmt.Println("report")
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Println(k, m[k])
	}
}
`)
	if assert.Len(t, violations, 1, "inside a longer function") {
		assert.Contains(t, violations[0].Message, "slices.Sorted(maps.Keys(m))")
		assert.Equal(t, 13, violations[0].Line)
	}

	assert.Len(t, run("1.23", `func report(m map[int]bool, verbose bool) {
	if verbose {
		var ids []int
		for id := range m { ids = append(ids, id) }
		slices.Sort(ids)
		fmt.Println(ids)
	}
}
`), 1, "inside a nested block")

	assert.Len(t, run("1.23", `func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m { keys = append(keys, k) }
	sort.Strings(keys)
	return keys
}
`), 1, "the whole function is one finding, not two")

	for name, body := range map[string]string{
		"a statement between the loop and the sort": `func report(m map[string]int) {
	keys := make([]string, 0, len(m))
	for k := range m { keys = append(keys, k) }
	keys = append(keys, "total")
	sort.Strings(keys)
	fmt.Println(keys)
}
`,
		"a filtered loop": `func report(m map[string]int) {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v > 0 { keys = append(keys, k) }
	}
	sort.Strings(keys)
	fmt.Println(keys)
}
`,
		"a struct key": `func report(m map[pair]bool) {
	keys := make([]pair, 0, len(m))
	for k := range m { keys = append(keys, k) }
	sort.Slice(keys, func(i, j int) bool { return keys[i].a < keys[j].a })
	fmt.Println(keys)
}
`,
		"a descending sort": `func report(m map[string]int) {
	keys := make([]string, 0, len(m))
	for k := range m { keys = append(keys, k) }
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	fmt.Println(keys)
}
`,
	} {
		assert.Empty(t, run("1.23", body), name)
	}

	assert.Empty(t, run("1.22", `func report(m map[string]int) {
	keys := make([]string, 0, len(m))
	for k := range m { keys = append(keys, k) }
	sort.Strings(keys)
	fmt.Println(keys)
}
`), "before go 1.23 there is no maps.Keys")
}

// The fixer gets the keys name only where slices.Sorted's nil for an empty map
// reads as the empty slice the block built: var keys []T, or keys only ranged
// over and measured afterwards.
func TestReimplementedStdlibMarksSortedKeysBlockForFix(t *testing.T) {
	mark := func(start, use string) any {
		source := "package helpers\n\nimport (\"encoding/json\"; \"fmt\"; \"sort\")\n\nvar _ = json.Marshal\n\nfunc report(m map[string]int) {\n\tfmt.Println()\n\t" + start + "\n\tfor k := range m { keys = append(keys, k) }\n\tsort.Strings(keys)\n\t" + use + "\n}\n"
		violations := rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
			"go.mod":     "module example.com/helpers\n\ngo 1.23\n",
			"helpers.go": source,
		})
		require.Len(t, violations, 1, start+" / "+use)
		return violations[0].Context["fix_sorted_keys"]
	}
	assert.Equal(t, "keys", mark("keys := make([]string, 0, len(m))", "for _, k := range keys { fmt.Println(k, len(keys)) }"))
	assert.Equal(t, "keys", mark("var keys []string", "_, _ = json.Marshal(keys)"))
	assert.Nil(t, mark("keys := []string{}", "_, _ = json.Marshal(keys)"))
	assert.Equal(t, "keys", mark("keys := []string{}", "fmt.Println(keys[0], len(keys))"))
	assert.Nil(t, mark("keys := make([]string, 0)", "fmt.Println(keys == nil)"))
	// A subslice of nil is nil, of an empty slice empty: it carries the difference out.
	assert.Nil(t, mark("keys := []string{}", "_, _ = json.Marshal(keys[1:])"))
	// keys := replacement with no read after it does not compile.
	assert.Nil(t, mark("keys := []string{}", ""))
	assert.Nil(t, mark("var keys []string", ""))
	// An assignment is no read: keys := replacement with only keys = nil after it does not compile.
	assert.Nil(t, mark("var keys []string", "keys = nil"))
	assert.Nil(t, mark("var keys []string", "(keys) = nil"))
	assert.Nil(t, mark("var keys []string", "for _, keys = range [][]string{} {}"))
}

func TestReimplementedStdlibSortedKeysNeedBuiltinLenAndNil(t *testing.T) {
	run := func(source string) []*core.Violation {
		return rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
			"go.mod":     "module example.com/helpers\n\ngo 1.23\n",
			"helpers.go": source,
		})
	}
	// A local len in the capacity runs for its effect; the rewrite would drop the call.
	assert.Empty(t, run("package helpers\n\nimport (\"fmt\"; \"sort\")\n\nfunc report(m map[string]int) {\n\tlen := func(map[string]int) int { fmt.Println(); return 0 }\n"+
		"\tkeys := make([]string, 0, len(m))\n\tfor k := range m { keys = append(keys, k) }\n\tsort.Strings(keys)\n\tfmt.Println(keys)\n}\n"))
	// A package nil that is no empty slice starts keys with elements.
	assert.Empty(t, run("package helpers\n\nimport \"sort\"\n\nvar nil = []string{\"x\"}\n\nfunc keysOf(m map[string]int) (keys []string) {\n\tkeys = nil\n"+
		"\tfor k := range m { keys = append(keys, k) }\n\tsort.Strings(keys)\n\treturn keys\n}\n"))
}

func TestReimplementedStdlibSortedKeysNeedBuiltinAppend(t *testing.T) {
	// A local append collects whatever it likes.
	violations := rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
		"go.mod": "module example.com/helpers\n\ngo 1.23\n",
		"helpers.go": "package helpers\n\nimport (\"fmt\"; \"sort\")\n\nfunc report(m map[string]int) {\n\tappend := func(s []string, _ string) []string { return s }\n\tvar keys []string\n" +
			"\tfor k := range m { keys = append(keys, k) }\n\tsort.Strings(keys)\n\tfmt.Println(keys)\n}\n",
	})
	assert.Empty(t, violations)
}

func TestReimplementedStdlibSortedKeysBlockFixKeepsImportsUsed(t *testing.T) {
	// slices imported as s: the rewrite would leave the import s unused.
	violations := rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
		"go.mod": "module example.com/helpers\n\ngo 1.23\n",
		"helpers.go": "package helpers\n\nimport (\"fmt\"; s \"slices\")\n\nfunc report(m map[string]int) {\n\tfmt.Println()\n\tvar keys []string\n" +
			"\tfor k := range m { keys = append(keys, k) }\n\ts.Sort(keys)\n\tfmt.Println(keys)\n}\n",
	})
	require.Len(t, violations, 1)
	assert.Nil(t, violations[0].Context["fix_sorted_keys"])
}

func TestReimplementedStdlibSortedKeysBlockFixNeedsBuiltinLen(t *testing.T) {
	// A local len may tell nil from empty.
	violations := rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
		"go.mod": "module example.com/helpers\n\ngo 1.23\n",
		"helpers.go": "package helpers\n\nimport (\"fmt\"; \"sort\")\n\nfunc report(m map[string]int) {\n\tlen := func(s []string) bool { return s == nil }\n\tkeys := []string{}\n" +
			"\tfor k := range m { keys = append(keys, k) }\n\tsort.Strings(keys)\n\tfmt.Println(len(keys))\n}\n",
	})
	require.Len(t, violations, 1)
	assert.Nil(t, violations[0].Context["fix_sorted_keys"])
}

func TestReimplementedStdlibSortSliceOfFloatKeysIsNotSorted(t *testing.T) {
	// sort.Slice by < leaves NaN keys anywhere; slices.Sorted puts them first.
	violations := rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
		"go.mod": "module example.com/helpers\n\ngo 1.23\n",
		"helpers.go": "package helpers\n\nimport (\"fmt\"; \"sort\")\n\nfunc report(m map[float64]int) {\n\tfmt.Println()\n\tvar keys []float64\n" +
			"\tfor k := range m { keys = append(keys, k) }\n\tsort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })\n\tfmt.Println(keys)\n}\n",
	})
	assert.Empty(t, violations)
}

func TestReimplementedStdlibSortedKeysBlockFixNeedsPlainNames(t *testing.T) {
	run := func(files map[string]string) []*core.Violation {
		files["go.mod"] = "module example.com/helpers\n\ngo 1.23\n"
		return rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), files)
	}
	body := func(rangeOver string) string {
		return "\tfmt.Println()\n\tvar keys []string\n\tfor k := range " + rangeOver + " { keys = append(keys, k) }\n\tsort.Strings(keys)\n\tfmt.Println(keys)\n"
	}

	// maps declared by another file of the package: an added import "maps" collides with it.
	violations := run(map[string]string{
		"helpers.go": "package helpers\n\nimport (\"fmt\"; \"sort\")\n\nfunc report(m map[string]int) {\n" + body("m") + "}\n",
		"other.go":   "package helpers\n\nvar maps = 1\n",
	})
	require.Len(t, violations, 1)
	assert.Nil(t, violations[0].Context["fix_sorted_keys"], "maps names a package variable")

	// The replacement must be the map's source: a literal prints as {…}.
	violations = run(map[string]string{
		"helpers.go": "package helpers\n\nimport (\"fmt\"; \"sort\")\n\nfunc report() {\n" + body(`map[string]int{"a": 1}`) + "}\n",
	})
	require.Len(t, violations, 1)
	assert.Nil(t, violations[0].Context["fix_sorted_keys"], "a map literal")

	// The map is computed from keys itself: the rewrite would hand it the outer keys.
	violations = run(map[string]string{
		"helpers.go": "package helpers\n\nimport (\"fmt\"; \"sort\")\n\nfunc pick(s []string) map[string]int { return nil }\n\nfunc report() {\n" + body("pick(keys)") + "}\n",
	})
	require.Len(t, violations, 1)
	assert.Nil(t, violations[0].Context["fix_sorted_keys"], "a map computed from keys")
}

func TestReimplementedStdlibSortedKeysBlockSortsWithPackageSort(t *testing.T) {
	// sort here is a value whose Strings sorts in descending order, not package sort.
	violations := rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
		"go.mod": "module example.com/helpers\n\ngo 1.23\n",
		"helpers.go": "package helpers\n\nimport \"fmt\"\n\ntype descending struct{}\n\nfunc (descending) Strings([]string) {}\n\n" +
			"func report(m map[string]int) {\n\tsort := descending{}\n\tfmt.Println()\n\tkeys := []string{}\n\tfor k := range m { keys = append(keys, k) }\n\tsort.Strings(keys)\n\tfmt.Println(keys[0])\n}\n",
	})
	assert.Empty(t, violations)
}

// strings.Join reads nil as it reads an empty slice: both join to "".
func TestReimplementedStdlibSortedKeysBlockFixJoinsKeys(t *testing.T) {
	mark := func(imports, use string) any {
		source := "package helpers\n\nimport (\"fmt\"; \"sort\"; " + imports + ")\n\nfunc report(m map[string]int) string {\n\tfmt.Println()\n\tkeys := make([]string, 0, len(m))\n\tfor k := range m { keys = append(keys, k) }\n\tsort.Strings(keys)\n\treturn " + use + "\n}\n"
		violations := rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
			"go.mod":             "module example.com/helpers\n\ngo 1.23\n",
			"helpers.go":         source,
			"strings/strings.go": "package strings\n\nimport \"fmt\"\n\nfunc Join(s []string, sep string) string { return fmt.Sprint(s == nil) }\n",
		})
		require.Len(t, violations, 1, use)
		return violations[0].Context["fix_sorted_keys"]
	}
	assert.Equal(t, "keys", mark(`"strings"`, `strings.Join(keys, ",")`))
	assert.Nil(t, mark(`strs "strings"`, `strs.Join(keys, ",") + fmt.Sprint(keys == nil)`), "another read tells nil apart")
	assert.Nil(t, mark(`"example.com/helpers/strings"`, `strings.Join(keys, ",")`), "a Join of another package")
	assert.Nil(t, mark(`"strings"`, `strings.Join(keys[1:], ",")`), "a subslice carries nil out")
}

// The keys of a map held in another map or a field's map are the same
// expression read once: slices.Sorted(maps.Keys(g[name])).
func TestReimplementedStdlibSortedKeysBlockFixOfIndexedMap(t *testing.T) {
	mark := func(over string) (any, any) {
		source := "package helpers\n\nimport (\"fmt\"; \"sort\")\n\ntype groups struct{ other map[string]map[string]int }\n\nfunc name() string { return \"\" }\n\n" +
			"func report(g groups, byID []map[string]int, id int, n string) {\n\tfmt.Println()\n\tvar keys []string\n\tfor k := range " + over + " { keys = append(keys, k) }\n\tsort.Strings(keys)\n\tfmt.Println(keys)\n}\n"
		violations := rulestest.RunRuleOnFiles(t, NewReimplementedStdlibRule(), map[string]string{
			"go.mod":     "module example.com/helpers\n\ngo 1.23\n",
			"helpers.go": source,
		})
		require.Len(t, violations, 1, over)
		return violations[0].Context["fix_sorted_keys"], violations[0].Context["replacement"]
	}
	keys, replacement := mark("g.other[n]")
	assert.Equal(t, "keys", keys)
	assert.Equal(t, "slices.Sorted(maps.Keys(g.other[n]))", replacement)
	keys, _ = mark(`g.other["a"]`)
	assert.Equal(t, "keys", keys)
	keys, _ = mark("byID[id]")
	assert.Equal(t, "keys", keys)
	keys, _ = mark("g.other[name()]")
	assert.Nil(t, keys, "a call in the index runs once instead of twice")
	keys, _ = mark("g.other[fmt.Sprint(id)]")
	assert.Nil(t, keys, "a call in the index")
	keys, _ = mark("g.other[keys[0]]")
	assert.Nil(t, keys, "the map read through the slice the block declares")
}
