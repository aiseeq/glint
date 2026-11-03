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
	assert.Equal(t, "keys", mark("keys := []string{}", "fmt.Println(keys[0], keys[1:])"))
	assert.Nil(t, mark("keys := make([]string, 0)", "fmt.Println(keys == nil)"))
}
