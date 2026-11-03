package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
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
