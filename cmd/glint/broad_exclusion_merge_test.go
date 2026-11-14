package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/aiseeq/glint/pkg/core"
)

// mergeTemplates is the start of a configuration whose rule settings, which
// have no schema, hold the templates the cases merge: lines 1-20.
var mergeTemplates = []string{
	"version: 1",
	"categories:",
	"  deadcode:",
	"    rules:",
	"      unused-internal-export:",
	"        settings:",
	"          excepted: &excepted",
	"            suppression-without-reason:",
	"              exceptions:",
	"                - pattern: \"Suppression\"",
	"                  reason: legacy markers",
	"          off: &off",
	"            suppression-without-reason:",
	"              enabled: false",
	"          on: &on",
	"            suppression-without-reason:",
	"              enabled: true",
	"          nested: &nested",
	"            <<: [*excepted]",
	"            stale-suppression: {enabled: true}",
}

// The load of the configuration merges the keys a merge key (<<) brings into
// a mapping of categories or rules (yaml.v3): a key the mapping sets itself
// wins, and of a list the earlier mapping wins. broad-exclusion read the merge
// key as a rule named "<<", so an exception or a switch merged in took the
// watch away without a finding. It now reads the mapping as the load does,
// and reports what the merge brings on the line of the merge key.
func TestBroadExclusionFollowsMergeKeys(t *testing.T) {
	for name, tt := range map[string]struct {
		lines []string
		want  []string
		// off is what the load makes of it: suppression-without-reason
		// excepted or switched off.
		off bool
	}{
		"exceptions merged":          {[]string{"      <<: [*excepted]"}, []string{".glint.yaml:21"}, true},
		"rule switched off":          {[]string{"      <<: [*off]"}, []string{".glint.yaml:21"}, true},
		"on the lines below":         {[]string{"      <<:", "        - *excepted"}, []string{".glint.yaml:21"}, true},
		"merged into a merged one":   {[]string{"      <<: [*nested]"}, []string{".glint.yaml:21"}, true},
		"the earlier one wins":       {[]string{"      <<: [*on, *off]"}, nil, false},
		"the earlier one switches":   {[]string{"      <<: [*off, *on]"}, []string{".glint.yaml:21"}, true},
		"the earlier one has none":   {[]string{"      <<: [*on, *excepted]"}, nil, false},
		"a key of its own wins":      {[]string{"      suppression-without-reason:", "        enabled: true", "      <<: [*excepted]"}, nil, false},
		"its own key after the <<":   {[]string{"      <<: [*off]", "      suppression-without-reason: {enabled: true}"}, nil, false},
		"marker on the merge key":    {[]string{"      # broad-exclusion: safe — the legacy markers are tracked in one ticket", "      <<: [*excepted]"}, nil, true},
		"templates alone, as it was": {nil, nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeModuleFile(t, root, ".glint.yaml", strings.Join(slices.Concat(mergeTemplates, tt.lines), "\n")+"\n")
			writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
			cfg, err := core.LoadConfigWithDefaults(root)
			require.NoError(t, err)
			// The load and broad-exclusion read the same merge.
			off := cfg.IsRuleDisabled("deadcode", "suppression-without-reason") || len(cfg.GetRuleExceptions("deadcode", "suppression-without-reason")) > 0
			assert.Equal(t, tt.off, off, "the load")
			assert.Equal(t, tt.want, broadPlaces(t, root))
		})
	}
}

// A merge key in categories brings a category in as one of its own: one
// switched off, or the exceptions of a rule watching suppressions in it.
func TestBroadExclusionFollowsMergeKeysOfCategories(t *testing.T) {
	head := []string{"version: 1", "categories:", "  security:", "    rules:", "      hardcoded-secret:", "        settings:", "          tpl: &cats"}
	for name, tt := range map[string]struct {
		lines []string
		want  []string
	}{
		"category off":        {[]string{"            deadcode:", "              enabled: false", "  <<: [*cats]"}, []string{".glint.yaml:10"}},
		"exceptions":          {[]string{"            deadcode:", "              rules:", "                suppression-without-reason:", "                  exceptions:", "                    - pattern: \"Suppression\"", "                      reason: legacy markers", "  <<: [*cats]"}, []string{".glint.yaml:14"}},
		"category of its own": {[]string{"            deadcode:", "              enabled: false", "  deadcode:", "    severity_override: low", "  <<: [*cats]"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeModuleFile(t, root, ".glint.yaml", strings.Join(slices.Concat(head, tt.lines), "\n")+"\n")
			writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
			assert.Equal(t, tt.want, broadPlaces(t, root))
		})
	}
}

// A merge key of one mapping, an alias or a mapping written in place, merges
// it as a list of one does; the merge key itself goes. The load refuses one
// in a mapping it reads, so this reads the node broad-exclusion walks.
func TestExpandBroadAliasesMergesOneMapping(t *testing.T) {
	for name, source := range map[string]string{
		"alias":    "base: &base {a: 1, b: 2}\nm:\n  b: 3\n  <<: *base\n",
		"in place": "base: {}\nm:\n  b: 3\n  <<: {a: 1, b: 2}\n",
	} {
		t.Run(name, func(t *testing.T) {
			var doc yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(source), &doc))
			expandBroadAliases(&doc)
			m := configNode(doc.Content[0], "m")
			var keys []string
			forEachPair(m, func(key, value *yaml.Node) {
				keys = append(keys, fmt.Sprintf("%s=%s@%d", key.Value, value.Value, value.Line))
			})
			assert.Equal(t, []string{"b=3@3", "a=1@4"}, keys)
		})
	}
}

// Only a plain << is a merge key: a quoted one is a key like any other, and
// a << in a list is an item.
func TestExpandBroadAliasesKeepsWhatIsNoMergeKey(t *testing.T) {
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("base: &base {a: 1}\nm:\n  \"<<\": *base\nl: [<<, *base]\n"), &doc))
	expandBroadAliases(&doc)
	var keys []string
	forEachPair(configNode(doc.Content[0], "m"), func(key, _ *yaml.Node) { keys = append(keys, key.Value) })
	assert.Equal(t, []string{"<<"}, keys)
	list := configNode(doc.Content[0], "l")
	require.Len(t, list.Content, 2)
	assert.Equal(t, "<<", list.Content[0].Value)
}
