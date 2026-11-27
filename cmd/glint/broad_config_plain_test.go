//go:build !race

package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// These are parser and name-classification unit tests. They do not load a
// project source tree or start analysis workers.

// A test file is named by its language: Go by _test.go, TypeScript and
// JavaScript by .test or .spec before the extension.
func TestTestFileLanguage(t *testing.T) {
	for file, want := range map[string][2]string{
		"a/x_test.go":  {"Go", "test"},
		"a/x.go":       {"Go", ""},
		"a/x.test.ts":  {"TypeScript", "test"},
		"a/x.spec.mts": {"TypeScript", "test"},
		"a/x.tsx":      {"TypeScript", ""},
		"a/test.ts":    {"TypeScript", ""},
		"a/x.test.JS":  {"JavaScript", "test"},
		"a/x.spec.cjs": {"JavaScript", "test"},
		"a/x.jsx":      {"JavaScript", ""},
		"a/x.test.md":  {"", ""},
		"a/x_Test.go":  {"Go", ""},
		"a/x.Spec.ts":  {"TypeScript", ""},
	} {
		language, test := testFileLanguage(file)
		kind := ""
		if test {
			kind = "test"
		}
		assert.Equal(t, want, [2]string{language, kind}, file)
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
