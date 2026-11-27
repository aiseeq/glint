//go:build !race

package main

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// These tests inspect registry keys and cache metadata without running file
// analysis or starting glint workers in the test process.

// A rule that asks the registry whether a marker names a rule keeps its
// cached findings only while the registered rule names stay the same: a
// release that adds rule X turns a bare //nolint:X into a
// suppression-without-reason finding, and the cache of the release before
// must not hide it.
func TestRegistryReadersAreKeyedByRegisteredRuleNames(t *testing.T) {
	reader, ok := rules.Get("suppression-without-reason")
	require.True(t, ok)
	other, ok := rules.Get("deprecated-ioutil")
	require.True(t, ok)
	list := []rules.Rule{reader, other}
	content := sha256.Sum256([]byte("//nolint:probe-later-rule\npackage p\n"))

	open := func(names ...string) *resultCache {
		return &resultCache{
			build:            "build-v1",
			ruleFingerprints: map[string]string{},
			registry:         registryKey(names),
			previous:         map[string]cacheEntry{},
			current:          map[string]cacheEntry{},
		}
	}
	before := open("deprecated-ioutil", "suppression-without-reason")
	before.store("a.go", content, map[string][]core.Violation{reader.Name(): nil, other.Name(): nil}, before.fingerprints(list))

	after := open("deprecated-ioutil", "probe-later-rule", "suppression-without-reason")
	after.previous = before.current
	found := after.lookup("a.go", content, after.fingerprints(list))
	require.NotContains(t, found, reader.Name(), "a new registered rule must rerun suppression-without-reason")
	require.Contains(t, found, other.Name(), "a rule that does not read the registry keeps its cached findings")

	same := open("suppression-without-reason", "deprecated-ioutil")
	same.previous = before.current
	require.Contains(t, same.lookup("a.go", content, same.fingerprints(list)), reader.Name(), "the same rule names, in another order, keep the findings")
}

func TestStaleSuppressionReadsTheRegistry(t *testing.T) {
	for _, name := range []string{"suppression-without-reason", "stale-suppression"} {
		rule, ok := rules.Get(name)
		require.True(t, ok, name)
		_, reads := rule.(rules.RuleCacheReadsRegistry)
		require.True(t, reads, "%s judges marker names by the registry", name)
	}
}

// The cache a run opens keys the registry readers by every rule of the build.
func TestNewRootCacheKeysTheRegistryByAllRuleNames(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	cache, err := newRootCache("/project", "", core.DefaultConfig(), false)
	require.NoError(t, err)
	var names []string
	for _, rule := range rules.All() {
		names = append(names, rule.Name())
	}
	require.Contains(t, names, "suppression-without-reason")
	require.Equal(t, registryKey(names), cache.registry)
	require.NotEqual(t, registryKey(names[1:]), cache.registry, "one rule fewer is another registry")
}
