package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/internal/cachekey"
	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// useManifest makes the binary's cache key what read returns for the test.
func useManifest(t *testing.T, read func() (*cachekey.Manifest, error)) {
	t.Helper()
	previous := readManifest
	readManifest = read
	manifestOnce = sync.Once{}
	t.Cleanup(func() {
		readManifest = previous
		manifestOnce = sync.Once{}
	})
}

// magicNumberManifest describes a build whose only site is the registration
// of magic-number.
func magicNumberManifest(t *testing.T) *cachekey.Manifest {
	t.Helper()
	site, ok := rules.RegistrationSiteOf("magic-number")
	require.True(t, ok)
	var index cachekey.Index
	manifest := &cachekey.Manifest{Driver: "driver-1", All: "whole-build", DriverFuncs: []int{index.Add("m/cmd/glint/main.go:1")}}
	manifest.Sites = []cachekey.Site{{File: site.File, From: site.Line, To: site.Line, Hash: "magic-1", Funcs: []int{index.Add(site.File + ":65")}}}
	manifest.Funcs = index.Keys()
	return manifest
}

func TestRegistrationSiteIsTheRegisterCall(t *testing.T) {
	site, ok := rules.RegistrationSiteOf("magic-number")
	require.True(t, ok)
	assert.Equal(t, "github.com/aiseeq/glint/pkg/rules/patterns/moneyrules/magic_number.go", site.File)
	source, err := os.ReadFile("../../pkg/rules/patterns/moneyrules/magic_number.go")
	require.NoError(t, err)
	lines := strings.Split(string(source), "\n")
	require.Greater(t, len(lines), site.Line)
	assert.Contains(t, lines[site.Line-1], "rules.Register(NewMagicNumberRule())")
}

func TestRuleFingerprintIsItsRegistrationsHash(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	manifest := magicNumberManifest(t)
	useManifest(t, func() (*cachekey.Manifest, error) { return manifest, nil })

	cache, err := newRootCache("/project", "", core.DefaultConfig(), false)
	require.NoError(t, err)

	assert.Equal(t, "driver-1", cache.build, "the driver names the cache files")
	assert.Equal(t, "magic-1", cache.ruleFingerprints["magic-number"])
	assert.Equal(t, "whole-build", cache.allFingerprint)
	magic, _ := rules.Get("magic-number")
	other, _ := rules.Get("ignored-error")
	plain := &resultCache{ruleFingerprints: map[string]string{"magic-number": "magic-1"}, allFingerprint: "whole-build"}
	assert.Equal(t, "magic-1", plain.fingerprint(magic))
	assert.Equal(t, "whole-build", plain.fingerprint(other), "a rule the build has no site for is keyed by the whole build")
}

func TestTimingCountsRulesWhoseFingerprintChanged(t *testing.T) {
	dir := t.TempDir()
	first, second := newCountingRule("first", false), newCountingRule("second", false)
	list := []rules.Rule{first, second}
	run := func(fingerprints map[string]string) *resultCache {
		cache, err := openResultCache(dir, "/project", "", "build", "stamp")
		require.NoError(t, err)
		cache.ruleFingerprints = fingerprints
		cache.recordRuleFingerprints(list)
		require.NoError(t, cache.save())
		return cache
	}

	cold := run(map[string]string{"first": "a", "second": "b"})
	changed, total := cold.ruleFingerprintChanges()
	assert.Equal(t, [2]int{2, 2}, [2]int{changed, total}, "nothing was read")

	warm := run(map[string]string{"first": "a", "second": "b"})
	changed, total = warm.ruleFingerprintChanges()
	assert.Equal(t, [2]int{0, 2}, [2]int{changed, total})

	edited := run(map[string]string{"first": "a", "second": "c"})
	changed, total = edited.ruleFingerprintChanges()
	assert.Equal(t, [2]int{1, 2}, [2]int{changed, total})
}

func TestCacheDepsPrintsTheDriverAndEachRulesFunctions(t *testing.T) {
	manifest := magicNumberManifest(t)
	useManifest(t, func() (*cachekey.Manifest, error) { return manifest, nil })
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, runCacheDeps(cmd, nil))

	var deps struct {
		Driver []string            `json:"driver"`
		Rules  map[string][]string `json:"rules"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &deps))
	assert.Equal(t, []string{"m/cmd/glint/main.go:1"}, deps.Driver)
	site, _ := rules.RegistrationSiteOf("magic-number")
	assert.Equal(t, []string{site.File + ":65"}, deps.Rules["magic-number"])
	assert.Len(t, deps.Rules, rules.Count(), "every registered rule")
	assert.ElementsMatch(t, manifest.Funcs, deps.Rules["ignored-error"], "a rule without a site depends on everything")
}

func TestCacheDepsNeedsACacheKey(t *testing.T) {
	useManifest(t, func() (*cachekey.Manifest, error) { return nil, cachekey.ErrNone })
	require.ErrorContains(t, runCacheDeps(&cobra.Command{}, nil), "no cache key")
}
