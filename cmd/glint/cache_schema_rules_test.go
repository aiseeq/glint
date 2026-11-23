package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules"
)

// Every registered rule that reads the SQL schema - it takes the migrations
// setting - keys its cached findings by the migration bytes: a cached finding
// of a column later made NOT NULL must not outlive the migration.
func TestEveryMigrationsRuleKeysItsCacheByMigrationBytes(t *testing.T) {
	root := func(ddl string) string {
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "migrations"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "migrations", "001_init.up.sql"), []byte(ddl), 0o600))
		return dir
	}
	nullable := root("CREATE TABLE accounts (id INTEGER PRIMARY KEY, nickname TEXT);\n")
	notNull := root("CREATE TABLE accounts (id INTEGER PRIMARY KEY, nickname TEXT NOT NULL);\n")
	fileKey := func(rule rules.Rule, root string) (bool, string) {
		cache := &resultCache{build: "build", ruleFingerprints: map[string]string{}, previous: map[string]cacheEntry{}, current: map[string]cacheEntry{}}
		local, keys := fileCacheRules(cache, []rules.Rule{rule}, root)
		return local[0], keys[rule.Name()]
	}
	var checked []string
	for _, rule := range rules.All() {
		settings, ok := rule.(interface{ SettingSpecs() []rules.SettingSpec })
		if !ok || !slices.ContainsFunc(settings.SettingSpecs(), func(spec rules.SettingSpec) bool { return spec.Key == "migrations" }) {
			continue
		}
		checked = append(checked, rule.Name())
		input, ok := rule.(rules.CacheInputRule)
		if !assert.True(t, ok, "%s reads migrations but declares no CacheInputs", rule.Name()) {
			continue
		}
		before, err := input.CacheInputs(nullable)
		require.NoError(t, err, rule.Name())
		after, err := input.CacheInputs(notNull)
		require.NoError(t, err, rule.Name())
		assert.NotEqual(t, before, after, "%s keeps one cache key across a migration change", rule.Name())
		// The cache that keeps the findings of the rule reads CacheInputs.
		switch rule.(type) {
		case rules.GoProjectRule:
			// keyProject adds the CacheInputs of every project rule.
		case rules.ProjectFilesRule:
			if rootProjectRuleCacheable(rule) {
				_, keyed := rule.(rules.RootFilesAndCacheInputs)
				assert.True(t, keyed, "%s keeps root findings in the cache without its CacheInputs: declare RootFilesAndCacheInputs", rule.Name())
			}
		default:
			cachedBefore, keyBefore := fileKey(rule, nullable)
			cachedAfter, keyAfter := fileKey(rule, notNull)
			if cachedBefore || cachedAfter {
				assert.NotEqual(t, keyBefore, keyAfter, "%s keeps file findings in the cache without its CacheInputs: declare ReadsOtherFiles", rule.Name())
			}
		}
	}
	assert.Contains(t, checked, "sql-scan-nullable-into-value")
}
