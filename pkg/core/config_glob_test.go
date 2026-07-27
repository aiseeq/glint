package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The default exclude list and the `glint init` template both use **, which
// filepath.Match silently ignores — vendored and generated files below the top
// level were analyzed anyway.
func TestShouldExcludeSupportsDoubleStar(t *testing.T) {
	cfg := DefaultConfig()

	excluded := []string{
		"vendor/pkg/mod/thing.go",
		"vendor/thing.go",
		"node_modules/@scope/pkg/index.js",
		"internal/api/service.pb.go",
		"gen/models/user.generated.go",
	}
	for _, path := range excluded {
		assert.True(t, cfg.ShouldExclude(path), "default config must exclude %q", path)
	}

	kept := []string{"pkg/core/config.go", "cmd/glint/main.go", "src/app.ts"}
	for _, path := range kept {
		assert.False(t, cfg.ShouldExclude(path), "default config must keep %q", path)
	}
}

// Single-star patterns must keep matching exactly one path segment, so that
// existing configurations do not silently start excluding more.
func TestShouldExcludeKeepsSingleStarSemantics(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Settings.Exclude = []string{"tests/*", "vendor/*", "*_test.go"}

	assert.True(t, cfg.ShouldExclude("tests/helper.go"))
	assert.False(t, cfg.ShouldExclude("tests/unit/helper.go"))
	assert.True(t, cfg.ShouldExclude("vendor/thing.go"))
	assert.False(t, cfg.ShouldExclude("vendor/pkg/mod/thing.go"))
	// Bare patterns keep matching by base name, as they always have.
	assert.True(t, cfg.ShouldExclude("pkg/core/config_test.go"))
	assert.False(t, cfg.ShouldExclude("pkg/core/config.go"))
}

func TestMatchGlobPatternDoubleStar(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"**/testdata/**", "pkg/rules/testdata/a/b.go", true},
		{"**/testdata/**", "testdata/a.go", true},
		{"**/testdata/**", "pkg/rules/data/a.go", false},
		{"backend/**/mocks/*.go", "backend/svc/x/mocks/user.go", true},
		{"backend/**/mocks/*.go", "frontend/svc/mocks/user.go", false},
		{"**/*.sql", "db/migrations/0001_init.up.sql", true},
		{"docs/**", "docs/a/b/c.md", true},
		{"docs/**", "docs/a.md", true},
		{"docs/**", "documentation/a.md", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, matchGlobPattern(tc.pattern, tc.path),
			"matchGlobPattern(%q, %q)", tc.pattern, tc.path)
	}
}

// Mentioning a category or a rule without repeating `enabled: true` used to
// switch it off, because the Go zero value of a bool is false.
func TestMentioningCategoryKeepsItEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".glint.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`version: 1
categories:
  typesafety:
    rules:
      interface-any:
        severity: critical
  patterns:
    enabled: false
`), 0o644))

	cfg, err := LoadConfig(path)
	require.NoError(t, err)

	assert.True(t, cfg.IsCategoryEnabled("typesafety"), "category mentioned without enabled must stay on")
	assert.True(t, cfg.IsRuleEnabled("typesafety", "interface-any"), "rule mentioned without enabled must stay on")
	assert.False(t, cfg.IsCategoryEnabled("patterns"), "explicit enabled:false must still disable")
}

func TestExplicitRuleDisableStillWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".glint.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`version: 1
categories:
  typesafety:
    rules:
      interface-any:
        enabled: false
`), 0o644))

	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	assert.False(t, cfg.IsRuleEnabled("typesafety", "interface-any"))
	assert.True(t, cfg.IsRuleEnabled("typesafety", "type-assertion"))
}

// severity / severity_override were declared in the YAML schema but never read.
func TestSeverityOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".glint.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`version: 1
categories:
  typesafety:
    severity_override: high
    rules:
      interface-any:
        severity: critical
`), 0o644))

	cfg, err := LoadConfig(path)
	require.NoError(t, err)

	sev, ok, err := cfg.SeverityOverrideFor("typesafety", "interface-any")
	require.NoError(t, err)
	require.True(t, ok, "rule-level severity must be honored")
	assert.Equal(t, SeverityCritical, sev)

	sev, ok, err = cfg.SeverityOverrideFor("typesafety", "type-assertion")
	require.NoError(t, err)
	require.True(t, ok, "category-level severity_override must apply to the other rules")
	assert.Equal(t, SeverityHigh, sev)

	_, ok, err = cfg.SeverityOverrideFor("patterns", "any-rule")
	require.NoError(t, err)
	assert.False(t, ok, "categories without an override must keep the rule's own severity")
}

func TestInvalidSeverityIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".glint.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`version: 1
categories:
  typesafety:
    rules:
      interface-any:
        severity: catastrophic
`), 0o644))

	_, err := LoadConfig(path)
	require.Error(t, err, "an unparseable severity must not be silently ignored")
	assert.Contains(t, err.Error(), "catastrophic")
}

// `extends` was declared in the schema and copied around, but never loaded.
func TestExtendsInheritsBaseConfig(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	require.NoError(t, os.WriteFile(base, []byte(`version: 1
settings:
  min_severity: high
  exclude:
    - "**/generated/**"
categories:
  deadcode:
    enabled: false
`), 0o644))

	child := filepath.Join(dir, ".glint.yaml")
	require.NoError(t, os.WriteFile(child, []byte(`version: 1
extends: base.yaml
categories:
  naming:
    enabled: false
`), 0o644))

	cfg, err := LoadConfig(child)
	require.NoError(t, err)

	assert.Equal(t, "high", cfg.Settings.MinSeverity, "settings must be inherited")
	assert.True(t, cfg.ShouldExclude("pkg/generated/api.go"), "exclude list must be inherited")
	assert.False(t, cfg.IsCategoryEnabled("deadcode"), "base category state must be inherited")
	assert.False(t, cfg.IsCategoryEnabled("naming"), "child category state must win")
}

func TestExtendsRejectsCycles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.yaml")
	b := filepath.Join(dir, "b.yaml")
	require.NoError(t, os.WriteFile(a, []byte("version: 1\nextends: b.yaml\n"), 0o644))
	require.NoError(t, os.WriteFile(b, []byte("version: 1\nextends: a.yaml\n"), 0o644))

	_, err := LoadConfig(a)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle")
}

func TestExtendsReportsMissingBase(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, ".glint.yaml")
	require.NoError(t, os.WriteFile(child, []byte("version: 1\nextends: nope.yaml\n"), 0o644))

	_, err := LoadConfig(child)
	require.Error(t, err, "a missing base config must fail loudly, not fall back to defaults")
}
