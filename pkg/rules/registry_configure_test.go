package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// Rule-level settings used to replace the category-level ones wholesale,
// because BaseRule.Configure overwrites the settings map.
func TestConfigureAllMergesCategoryAndRuleSettings(t *testing.T) {
	registry := NewRegistry()
	rule := NewMockRule("merge-rule")
	rule.BaseRule = NewBaseRule("merge-rule", "architecture", "mock", core.SeverityMedium)
	require.NoError(t, registry.Register(rule))

	cfg := &core.Config{Categories: map[string]core.CategoryConfig{
		"architecture": {
			Enabled:  true,
			Settings: map[string]any{"max_complexity": 30, "shared": "category"},
			Rules: map[string]core.RuleConfig{
				"merge-rule": {Enabled: true, Settings: map[string]any{"max_lines": 200, "shared": "rule"}},
			},
		},
	}}
	require.NoError(t, registry.ConfigureAll(cfg))

	assert.Equal(t, 30, rule.GetIntSetting("max_complexity", 0), "category setting must survive rule settings")
	assert.Equal(t, 200, rule.GetIntSetting("max_lines", 0), "rule setting must be applied")
	assert.Equal(t, "rule", rule.GetStringSetting("shared", ""), "rule setting must win on conflict")
}

// Rules are process-wide singletons: analyzing a second project root must not
// inherit the settings configured for the first one.
func TestConfigureAllResetsSettingsBetweenConfigs(t *testing.T) {
	registry := NewRegistry()
	rule := NewMockRule("reset-rule")
	rule.BaseRule = NewBaseRule("reset-rule", "architecture", "mock", core.SeverityMedium)
	require.NoError(t, registry.Register(rule))

	withSettings := &core.Config{Categories: map[string]core.CategoryConfig{
		"architecture": {Enabled: true, Rules: map[string]core.RuleConfig{
			"reset-rule": {Enabled: true, Settings: map[string]any{"max_lines": 500}},
		}},
	}}
	require.NoError(t, registry.ConfigureAll(withSettings))
	require.Equal(t, 500, rule.GetIntSetting("max_lines", 42))

	bare := &core.Config{Categories: map[string]core.CategoryConfig{
		"architecture": {Enabled: true},
	}}
	require.NoError(t, registry.ConfigureAll(bare))
	assert.Equal(t, 42, rule.GetIntSetting("max_lines", 42),
		"settings from the previous config must not leak into the next one")
}
