package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, 1, cfg.Version)
	assert.Equal(t, "low", cfg.Settings.MinSeverity)
	assert.Equal(t, "console", cfg.Settings.Output)
	assert.Contains(t, cfg.Settings.Exclude, "vendor/**")
	assert.Contains(t, cfg.Settings.Exclude, "node_modules/**")
}

func TestConfigGetMinSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
	}{
		{"low", SeverityLow},
		{"medium", SeverityMedium},
		{"high", SeverityHigh},
		{"critical", SeverityCritical},
		{"invalid", SeverityLow}, // defaults to low on error
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Settings.MinSeverity = tt.input
			assert.Equal(t, tt.expected, cfg.GetMinSeverity())
		})
	}
}

func TestConfigIsCategoryEnabled(t *testing.T) {
	cfg := DefaultConfig()

	// Default categories should be enabled
	assert.True(t, cfg.IsCategoryEnabled("architecture"))
	assert.True(t, cfg.IsCategoryEnabled("patterns"))

	// Unknown category defaults to enabled
	assert.True(t, cfg.IsCategoryEnabled("unknown"))
}

func TestConfigIsRuleEnabled(t *testing.T) {
	cfg := DefaultConfig()

	// Default categories should have all rules enabled
	assert.True(t, cfg.IsRuleEnabled("architecture", "any-rule"))
	assert.True(t, cfg.IsRuleEnabled("patterns", "any-rule"))

	// Disable a category
	cat := cfg.Categories["architecture"]
	cat.Enabled = false
	cfg.Categories["architecture"] = cat
	assert.False(t, cfg.IsRuleEnabled("architecture", "any-rule"))

	// Disable specific rule
	patternsCat := cfg.Categories["patterns"]
	patternsCat.Rules = map[string]RuleConfig{
		"specific-rule": {Enabled: false},
	}
	cfg.Categories["patterns"] = patternsCat
	assert.False(t, cfg.IsRuleEnabled("patterns", "specific-rule"))
	assert.True(t, cfg.IsRuleEnabled("patterns", "other-rule"))
}

func TestConfigShouldExclude(t *testing.T) {
	cfg := DefaultConfig()

	// Default exclusions use glob patterns
	// Note: filepath.Match doesn't support ** like doublestar
	// So we test with simple patterns
	cfg.Settings.Exclude = []string{
		"vendor/*",
		"node_modules/*",
		"*.generated.go",
	}

	assert.True(t, cfg.ShouldExclude("vendor/pkg"))
	assert.True(t, cfg.ShouldExclude("node_modules/pkg"))
	assert.True(t, cfg.ShouldExclude("file.generated.go"))
	assert.False(t, cfg.ShouldExclude("pkg/main.go"))
	assert.False(t, cfg.ShouldExclude("src/app.ts"))
}

func TestLoadConfig(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".glint.yaml")

	configContent := `version: 1
settings:
  min_severity: high
  output: json
  exclude:
    - "*.test.go"
categories:
  architecture:
    enabled: false
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, 1, cfg.Version)
	assert.Equal(t, "high", cfg.Settings.MinSeverity)
	assert.Equal(t, "json", cfg.Settings.Output)
	assert.Contains(t, cfg.Settings.Exclude, "*.test.go")
	assert.False(t, cfg.Categories["architecture"].Enabled)
}

func TestFindConfig(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "sub", "dir")
	err := os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	// Create config in root
	configPath := filepath.Join(tmpDir, ".glint.yaml")
	err = os.WriteFile(configPath, []byte("version: 1"), 0644)
	require.NoError(t, err)

	// Find from subdir should find parent config
	found, err := FindConfig(subDir)
	require.NoError(t, err)
	assert.Equal(t, configPath, found)

	// Find from root should find config
	found, err = FindConfig(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, configPath, found)
}

func TestMergeConfigs(t *testing.T) {
	base := DefaultConfig()
	base.Settings.MinSeverity = "low"

	override := &Config{
		Version: 1,
		Settings: SettingsConfig{
			MinSeverity: "high",
			Exclude:     []string{"custom/**"},
		},
		Categories: map[string]CategoryConfig{
			"custom": {Enabled: true},
		},
	}

	result := MergeConfigs(base, override)

	assert.Equal(t, "high", result.Settings.MinSeverity)
	assert.Contains(t, result.Settings.Exclude, "custom/**")
	assert.True(t, result.Categories["custom"].Enabled)
}

func TestLoadConfigWithDefaults(t *testing.T) {
	tmpDir := t.TempDir()

	// No config file - should return defaults
	cfg, err := LoadConfigWithDefaults(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, "low", cfg.Settings.MinSeverity)
	assert.True(t, cfg.IsCategoryEnabled("architecture"))
}

func TestGetRuleExceptions(t *testing.T) {
	cfg := DefaultConfig()

	// No exceptions initially
	exceptions := cfg.GetRuleExceptions("patterns", "some-rule")
	assert.Empty(t, exceptions)

	// Add exceptions
	patternsCat := cfg.Categories["patterns"]
	patternsCat.Rules = map[string]RuleConfig{
		"some-rule": {
			Enabled: true,
			Exceptions: []Exception{
				{File: "legacy.go", Reason: "Legacy code"},
			},
		},
	}
	cfg.Categories["patterns"] = patternsCat

	exceptions = cfg.GetRuleExceptions("patterns", "some-rule")
	assert.Len(t, exceptions, 1)
	assert.Equal(t, "legacy.go", exceptions[0].File)
}
