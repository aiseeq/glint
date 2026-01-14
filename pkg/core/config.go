package core

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the glint configuration
type Config struct {
	Version    int                       `yaml:"version"`
	Extends    string                    `yaml:"extends,omitempty"`
	Settings   SettingsConfig            `yaml:"settings"`
	Categories map[string]CategoryConfig `yaml:"categories"`
}

// SettingsConfig contains global settings
type SettingsConfig struct {
	Exclude     []string `yaml:"exclude"`
	MinSeverity string   `yaml:"min_severity"`
	Output      string   `yaml:"output"`
}

// CategoryConfig contains category-specific settings
type CategoryConfig struct {
	Enabled          bool                  `yaml:"enabled"`
	SeverityOverride string                `yaml:"severity_override,omitempty"`
	Settings         map[string]any        `yaml:"settings,omitempty"`
	Rules            map[string]RuleConfig `yaml:"rules,omitempty"`
}

// RuleConfig contains rule-specific settings
type RuleConfig struct {
	Enabled    bool           `yaml:"enabled"`
	Severity   string         `yaml:"severity,omitempty"`
	Settings   map[string]any `yaml:"settings,omitempty"`
	Exceptions []Exception    `yaml:"exceptions,omitempty"`
}

// Exception defines when a rule should be skipped
type Exception struct {
	File     string `yaml:"file,omitempty"`
	Line     int    `yaml:"line,omitempty"`
	Files    string `yaml:"files,omitempty"`    // Glob pattern
	Pattern  string `yaml:"pattern,omitempty"`  // Code pattern
	Function string `yaml:"function,omitempty"` // Function name
	Reason   string `yaml:"reason,omitempty"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Version: 1,
		Settings: SettingsConfig{
			Exclude: []string{
				"vendor/**",
				"node_modules/**",
				".git/**",
				"**/*.generated.go",
				"**/*.pb.go",
			},
			MinSeverity: "low",
			Output:      "console",
		},
		Categories: map[string]CategoryConfig{
			"architecture": {Enabled: true},
			"patterns":     {Enabled: true},
			"typesafety":   {Enabled: true},
			"duplication":  {Enabled: true},
			"deadcode":     {Enabled: true},
			"config":       {Enabled: true},
			"naming":       {Enabled: true},
		},
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// FindConfig searches for .glint.yaml in the directory and its parents
func FindConfig(startDir string) (string, error) {
	dir := startDir
	for {
		configPath := filepath.Join(dir, ".glint.yaml")
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}

		// Also check for glint.yaml (without dot)
		configPath = filepath.Join(dir, "glint.yaml")
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root
			return "", nil
		}
		dir = parent
	}
}

// LoadConfigWithDefaults loads config and merges with defaults
func LoadConfigWithDefaults(projectRoot string) (*Config, error) {
	cfg := DefaultConfig()

	// Try to find and load project config
	configPath, err := FindConfig(projectRoot)
	if err != nil {
		return nil, err
	}

	if configPath != "" {
		projectCfg, err := LoadConfig(configPath)
		if err != nil {
			return nil, err
		}
		cfg = MergeConfigs(cfg, projectCfg)
	}

	return cfg, nil
}

// MergeConfigs merges two configs, with override taking precedence
func MergeConfigs(base, override *Config) *Config {
	result := &Config{
		Version:    override.Version,
		Extends:    override.Extends,
		Settings:   base.Settings,
		Categories: make(map[string]CategoryConfig),
	}

	// Merge settings
	if len(override.Settings.Exclude) > 0 {
		result.Settings.Exclude = override.Settings.Exclude
	}
	if override.Settings.MinSeverity != "" {
		result.Settings.MinSeverity = override.Settings.MinSeverity
	}
	if override.Settings.Output != "" {
		result.Settings.Output = override.Settings.Output
	}

	// Copy base categories
	for name, cat := range base.Categories {
		result.Categories[name] = cat
	}

	// Merge override categories
	for name, cat := range override.Categories {
		if existing, ok := result.Categories[name]; ok {
			// Merge with existing
			existing.Enabled = cat.Enabled
			if cat.SeverityOverride != "" {
				existing.SeverityOverride = cat.SeverityOverride
			}
			if cat.Settings != nil {
				existing.Settings = cat.Settings
			}
			if cat.Rules != nil {
				if existing.Rules == nil {
					existing.Rules = make(map[string]RuleConfig)
				}
				for ruleName, ruleCfg := range cat.Rules {
					existing.Rules[ruleName] = ruleCfg
				}
			}
			result.Categories[name] = existing
		} else {
			result.Categories[name] = cat
		}
	}

	return result
}

// IsCategoryEnabled checks if a category is enabled
func (c *Config) IsCategoryEnabled(name string) bool {
	if cat, ok := c.Categories[name]; ok {
		return cat.Enabled
	}
	return true // Enabled by default
}

// IsRuleEnabled checks if a specific rule is enabled
func (c *Config) IsRuleEnabled(category, rule string) bool {
	if !c.IsCategoryEnabled(category) {
		return false
	}

	cat, ok := c.Categories[category]
	if !ok {
		return true
	}

	if cat.Rules == nil {
		return true
	}

	if ruleCfg, ok := cat.Rules[rule]; ok {
		return ruleCfg.Enabled
	}

	return true
}

// GetRuleExceptions returns exceptions for a specific rule
func (c *Config) GetRuleExceptions(category, rule string) []Exception {
	cat, ok := c.Categories[category]
	if !ok {
		return nil
	}

	if cat.Rules == nil {
		return nil
	}

	if ruleCfg, ok := cat.Rules[rule]; ok {
		return ruleCfg.Exceptions
	}

	return nil
}

// GetMinSeverity returns the minimum severity level
func (c *Config) GetMinSeverity() Severity {
	sev, err := ParseSeverity(c.Settings.MinSeverity)
	if err != nil {
		return SeverityLow
	}
	return sev
}

// ShouldExclude checks if a path should be excluded based on glob patterns
func (c *Config) ShouldExclude(path string) bool {
	for _, pattern := range c.Settings.Exclude {
		matched, err := filepath.Match(pattern, path)
		if err == nil && matched {
			return true
		}
		// Also try matching against the base name
		matched, err = filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}
	}
	return false
}
