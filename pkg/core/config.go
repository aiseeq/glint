package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
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
	SkipDirs    []string `yaml:"skip_dirs,omitempty"`
	MinSeverity string   `yaml:"min_severity"`
	Output      string   `yaml:"output"`
}

// DefaultSkipDirs are the directory names the walker never descends into
// unless settings.skip_dirs says otherwise.
var DefaultSkipDirs = []string{
	".git", ".svn", ".hg",
	".idea", ".vscode",
	"node_modules", "vendor",
	".next", "out", "dist", "build", "bin",
}

// SkipDirs returns the configured directory names to skip, or the defaults.
func (c *Config) SkipDirs() []string {
	if len(c.Settings.SkipDirs) > 0 {
		return c.Settings.SkipDirs
	}
	return DefaultSkipDirs
}

// CategoryConfig contains category-specific settings
type CategoryConfig struct {
	Enabled          bool   `yaml:"enabled"`
	SeverityOverride string `yaml:"severity_override,omitempty"`
	// Rule settings are user-authored YAML whose shape each rule defines; a
	// typed struct here would have to know all of them.
	// any-in-public-contract: safe
	Settings map[string]any        `yaml:"settings,omitempty"`
	Rules    map[string]RuleConfig `yaml:"rules,omitempty"`
}

// UnmarshalYAML defaults Enabled to true. Without it, naming a category in
// order to configure its rules would switch the whole category off, because
// the zero value of a bool is false.
func (c *CategoryConfig) UnmarshalYAML(value *yaml.Node) error {
	type plainCategory CategoryConfig
	decoded := plainCategory{Enabled: true}
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	*c = CategoryConfig(decoded)
	return nil
}

// RuleConfig contains rule-specific settings
type RuleConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Severity string `yaml:"severity,omitempty"`
	// See CategoryConfig.Settings.
	// any-in-public-contract: safe
	Settings   map[string]any `yaml:"settings,omitempty"`
	Exceptions []Exception    `yaml:"exceptions,omitempty"`
}

// UnmarshalYAML defaults Enabled to true, for the same reason as
// CategoryConfig.UnmarshalYAML: setting a rule's severity, settings or
// exceptions must not disable it as a side effect.
func (r *RuleConfig) UnmarshalYAML(value *yaml.Node) error {
	type plainRule RuleConfig
	decoded := plainRule{Enabled: true}
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	*r = RuleConfig(decoded)
	return nil
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
		// Must stay in sync with the registered rule categories; a test in
		// pkg/rules asserts the two sets match (core cannot import rules).
		Categories: map[string]CategoryConfig{
			"architecture": {Enabled: true},
			"patterns": {Enabled: true, Rules: map[string]RuleConfig{
				"deprecated-nginx-http2-listen": {Enabled: false},
			}},
			"typesafety":    {Enabled: true},
			"duplication":   {Enabled: true},
			"deadcode":      {Enabled: true},
			"security":      {Enabled: true},
			"documentation": {Enabled: true},
			"naming":        {Enabled: true},
		},
	}
}

// maxConfigChain bounds how many `extends` hops a configuration may use.
const maxConfigChain = 16

// SupportedConfigVersion is the schema version this glint understands. A
// config written for a different one is rejected rather than half-applied.
const SupportedConfigVersion = 1

// LoadConfig loads a configuration file, resolving its `extends` chain.
func LoadConfig(path string) (*Config, error) {
	cfg, err := loadConfigChain(path, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	return cfg, nil
}

// loadConfigChain reads one config file and merges it on top of the config it
// extends. `extends` is resolved relative to the directory of the file that
// declares it.
func loadConfigChain(path string, visiting map[string]bool) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path %q: %w", path, err)
	}
	if visiting[absPath] {
		return nil, fmt.Errorf("config extends cycle at %q", absPath)
	}
	if len(visiting) >= maxConfigChain {
		return nil, fmt.Errorf("config extends chain longer than %d files at %q", maxConfigChain, absPath)
	}
	visiting[absPath] = true
	defer delete(visiting, absPath)

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if cfg.Extends == "" {
		return &cfg, nil
	}

	basePath := cfg.Extends
	if !filepath.IsAbs(basePath) {
		basePath = filepath.Join(filepath.Dir(absPath), basePath)
	}
	base, err := loadConfigChain(basePath, visiting)
	if err != nil {
		return nil, fmt.Errorf("config %q extends %q: %w", absPath, cfg.Extends, err)
	}
	return MergeConfigs(base, &cfg), nil
}

// Validate reports configuration values that glint would otherwise have to
// guess about: unparseable severities anywhere in the file.
func (c *Config) Validate() error {
	// Version 0 means the key is absent, which older configs rely on.
	if c.Version != 0 && c.Version != SupportedConfigVersion {
		return fmt.Errorf("version: unsupported config version %d (this glint understands version %d)",
			c.Version, SupportedConfigVersion)
	}
	if c.Settings.MinSeverity != "" {
		if _, err := ParseSeverity(c.Settings.MinSeverity); err != nil {
			return fmt.Errorf("settings.min_severity: %w", err)
		}
	}
	for i, pattern := range c.Settings.Exclude {
		if !doublestar.ValidatePattern(pattern) {
			return fmt.Errorf("settings.exclude[%d]: malformed glob pattern %q", i, pattern)
		}
	}
	for name, cat := range c.Categories {
		if cat.SeverityOverride != "" {
			if _, err := ParseSeverity(cat.SeverityOverride); err != nil {
				return fmt.Errorf("categories.%s.severity_override: %w", name, err)
			}
		}
		for ruleName, ruleCfg := range cat.Rules {
			if ruleCfg.Severity != "" {
				if _, err := ParseSeverity(ruleCfg.Severity); err != nil {
					return fmt.Errorf("categories.%s.rules.%s.severity: %w", name, ruleName, err)
				}
			}
			for i, exc := range ruleCfg.Exceptions {
				if exc.Files != "" && !doublestar.ValidatePattern(exc.Files) {
					return fmt.Errorf("categories.%s.rules.%s.exceptions[%d].files: malformed glob pattern %q",
						name, ruleName, i, exc.Files)
				}
			}
		}
	}
	return nil
}

// SeverityOverrideFor returns the severity configured for a rule, if any. A
// rule-level `severity` wins over its category's `severity_override`; when
// neither is set the rule keeps the severity it reports itself.
func (c *Config) SeverityOverrideFor(category, rule string) (Severity, bool, error) {
	cat, ok := c.Categories[category]
	if !ok {
		return SeverityLow, false, nil
	}
	if ruleCfg, ok := cat.Rules[rule]; ok && ruleCfg.Severity != "" {
		severity, err := ParseSeverity(ruleCfg.Severity)
		if err != nil {
			return SeverityLow, false, fmt.Errorf("categories.%s.rules.%s.severity: %w", category, rule, err)
		}
		return severity, true, nil
	}
	if cat.SeverityOverride != "" {
		severity, err := ParseSeverity(cat.SeverityOverride)
		if err != nil {
			return SeverityLow, false, fmt.Errorf("categories.%s.severity_override: %w", category, err)
		}
		return severity, true, nil
	}
	return SeverityLow, false, nil
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
	if len(override.Settings.SkipDirs) > 0 {
		result.Settings.SkipDirs = override.Settings.SkipDirs
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
				// Clone before writing: the map header was copied from base,
				// so writing through it would mutate the base config.
				merged := make(map[string]RuleConfig, len(existing.Rules)+len(cat.Rules))
				for ruleName, ruleCfg := range existing.Rules {
					merged[ruleName] = ruleCfg
				}
				for ruleName, ruleCfg := range cat.Rules {
					merged[ruleName] = mergeRuleConfig(merged[ruleName], ruleCfg)
				}
				existing.Rules = merged
			}
			result.Categories[name] = existing
		} else {
			result.Categories[name] = cat
		}
	}

	return result
}

// mergeRuleConfig overlays an override rule config onto the base one field by
// field. Replacing the whole struct made a severity-only override erase the
// base's settings and exceptions.
func mergeRuleConfig(base, override RuleConfig) RuleConfig {
	merged := base
	// Enabled has no "unset" state: UnmarshalYAML defaults it to true, so the
	// override's value is always explicit.
	merged.Enabled = override.Enabled
	if override.Severity != "" {
		merged.Severity = override.Severity
	}
	if override.Settings != nil {
		merged.Settings = override.Settings
	}
	if override.Exceptions != nil {
		merged.Exceptions = override.Exceptions
	}
	return merged
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

// GetMinSeverity returns the configured minimum severity level.
func (c *Config) GetMinSeverity() (Severity, error) {
	sev, err := ParseSeverity(c.Settings.MinSeverity)
	if err != nil {
		return SeverityLow, fmt.Errorf("parse minimum severity %q: %w", c.Settings.MinSeverity, err)
	}
	return sev, nil
}

// IsFileExcepted checks if a file should be excepted from a specific rule based on YAML exceptions.
// Supports ** glob patterns by converting to substring match on path segments.
func (c *Config) IsFileExcepted(category, rule, filePath string) bool {
	exceptions := c.GetRuleExceptions(category, rule)
	for _, exc := range exceptions {
		if !exc.isFileOnly() {
			continue
		}
		if exc.Files != "" && matchGlobPattern(exc.Files, filePath) {
			return true
		}
		if exc.File != "" && (exc.File == filePath || exc.File == filepath.Base(filePath)) {
			return true
		}
	}
	return false
}

// IsViolationExcepted checks whether a specific violation matches a rule exception.
func (c *Config) IsViolationExcepted(category, rule, filePath string, violation *Violation) bool {
	exceptions := c.GetRuleExceptions(category, rule)
	for _, exc := range exceptions {
		if exc.matchesViolation(filePath, violation) {
			return true
		}
	}
	return false
}

func (e Exception) isFileOnly() bool {
	return (e.File != "" || e.Files != "") && e.Line == 0 && e.Pattern == "" && e.Function == ""
}

func (e Exception) matchesViolation(filePath string, violation *Violation) bool {
	if violation == nil {
		return false
	}
	if e.File == "" && e.Files == "" && e.Line == 0 && e.Pattern == "" && e.Function == "" {
		return false
	}
	if e.File != "" && e.File != filePath && e.File != filepath.Base(filePath) {
		return false
	}
	if e.Files != "" && !matchGlobPattern(e.Files, filePath) {
		return false
	}
	if e.Line > 0 && e.Line != violation.Line {
		return false
	}
	if e.Pattern != "" && !strings.Contains(violation.Code, e.Pattern) && !strings.Contains(violation.Message, e.Pattern) {
		return false
	}
	if e.Function != "" && !exceptionFunctionMatches(e.Function, violation) {
		return false
	}
	return true
}

func exceptionFunctionMatches(name string, violation *Violation) bool {
	if violation.Context == nil {
		return false
	}
	for _, key := range []string{"function", "func", "method"} {
		value, ok := violation.Context[key]
		if !ok {
			continue
		}
		if text, ok := value.(string); ok && text == name {
			return true
		}
	}
	return false
}

// matchGlobPattern matches a project-relative path against a glob pattern.
// `*` matches within one path segment, `**` spans segments; a pattern without
// a separator also matches the file's base name, so that "*_test.go" keeps
// covering nested test files. This is the single glob implementation — path
// exclusion and rule exceptions must both go through it.
func matchGlobPattern(pattern, path string) bool {
	path = filepath.ToSlash(path)
	if globMatches(pattern, path) {
		return true
	}
	// A directory pattern also covers the directory itself: "vendor/**" is what
	// users write, but "vendor" alone reads as the whole tree too.
	if strings.HasSuffix(pattern, "/**") && globMatches(strings.TrimSuffix(pattern, "/**"), path) {
		return true
	}
	return globMatches(pattern, filepath.Base(path))
}

// globMatches reports whether a well-formed pattern matches. Malformed
// patterns never reach here: Config.Validate rejects the configuration that
// declares them.
func globMatches(pattern, path string) bool {
	matched, err := doublestar.Match(pattern, path)
	return err == nil && matched
}

// ShouldExclude checks if a path should be excluded based on glob patterns
func (c *Config) ShouldExclude(path string) bool {
	for _, pattern := range c.Settings.Exclude {
		if matchGlobPattern(pattern, path) {
			return true
		}
	}
	return false
}
