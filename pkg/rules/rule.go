package rules

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// Rule is the interface that all rules must implement
type Rule interface {
	// Metadata
	Name() string
	Category() string
	Description() string
	DefaultSeverity() core.Severity

	// Configuration
	Configure(settings map[string]any) error

	// Analysis - rules implement the ones they need
	AnalyzeFile(ctx *core.FileContext) []*core.Violation
}

// GoProjectRule is an optional package-level analysis interface for rules that
// need shared typed syntax or SSA. Implementations still satisfy Rule for API
// compatibility, but their AnalyzeFile method is not called by the check flow.
type GoProjectRule interface {
	Rule
	AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error)
	RequiresSSA() bool
}

// TypedGoProjectRule is a file rule that needs Go type information from the
// shared project load while still analyzing files individually. Returning false
// removes the rule from the entire root, including per-file analysis.
type TypedGoProjectRule interface {
	Rule
	NeedsTypedGoProject(files []*core.FileContext) bool
	TypedGoProjectImports() []string
}

// BaseRule provides common functionality for rules
type BaseRule struct {
	name            string
	category        string
	description     string
	defaultSeverity core.Severity
	settings        map[string]any
	settingSpecs    []SettingSpec
}

// SettingSpec describes a configurable rule setting.
type SettingSpec struct {
	Key         string
	Type        string
	Default     string
	Description string
	Example     any // any-in-public-contract: safe
}

type settingDefault interface {
	~string | ~int | ~bool | ~float64 | ~[]string
}

// NewSettingSpec creates a setting declaration and formats its default value.
func NewSettingSpec[T settingDefault](key, settingType string, defaultValue T, description string, example any) SettingSpec {
	return SettingSpec{Key: key, Type: settingType, Default: fmt.Sprint(defaultValue), Description: description, Example: example}
}

// DeclareSettings records the settings supported by this rule.
func (r *BaseRule) DeclareSettings(specs ...SettingSpec) *BaseRule {
	r.settingSpecs = append([]SettingSpec(nil), specs...)
	return r
}

// SettingSpecs returns the settings supported by this rule.
func (r *BaseRule) SettingSpecs() []SettingSpec {
	return append([]SettingSpec(nil), r.settingSpecs...)
}

// NewBaseRule creates a new base rule
func NewBaseRule(name, category, description string, severity core.Severity) *BaseRule {
	r := &BaseRule{
		name:            name,
		category:        category,
		description:     description,
		defaultSeverity: severity,
		settings:        make(map[string]any),
	}
	return r
}

// Name returns the rule name
func (r *BaseRule) Name() string {
	return r.name
}

// Category returns the rule category
func (r *BaseRule) Category() string {
	return r.category
}

// Description returns the rule description
func (r *BaseRule) Description() string {
	return r.description
}

// DefaultSeverity returns the default severity
func (r *BaseRule) DefaultSeverity() core.Severity {
	return r.defaultSeverity
}

// Configure sets rule settings
func (r *BaseRule) Configure(settings map[string]any) error {
	r.settings = settings
	return nil
}

// GetSetting retrieves a setting value
func (r *BaseRule) GetSetting(key string) (any, bool) {
	val, ok := r.settings[key]
	return val, ok
}

// GetStringSetting retrieves a string setting
func (r *BaseRule) GetStringSetting(key, defaultVal string) string {
	if val, ok := r.settings[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return defaultVal
}

// GetStringListSetting retrieves a list of non-empty strings. The bool reports
// whether the setting was present; malformed values return an error.
func (r *BaseRule) GetStringListSetting(key string) ([]string, bool, error) {
	value, exists := r.GetSetting(key)
	if !exists {
		return nil, false, nil
	}
	values, err := StringList(value)
	if err != nil {
		setting := fmt.Sprintf("configure %s: %s", r.Name(), key)
		var itemErr *StringListItemError
		if errors.As(err, &itemErr) {
			return nil, true, fmt.Errorf("%s[%d]: %w", setting, itemErr.Index, itemErr.Cause)
		}
		return nil, true, fmt.Errorf("%s: %w", setting, err)
	}
	return values, true, nil
}

// StringListItemError reports an invalid list element and its zero-based index.
type StringListItemError struct {
	Index int
	Cause error
}

func (e *StringListItemError) Error() string {
	return fmt.Sprintf("item %d: %v", e.Index, e.Cause)
}

func (e *StringListItemError) Unwrap() error { return e.Cause }

// StringList parses a list containing only non-empty strings.
func StringList(value any) ([]string, error) {
	var items []any
	switch list := value.(type) {
	case []any:
		items = list
	case []string:
		for _, item := range list {
			items = append(items, item)
		}
	default:
		return nil, fmt.Errorf("must be a list, got %T", value)
	}
	result := make([]string, 0, len(items))
	for i, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, &StringListItemError{Index: i, Cause: fmt.Errorf("must be a non-empty string, got %T", item)}
		}
		if strings.TrimSpace(text) == "" {
			return nil, &StringListItemError{Index: i, Cause: fmt.Errorf("must be a non-empty string")}
		}
		result = append(result, text)
	}
	return result, nil
}

// GetIntSetting retrieves an int setting
func (r *BaseRule) GetIntSetting(key string, defaultVal int) int {
	if val, ok := r.settings[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultVal
}

// GetBoolSetting retrieves a bool setting
func (r *BaseRule) GetBoolSetting(key string, defaultVal bool) bool {
	if val, ok := r.settings[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultVal
}

// GetFloat64Setting retrieves a float64 setting
func (r *BaseRule) GetFloat64Setting(key string, defaultVal float64) float64 {
	if val, ok := r.settings[key]; ok {
		switch v := val.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		}
	}
	return defaultVal
}

// CreateViolation creates a new violation for this rule
func (r *BaseRule) CreateViolation(file string, line int, message string) *core.Violation {
	return core.NewViolation(r.name, r.category, file, line, r.defaultSeverity, message)
}

// RuleInfo contains metadata about a rule for display purposes. Auto-fix
// availability is not part of it: fixers live in pkg/fix (fix.DefaultRegistry),
// which the display layer consults directly.
type RuleInfo struct {
	Name        string
	Category    string
	Description string
	Severity    core.Severity
	Settings    []SettingSpec
}

// GetRuleInfo extracts info from a rule
func GetRuleInfo(r Rule) RuleInfo {
	return RuleInfo{
		Name:        r.Name(),
		Category:    r.Category(),
		Description: r.Description(),
		Severity:    r.DefaultSeverity(),
		Settings:    settingSpecs(r),
	}
}

func settingSpecs(r Rule) []SettingSpec {
	if provider, ok := r.(interface{ SettingSpecs() []SettingSpec }); ok {
		return provider.SettingSpecs()
	}
	return nil
}

// StatefulRule is an optional interface for rules that accumulate state across
// files (cross-file analysis). The check flow resets them before analyzing a
// project root, so that findings never depend on a previously analyzed root.
type StatefulRule interface {
	Rule
	ResetState()
}

// ResetState clears the accumulated state of every stateful rule in the list.
func ResetState(list []Rule) {
	for _, rule := range list {
		if stateful, ok := rule.(StatefulRule); ok {
			stateful.ResetState()
		}
	}
}

// SuppressionExempt is an optional interface for rules whose findings must
// not be silenced by inline comments (nolint:<rule> / <rule>: safe). Policy
// rules that forbid a pattern unconditionally implement it and return true.
type SuppressionExempt interface {
	SuppressionExempt() bool
}

// HonorsSuppression reports whether inline suppression comments apply to the
// given rule. All rules honor suppression unless they opt out explicitly via
// the SuppressionExempt interface.
func HonorsSuppression(r Rule) bool {
	if se, ok := r.(SuppressionExempt); ok && se.SuppressionExempt() {
		return false
	}
	return true
}

// ReadsOtherFiles is an optional interface for file rules whose findings
// depend on more than the analyzed file — links checked against the disk, for
// instance. Their findings are never reused from the result cache.
type ReadsOtherFiles interface {
	Rule
	ReadsOtherFiles() bool
}

// ProjectFilesRule is an optional interface for file rules that compare a
// file with the rest of the project: before it analyzes a root, the check
// flow hands them every file of the root, also when the run covers only some
// of them; the files of the run are the same contexts the analysis then
// passes one by one. They are stateful: ResetState drops the files.
type ProjectFilesRule interface {
	StatefulRule
	UseProjectFiles(files []*core.FileContext)
}

// CachedProjectFilesRule lets a project-files rule persist its root index with
// the cached project findings.
type CachedProjectFilesRule interface {
	ProjectFilesRule
	CacheProjectFiles() ([]byte, error)
	RestoreProjectFiles(data []byte) error
}

// ExternalToolRule is a rule that runs a program glint does not ship
// (shellcheck, tsc). Before a root's files are analyzed, the check flow
// hands it the files: it returns an error when they need the program and
// the machine does not have it, and the run fails with that error instead
// of passing the files unchecked.
type ExternalToolRule interface {
	Rule
	CheckTools(files []*core.FileContext) error
}

// ExcludedInstructionReader is a file rule that measures the Claude Code
// instruction files even where the configuration's exclude patterns leave
// them out: an exclusion of *.md meant for documentation must not hide a
// CLAUDE.md over its limit. No other rule sees those files.
type ExcludedInstructionReader interface {
	Rule
	ReadsExcludedInstructions()
}

// ReadsExcludedInstructions reports whether the rule measures the
// instruction files the exclude patterns leave out.
func ReadsExcludedInstructions(r Rule) bool {
	_, ok := r.(ExcludedInstructionReader)
	return ok
}

// FileLocal reports whether a rule's findings on a file depend only on that
// file — its path and content — and the configuration, so that they can be
// reused while the file is unchanged. Project rules see the whole module,
// stateful rules the files analyzed before, and rules that read other files
// the disk; none of them is file-local.
func FileLocal(r Rule) bool {
	if _, ok := r.(GoProjectRule); ok {
		return false
	}
	if _, ok := r.(StatefulRule); ok {
		return false
	}
	if reader, ok := r.(ReadsOtherFiles); ok && reader.ReadsOtherFiles() {
		return false
	}
	return true
}
