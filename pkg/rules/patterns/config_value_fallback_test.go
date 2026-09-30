package patterns

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

const configFallbackConfigPackage = `package config

type Report struct {
	WindowDays int     ` + "`yaml:\"window_days\" default:\"14\"`" + `
	ThresholdPercent    float64 ` + "`yaml:\"threshold_percent\"`" + `
	Region            string  ` + "`env:\"REGION\"`" + `
}

type Config struct {
	Report Report ` + "`yaml:\"yield\"`" + `
}

// ApplyDefaults is where the configuration's defaults belong.
func (c *Config) ApplyDefaults() {
	if c.Report.WindowDays == 0 {
		c.Report.WindowDays = 14
	}
}
`

func runConfigValueFallbackRule(t *testing.T, service string) []*core.Violation {
	t.Helper()
	project := decimalProject(t, map[string]string{
		"config/config.go":   configFallbackConfigPackage,
		"service/service.go": service,
	})
	violations, err := NewConfigValueFallbackRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	return violations
}

func TestConfigValueFallback_VariableFromConfig(t *testing.T) {
	violations := runConfigValueFallbackRule(t, `package service

import (
	"github.com/shopspring/decimal"

	"example.com/rulestest/config"
)

type Service struct {
	days      int
	threshold decimal.Decimal
}

func New(cfg *config.Config) *Service {
	days := cfg.Report.WindowDays
	if days <= 0 {
		days = 14
	}
	threshold := decimal.NewFromFloat(cfg.Report.ThresholdPercent)
	if threshold.IsZero() {
		threshold = decimal.NewFromFloat(-1.0)
	}
	return &Service{days: days, threshold: threshold}
}
`)

	require.Len(t, violations, 2)
	assert.Equal(t, 16, violations[0].Line)
	assert.Contains(t, violations[0].Message, "cfg.Report.WindowDays")
	assert.Contains(t, violations[0].Message, `default:"14"`)
	assert.Contains(t, violations[1].Message, "decimal.NewFromFloat(-1.0)")
}

func TestConfigValueFallback_FieldAssignedDirectly(t *testing.T) {
	violations := runConfigValueFallbackRule(t, `package service

import "example.com/rulestest/config"

func Region(cfg *config.Config) string {
	if cfg.Report.Region == "" {
		cfg.Report.Region = "eu"
	}
	return cfg.Report.Region
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, `"eu"`)
}

// A parameter default, a fallback that does more than assign a constant, an
// else branch, a payload field (json) and the configuration package's own
// defaults are not reported.
func TestConfigValueFallback_NotReported(t *testing.T) {
	violations := runConfigValueFallbackRule(t, `package service

import (
	"errors"

	"example.com/rulestest/config"
)

type Page struct {
	Limit int `+"`json:\"limit\"`"+`
}

func List(limit int, page Page) int {
	if limit <= 0 {
		limit = 50
	}
	if page.Limit == 0 {
		page.Limit = 20
	}
	return limit + page.Limit
}

func Days(cfg *config.Config, other int) (int, error) {
	days := cfg.Report.WindowDays
	if days <= 0 {
		return 0, errors.New("window_days must be positive")
	}
	if days == 0 {
		days = other
	}
	if days < 0 {
		days = 1
	} else {
		days++
	}
	return days, nil
}
`)

	assert.Empty(t, violations)
}

// A getter that returns a literal when the field is unset is the same second
// default in another shape: nothing writes the default into the field, the
// loaded configuration stays empty and the code runs on a value the
// configuration does not know. That holds in the configuration's own package
// too, unlike an applyDefaults that fills the field.
func TestConfigValueFallback_GetterReturnsLiteral(t *testing.T) {
	project := decimalProject(t, map[string]string{
		"config/config.go": configFallbackConfigPackage,
		"config/getters.go": `package config

func (c *Config) DefaultRegion() string {
	if c.Report.Region != "" {
		return c.Report.Region
	}
	return "eu"
}

func (c *Config) WindowDays() int {
	if c.Report.WindowDays <= 0 {
		return 14
	}
	return c.Report.WindowDays
}
`,
		"service/service.go": `package service

import (
	"github.com/shopspring/decimal"

	"example.com/rulestest/config"
)

func Region(cfg *config.Config) (string, error) {
	region := cfg.Report.Region
	if region == "" {
		return "eu", nil
	}
	return region, nil
}

func Days(cfg *config.Config) int {
	if days := cfg.Report.WindowDays; days > 0 {
		return days
	} else {
		return 7
	}
}

func Threshold(cfg *config.Config) decimal.Decimal {
	threshold := decimal.NewFromFloat(cfg.Report.ThresholdPercent)
	if !threshold.IsZero() {
		return threshold
	}
	return decimal.NewFromFloat(-1.0)
}

func Mirrored(cfg *config.Config) int {
	if 0 < cfg.Report.WindowDays {
		return cfg.Report.WindowDays
	}
	return 21
}
`,
	})
	violations, err := NewConfigValueFallbackRule().AnalyzeGoProject(project)
	require.NoError(t, err)

	lines := make(map[string][]int)
	for _, v := range violations {
		lines[filepath.Base(v.File)] = append(lines[filepath.Base(v.File)], v.Line)
		assert.Contains(t, v.Message, "falls back to")
	}
	assert.Equal(t, []int{4, 11}, lines["getters.go"], "getters in the configuration package are reported")
	assert.Equal(t, []int{11, 18, 27, 34}, lines["service.go"])
	require.NotEmpty(t, violations)
	for _, v := range violations {
		if filepath.Base(v.File) == "getters.go" && v.Line == 4 {
			assert.Contains(t, v.Message, `c.Report.Region falls back to "eu"`)
		}
		if filepath.Base(v.File) == "getters.go" && v.Line == 11 {
			assert.Contains(t, v.Message, `(the field already declares default:"14")`)
		}
	}
}

// Returning a zero value or an error is validation, not a default; a returned
// literal of another type than the value is not its replacement; a parameter
// default is not configuration; the return after the if must be the very next
// statement and return a constant.
func TestConfigValueFallback_ReturnFormNotReported(t *testing.T) {
	violations := runConfigValueFallbackRule(t, `package service

import (
	"errors"
	"fmt"

	"example.com/rulestest/config"
)

var errNoRegion = errors.New("no region")

func Region(cfg *config.Config) (string, error) {
	region := cfg.Report.Region
	if region == "" {
		return "", fmt.Errorf("region is required")
	}
	return region, nil
}

func RegionErr(cfg *config.Config) (string, error) {
	if cfg.Report.Region == "" {
		return "eu", errNoRegion
	}
	return cfg.Report.Region, nil
}

func Score(cfg *config.Config) int {
	if cfg.Report.Region == "" {
		return 3
	}
	return 1
}

func Days(cfg *config.Config, other int) int {
	if cfg.Report.WindowDays > 0 {
		return cfg.Report.WindowDays
	}
	return other
}

func Zero(cfg *config.Config) string {
	if cfg.Report.Region != "" {
		return cfg.Report.Region
	}
	return ""
}

func Later(cfg *config.Config) int {
	if cfg.Report.WindowDays > 0 {
		return cfg.Report.WindowDays
	}
	fmt.Println("unset")
	return 14
}

func Limit(n int) int {
	if n <= 0 {
		return 50
	}
	return n
}
`)

	assert.Empty(t, violations)
}

// When the program tells an unset value apart elsewhere — a validation that
// rejects a usage text without arguments — the default cannot be written into
// the field without losing that state, and the getter is where it belongs.
func TestConfigValueFallback_GetterOfFieldWhoseUnsetStateMatters(t *testing.T) {
	project := decimalProject(t, map[string]string{
		"tasks/tasks.go": `package tasks

import "errors"

type Task struct {
	Usage   string ` + "`yaml:\"usage\"`" + `
	Summary string ` + "`yaml:\"summary\"`" + `
	Args    bool
}

func (t *Task) Validate() error {
	if t.Usage != "" && !t.Args {
		return errors.New("usage needs args")
	}
	return nil
}

func (t *Task) UsageText() string {
	if t.Usage != "" {
		return t.Usage
	}
	return "args..."
}

func (t *Task) SummaryText() string {
	if t.Summary != "" {
		return t.Summary
	}
	return "no summary"
}
`,
	})
	violations, err := NewConfigValueFallbackRule().AnalyzeGoProject(project)
	require.NoError(t, err)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "t.Summary falls back to")
}
