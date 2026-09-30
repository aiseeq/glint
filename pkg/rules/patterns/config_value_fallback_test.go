package patterns

import (
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
