package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// A config that excludes every Go test file switches the test rules off
// without a word; excluding one directory of tests does not.
func TestExcludedTestRulesWarning(t *testing.T) {
	enabled := []rules.Rule{}
	for _, name := range []string{"test-schema-mutation-without-cleanup", "skipped-test", "tautological-assertion", "error-wrap"} {
		rule, ok := rules.Get(name)
		assert.True(t, ok, name)
		enabled = append(enabled, rule)
	}
	cfg := core.DefaultConfig()
	cfg.Settings.Exclude = []string{"vendor/*", "*_test.go"}
	warning := excludedTestRulesWarning(cfg, enabled)
	assert.Contains(t, warning, "3 rules about tests")
	assert.Contains(t, warning, "skipped-test")

	cfg.Settings.Exclude = []string{"legacy/**/*_test.go"}
	assert.Empty(t, excludedTestRulesWarning(cfg, enabled))
	cfg.Settings.Exclude = []string{"*_test.go"}
	assert.Empty(t, excludedTestRulesWarning(cfg, enabled[3:]))
}
