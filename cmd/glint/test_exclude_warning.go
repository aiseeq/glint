package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// testRuleName matches the rules about Go tests by name: test-*, *-test-*,
// skipped-test; tautological-assertion reads tests only too.
var testRuleName = regexp.MustCompile(`(?:^|-)tests?(?:-|$)|^tautological-assertion$`)

// excludedTestRulesWarning returns a warning when settings.exclude drops
// every Go test file while rules about tests are enabled: those rules then
// see no file and report nothing, and the clean run reads as clean tests.
// It returns "" when nothing is lost.
func excludedTestRulesWarning(cfg *core.Config, enabled []rules.Rule) string {
	if !cfg.ShouldExclude("x_test.go") || !cfg.ShouldExclude("internal/pkg/x_test.go") {
		return ""
	}
	var names []string
	for _, rule := range enabled {
		if testRuleName.MatchString(rule.Name()) {
			names = append(names, rule.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	listed := strings.Join(names, ", ")
	if len(names) > 5 {
		listed = strings.Join(names[:5], ", ") + ", ..."
	}
	return fmt.Sprintf("warning: settings.exclude drops every *_test.go, so %d rules about tests see no file (%s); except the test files per rule instead",
		len(names), listed)
}
