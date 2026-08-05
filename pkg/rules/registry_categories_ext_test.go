package rules_test

import (
	"slices"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"

	// Rule packages - imported for init() registration
	_ "github.com/aiseeq/glint/pkg/rules/architecture"
	_ "github.com/aiseeq/glint/pkg/rules/deadcode"
	_ "github.com/aiseeq/glint/pkg/rules/doccheck"
	_ "github.com/aiseeq/glint/pkg/rules/duplication"
	_ "github.com/aiseeq/glint/pkg/rules/naming"
	_ "github.com/aiseeq/glint/pkg/rules/patterns"
	_ "github.com/aiseeq/glint/pkg/rules/security"
	_ "github.com/aiseeq/glint/pkg/rules/typesafety"
)

// DefaultConfig lives in core, which cannot import the registry, so its
// category list is a literal. This test keeps it honest: every registered
// category must appear there, and it must not name categories that no rule has.
func TestDefaultConfigCategoriesMatchRegistry(t *testing.T) {
	registered := rules.Categories()
	configured := core.DefaultConfig().Categories

	for _, category := range registered {
		if _, ok := configured[category]; !ok {
			t.Errorf("registered category %q is missing from core.DefaultConfig()", category)
		}
	}
	for category := range configured {
		if !slices.Contains(registered, category) {
			t.Errorf("core.DefaultConfig() names category %q, but no rule registers it", category)
		}
	}
}
