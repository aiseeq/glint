package main

import (
	"slices"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// DefaultConfig lives in core, which cannot import the registry, so its
// category list is a literal. This test keeps it honest: every category the
// binary registers must appear there, and it must not name categories that no
// rule has. It lives here, not beside the registry: an external test of
// pkg/rules importing every rule package makes go test compile each of them a
// second time against the test build of pkg/rules.
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
