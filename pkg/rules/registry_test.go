package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	assert.NotNil(t, r)
	assert.Equal(t, 0, r.Count())
}

func TestRegistryRegister(t *testing.T) {
	r := NewRegistry()

	rule := NewMockRule("test-rule")
	err := r.Register(rule)
	require.NoError(t, err)

	assert.Equal(t, 1, r.Count())
}

func TestRegistryRegisterDuplicate(t *testing.T) {
	r := NewRegistry()

	rule1 := NewMockRule("same-name")
	rule2 := NewMockRule("same-name")

	err := r.Register(rule1)
	require.NoError(t, err)

	err = r.Register(rule2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestRegistryGet(t *testing.T) {
	r := NewRegistry()

	rule := NewMockRule("my-rule")
	r.Register(rule)

	found, ok := r.Get("my-rule")
	assert.True(t, ok)
	assert.Equal(t, "my-rule", found.Name())

	_, ok = r.Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistryGetByCategory(t *testing.T) {
	r := NewRegistry()

	// Create rules with different categories
	rule1 := &MockRule{BaseRule: NewBaseRule("rule1", "category-a", "desc", core.SeverityLow)}
	rule2 := &MockRule{BaseRule: NewBaseRule("rule2", "category-a", "desc", core.SeverityLow)}
	rule3 := &MockRule{BaseRule: NewBaseRule("rule3", "category-b", "desc", core.SeverityLow)}

	r.Register(rule1)
	r.Register(rule2)
	r.Register(rule3)

	catA := r.GetByCategory("category-a")
	assert.Len(t, catA, 2)

	catB := r.GetByCategory("category-b")
	assert.Len(t, catB, 1)

	catC := r.GetByCategory("nonexistent")
	assert.Len(t, catC, 0)
}

func TestRegistryAll(t *testing.T) {
	r := NewRegistry()

	r.Register(&MockRule{BaseRule: NewBaseRule("rule-b", "cat-b", "desc", core.SeverityLow)})
	r.Register(&MockRule{BaseRule: NewBaseRule("rule-a", "cat-a", "desc", core.SeverityLow)})
	r.Register(&MockRule{BaseRule: NewBaseRule("rule-c", "cat-a", "desc", core.SeverityLow)})

	all := r.All()
	assert.Len(t, all, 3)

	// Should be sorted by category, then name
	assert.Equal(t, "rule-a", all[0].Name())
	assert.Equal(t, "rule-c", all[1].Name())
	assert.Equal(t, "rule-b", all[2].Name())
}

func TestRegistryCategories(t *testing.T) {
	r := NewRegistry()

	r.Register(&MockRule{BaseRule: NewBaseRule("r1", "zebra", "desc", core.SeverityLow)})
	r.Register(&MockRule{BaseRule: NewBaseRule("r2", "alpha", "desc", core.SeverityLow)})
	r.Register(&MockRule{BaseRule: NewBaseRule("r3", "beta", "desc", core.SeverityLow)})

	cats := r.Categories()
	assert.Equal(t, []string{"alpha", "beta", "zebra"}, cats)
}

func TestRegistryCountByCategory(t *testing.T) {
	r := NewRegistry()

	r.Register(&MockRule{BaseRule: NewBaseRule("r1", "cat-a", "desc", core.SeverityLow)})
	r.Register(&MockRule{BaseRule: NewBaseRule("r2", "cat-a", "desc", core.SeverityLow)})
	r.Register(&MockRule{BaseRule: NewBaseRule("r3", "cat-b", "desc", core.SeverityLow)})

	counts := r.CountByCategory()
	assert.Equal(t, 2, counts["cat-a"])
	assert.Equal(t, 1, counts["cat-b"])
}

func TestRegistryGetEnabled(t *testing.T) {
	r := NewRegistry()

	r.Register(&MockRule{BaseRule: NewBaseRule("r1", "enabled-cat", "desc", core.SeverityLow)})
	r.Register(&MockRule{BaseRule: NewBaseRule("r2", "disabled-cat", "desc", core.SeverityLow)})
	r.Register(&MockRule{BaseRule: NewBaseRule("r3", "enabled-cat", "desc", core.SeverityLow)})

	cfg := core.DefaultConfig()
	cfg.Categories["enabled-cat"] = core.CategoryConfig{Enabled: true}
	cfg.Categories["disabled-cat"] = core.CategoryConfig{Enabled: false}

	enabled := r.GetEnabled(cfg)
	assert.Len(t, enabled, 2)

	for _, rule := range enabled {
		assert.Equal(t, "enabled-cat", rule.Category())
	}
}

func TestRegistryConfigureAll(t *testing.T) {
	r := NewRegistry()

	rule := NewMockRule("configurable-rule")
	r.Register(rule)

	cfg := core.DefaultConfig()
	cfg.Categories["mock"] = core.CategoryConfig{
		Enabled: true,
		Settings: map[string]interface{}{
			"threshold": 100,
		},
	}

	err := r.ConfigureAll(cfg)
	require.NoError(t, err)

	// Rule should have received settings
	assert.Equal(t, 100, rule.GetIntSetting("threshold", 0))
}

func TestGlobalRegistry(t *testing.T) {
	// Note: These test the global functions but may interfere with other tests
	// In production, consider using a fresh registry for tests

	// Just verify the global functions exist and return reasonable values
	count := Count()
	assert.GreaterOrEqual(t, count, 0)

	all := All()
	assert.NotNil(t, all)

	cats := Categories()
	assert.NotNil(t, cats)

	reg := GlobalRegistry()
	assert.NotNil(t, reg)
}
