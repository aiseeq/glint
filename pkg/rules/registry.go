package rules

import (
	"fmt"
	"sort"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
)

// Registry holds all registered rules
type Registry struct {
	rules    map[string]Rule
	byCategory map[string][]Rule
	mu       sync.RWMutex
}

// Global registry instance
var globalRegistry = NewRegistry()

// NewRegistry creates a new rule registry
func NewRegistry() *Registry {
	return &Registry{
		rules:      make(map[string]Rule),
		byCategory: make(map[string][]Rule),
	}
}

// Register adds a rule to the registry
func (r *Registry) Register(rule Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := rule.Name()
	if _, exists := r.rules[name]; exists {
		return fmt.Errorf("rule %q already registered", name)
	}

	r.rules[name] = rule

	category := rule.Category()
	r.byCategory[category] = append(r.byCategory[category], rule)

	return nil
}

// Get returns a rule by name
func (r *Registry) Get(name string) (Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rule, ok := r.rules[name]
	return rule, ok
}

// GetByCategory returns all rules in a category
func (r *Registry) GetByCategory(category string) []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.byCategory[category]
}

// All returns all registered rules
func (r *Registry) All() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rules := make([]Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		rules = append(rules, rule)
	}

	// Sort by category, then by name
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Category() != rules[j].Category() {
			return rules[i].Category() < rules[j].Category()
		}
		return rules[i].Name() < rules[j].Name()
	})

	return rules
}

// Categories returns all category names
func (r *Registry) Categories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	categories := make([]string, 0, len(r.byCategory))
	for cat := range r.byCategory {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	return categories
}

// Count returns the total number of registered rules
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.rules)
}

// CountByCategory returns the number of rules per category
func (r *Registry) CountByCategory() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	counts := make(map[string]int)
	for cat, rules := range r.byCategory {
		counts[cat] = len(rules)
	}
	return counts
}

// GetEnabled returns rules that are enabled according to config
func (r *Registry) GetEnabled(cfg *core.Config) []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var enabled []Rule
	for _, rule := range r.rules {
		if cfg.IsRuleEnabled(rule.Category(), rule.Name()) {
			enabled = append(enabled, rule)
		}
	}

	return enabled
}

// ConfigureAll configures all rules from config
func (r *Registry) ConfigureAll(cfg *core.Config) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, rule := range r.rules {
		cat, ok := cfg.Categories[rule.Category()]
		if !ok {
			continue
		}

		// Apply category-level settings
		if cat.Settings != nil {
			if err := rule.Configure(cat.Settings); err != nil {
				return fmt.Errorf("failed to configure rule %s: %w", rule.Name(), err)
			}
		}

		// Apply rule-level settings
		if cat.Rules != nil {
			if ruleCfg, ok := cat.Rules[rule.Name()]; ok && ruleCfg.Settings != nil {
				if err := rule.Configure(ruleCfg.Settings); err != nil {
					return fmt.Errorf("failed to configure rule %s: %w", rule.Name(), err)
				}
			}
		}
	}

	return nil
}

// Global registry functions

// Register adds a rule to the global registry
func Register(rule Rule) error {
	return globalRegistry.Register(rule)
}

// Get returns a rule from the global registry
func Get(name string) (Rule, bool) {
	return globalRegistry.Get(name)
}

// GetByCategory returns rules by category from the global registry
func GetByCategory(category string) []Rule {
	return globalRegistry.GetByCategory(category)
}

// All returns all rules from the global registry
func All() []Rule {
	return globalRegistry.All()
}

// Categories returns all categories from the global registry
func Categories() []string {
	return globalRegistry.Categories()
}

// Count returns the rule count from the global registry
func Count() int {
	return globalRegistry.Count()
}

// GetEnabled returns enabled rules from the global registry
func GetEnabled(cfg *core.Config) []Rule {
	return globalRegistry.GetEnabled(cfg)
}

// ConfigureAll configures all rules in the global registry
func ConfigureAll(cfg *core.Config) error {
	return globalRegistry.ConfigureAll(cfg)
}

// GlobalRegistry returns the global registry instance
func GlobalRegistry() *Registry {
	return globalRegistry
}
