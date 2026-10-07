package rules

import (
	"fmt"
	"strings"
)

// NameSetSetting reads a list-of-names setting of a rule's configuration:
// present reports whether the key is set at all; a value that is not a list
// of non-empty strings is an error naming the rule and the key.
func NameSetSetting(settings map[string]any, ruleName, key string) (names map[string]bool, present bool, err error) {
	raw, ok := settings[key]
	if !ok {
		return nil, false, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, true, fmt.Errorf("configure %s: %s must be a list, got %T", ruleName, key, raw)
	}
	names = make(map[string]bool, len(list))
	for i, item := range list {
		name, ok := item.(string)
		if !ok {
			return nil, true, fmt.Errorf("configure %s: %s item %d must be a string, got %T", ruleName, key, i, item)
		}
		if strings.TrimSpace(name) == "" {
			return nil, true, fmt.Errorf("configure %s: %s item %d is empty", ruleName, key, i)
		}
		names[name] = true
	}
	return names, true, nil
}
