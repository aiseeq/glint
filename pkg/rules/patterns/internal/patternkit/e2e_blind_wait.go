package patternkit

import (
	"strings"
)

// IsE2EPath reports whether the file belongs to a browser-test tree.
func IsE2EPath(relPath string) bool {
	normalized := strings.ReplaceAll(relPath, "\\", "/")
	for _, marker := range []string{"/e2e/", "e2e/", "/playwright/", "playwright/", "/cypress/", "cypress/"} {
		if strings.HasPrefix(normalized, marker) || strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
