package patterns

import "strings"

// isVendoredOrGeneratedPath reports whether the path points into vendored or
// generated code that rules should not report on. Matching is case-sensitive,
// as the original per-rule lists were.
func isVendoredOrGeneratedPath(path string) bool {
	return strings.Contains(path, "vendor/") ||
		strings.Contains(path, "node_modules/") ||
		strings.Contains(path, "generated") ||
		strings.Contains(path, ".gen.")
}

// isConfigOrConstantsPath reports whether the lowercased path points at
// config/constants files or directories, where many literal values are
// legitimate. Callers pass strings.ToLower(path).
//
// Contains("config/") subsumes "/config/", and Contains("config.go") subsumes
// "_config.go" — the shorter needles cover the prefixed variants the per-rule
// lists used to spell out.
func isConfigOrConstantsPath(pathLower string) bool {
	for _, pattern := range []string{"config/", "config.go", "constants/", "constants.go"} {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}
