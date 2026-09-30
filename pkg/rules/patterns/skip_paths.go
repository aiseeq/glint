package patterns

import (
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// skipFrontendPath is the one path filter of the frontend line rules: tests,
// e2e trees, installed dependencies, build output and test setup are not
// hand-written UI code. The walker already skips node_modules/.next/out/dist by
// default; the filter keeps them out when a project overrides skip_dirs.
// Generated code is recognised by its header and dropped by the core, so the
// filter does not guess at it from "generated" in a path.
func skipFrontendPath(ctx *core.FileContext) bool {
	if ctx.IsTestFile() {
		return true
	}
	// RelPath has no leading slash; the prefix lets a top-level e2e/ match "/e2e/".
	path := "/" + filepath.ToSlash(ctx.RelPath)
	return strings.Contains(path, "/e2e/") ||
		strings.Contains(path, "/node_modules/") ||
		strings.Contains(path, "/.next/") ||
		strings.Contains(path, "/out/") ||
		strings.Contains(path, "/dist/") ||
		strings.HasSuffix(path, "/jest.setup.js")
}

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
