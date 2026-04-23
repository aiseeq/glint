package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewLegacyCommentMarkerRule())
}

// LegacyCommentMarkerRule detects inline comments that document a runtime
// legacy code path — "Legacy mode", "Legacy compatibility", "legacy SSE auth",
// "(legacy)" — as distinct from identifier names (covered by
// legacy-identifier) and godoc-level Deprecated comments (covered by
// deprecated-comment).
//
// Why inline: composite_router.go:831 has `// 2. Legacy mode: separate admin/
// user path handling` — not a symbol name, not a godoc. The comment itself
// admits a runtime legacy branch exists, which CLAUDE.md's "No legacy, only
// current code" forbids.
//
// Detects in Go and TypeScript/TSX files:
//   - `// Legacy mode`, `// Legacy compatibility`, `// Legacy:`
//   - `// legacy foo`, `// (legacy)`, `// SMTP_* (legacy)`
//   - multiline /* Legacy ... */ / /** Legacy ... */ prefix
//
// Skips:
//   - Test files and generated code
//   - Comments that quote CLAUDE.md policy (contain "CLAUDE.md", "No legacy",
//     "policy", "запрет", "запрещ") — self-references to the rule itself
//   - //nolint:legacy-comment-marker on the line
//   - The legacy-identifier rule's own file (which prints "Legacy" as a
//     string literal for diagnostic messages — it's the rule implementation,
//     not a legacy code path)
type LegacyCommentMarkerRule struct {
	*rules.BaseRule
	legacyCommentPatterns []*regexp.Regexp
	policyQuoteMarkers    []string
}

// NewLegacyCommentMarkerRule creates the rule
func NewLegacyCommentMarkerRule() *LegacyCommentMarkerRule {
	r := &LegacyCommentMarkerRule{
		BaseRule: rules.NewBaseRule(
			"legacy-comment-marker",
			"patterns",
			"Detects inline comments admitting a runtime legacy code path (CLAUDE.md: No legacy, only current code)",
			core.SeverityLow,
		),
	}
	r.legacyCommentPatterns = []*regexp.Regexp{
		// Line comment (//) containing "Legacy" / "legacy" as a whole word.
		// Requires the comment marker, optional spaces, then the word.
		regexp.MustCompile(`(?i)//\s*[^\n]*\blegacy\b`),
		// Block-comment line content (inside /* ... */ expanded per-line).
		regexp.MustCompile(`(?i)^\s*\*?\s*[^*]*\blegacy\b`),
	}
	r.policyQuoteMarkers = []string{
		"claude.md",
		"no legacy",
		"policy",
		"принцип",
		"запрет",
		"запрещ",
		"CLAUDE.md",
	}
	return r
}

// AnalyzeFile scans line-by-line for legacy comments in Go and TS files.
func (r *LegacyCommentMarkerRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !(ctx.IsGoFile() || ctx.IsTypeScriptFile()) {
		return nil
	}
	if ctx.IsTestFile() {
		return nil
	}
	if r.shouldSkipFile(ctx.RelPath) {
		return nil
	}

	var violations []*core.Violation
	inBlockComment := false

	for i, line := range ctx.Lines {
		lineNum := i + 1
		// Track /* ... */ block-comment state line-by-line.
		trimmed := strings.TrimSpace(line)
		if inBlockComment {
			if strings.Contains(line, "*/") {
				inBlockComment = false
			}
			if v := r.tryMatch(ctx, lineNum, line, true); v != nil {
				violations = append(violations, v)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "/*") && !strings.Contains(line, "*/") {
			inBlockComment = true
			if v := r.tryMatch(ctx, lineNum, line, true); v != nil {
				violations = append(violations, v)
			}
			continue
		}

		// Line with `//` or inline `/* ... */` on the same line.
		if !strings.Contains(line, "//") && !strings.Contains(line, "/*") {
			continue
		}
		if v := r.tryMatch(ctx, lineNum, line, false); v != nil {
			violations = append(violations, v)
		}
	}
	return violations
}

// tryMatch decides whether a comment-bearing line is a runtime legacy marker.
func (r *LegacyCommentMarkerRule) tryMatch(ctx *core.FileContext, lineNum int, line string, isBlock bool) *core.Violation {
	if strings.Contains(line, "nolint:legacy-comment-marker") {
		return nil
	}

	commentText := r.extractComment(line, isBlock)
	if commentText == "" {
		return nil
	}

	lower := strings.ToLower(commentText)
	// Policy quote — self-reference to the rule being enforced, not a legacy code path.
	for _, m := range r.policyQuoteMarkers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return nil
		}
	}
	// URL-adjacent parenthetical descriptor for a 3rd-party service — the
	// "legacy" describes the external service's capability, not our code.
	// Example: `"https://www.googletagmanager.com", // Google Tag Manager (legacy browser support)`
	if isURLAdjacentLegacyDescriptor(line, lower) {
		return nil
	}
	// "Legacy" must appear as a word on its own.
	if !containsLegacyWord(lower) {
		return nil
	}

	v := r.CreateViolation(ctx.RelPath, lineNum,
		"Comment admits a runtime legacy code path — remove the branch or update the comment")
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("CLAUDE.md: \"No legacy, only current code\". Either delete the legacy branch " +
		"(history stays in git) or rewrite it as the current canonical path and drop the \"legacy\" label.")
	return v
}

// extractComment returns the comment text on the line (or entire line content
// for block comments).
func (r *LegacyCommentMarkerRule) extractComment(line string, isBlock bool) string {
	if isBlock {
		return line
	}
	if idx := strings.Index(line, "//"); idx >= 0 {
		return line[idx:]
	}
	if idx := strings.Index(line, "/*"); idx >= 0 {
		end := strings.Index(line[idx:], "*/")
		if end >= 0 {
			return line[idx : idx+end+2]
		}
		return line[idx:]
	}
	return ""
}

// containsLegacyWord checks that "legacy" appears as a standalone word, not
// as a substring (e.g., "legally", "legacies").
func containsLegacyWord(lowerText string) bool {
	re := regexp.MustCompile(`\blegacy\b`)
	return re.MatchString(lowerText)
}

// urlAdjacentLegacyParenRE matches "legacy" appearing inside parentheses on a
// line that also contains a URL — i.e., the comment is describing a 3rd-party
// service's capability (e.g., "Google Tag Manager (legacy browser support)"),
// not admitting a legacy code path in this project.
var urlAdjacentLegacyParenRE = regexp.MustCompile(`\([^)]*\blegacy\b[^)]*\)`)

// isURLAdjacentLegacyDescriptor reports whether the line carries a URL plus a
// parenthetical "legacy ..." descriptor — a canonical 3rd-party-capability
// comment pattern that should not trip the rule.
func isURLAdjacentLegacyDescriptor(rawLine, lowerComment string) bool {
	if !strings.Contains(rawLine, "http://") && !strings.Contains(rawLine, "https://") {
		return false
	}
	return urlAdjacentLegacyParenRE.MatchString(lowerComment)
}

// shouldSkipFile excludes generated code, vendor, and the file that prints
// "Legacy" as part of its own diagnostic machinery.
func (r *LegacyCommentMarkerRule) shouldSkipFile(relPath string) bool {
	lower := strings.ToLower(relPath)
	if strings.HasSuffix(lower, ".gen.go") ||
		strings.HasSuffix(lower, "_gen.go") ||
		strings.Contains(lower, "/generated/") ||
		strings.Contains(lower, "node_modules/") ||
		strings.Contains(lower, "vendor/") {
		return true
	}
	// The legacy-identifier rule (and this one) reference "Legacy" as string
	// literals / comments for diagnostic purposes. Skip them.
	if strings.Contains(lower, "legacy_identifier.go") ||
		strings.Contains(lower, "legacy_comment_marker.go") ||
		strings.Contains(lower, "deprecated_comment.go") {
		return true
	}
	return false
}
