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
// Why inline: a router carrying `// 2. Legacy mode: separate admin/user path
// handling` — not a symbol name, not a godoc. The comment itself admits a
// runtime legacy branch exists, which CLAUDE.md's "No legacy, only current
// code" forbids.
//
// Detects in Go, TypeScript and JavaScript files:
//   - `// Legacy mode`, `// Legacy compatibility`, `// Legacy:`
//   - `// legacy foo`, `// (legacy)`, `// SMTP_* (legacy)`
//   - multiline /* Legacy ... */ / /** Legacy ... */ prefix
//
// Skips:
//   - Test files (generated code is dropped by the core for every rule)
//   - Comments that quote CLAUDE.md policy (contain "CLAUDE.md", "No legacy",
//     "policy", "запрет", "запрещ") — self-references to the rule itself
//   - //nolint:legacy-comment-marker on the line
type LegacyCommentMarkerRule struct { // legacy-identifier: safe — named after the marker this rule detects
	*rules.BaseRule
	policyQuoteMarkers []string
}

// NewLegacyCommentMarkerRule creates the rule
func NewLegacyCommentMarkerRule() *LegacyCommentMarkerRule { // legacy-identifier: safe — named after the marker this rule detects
	r := &LegacyCommentMarkerRule{
		BaseRule: rules.NewBaseRule(
			"legacy-comment-marker",
			"patterns",
			"Detects inline comments admitting a runtime legacy code path (CLAUDE.md: No legacy, only current code)",
			core.SeverityLow,
		),
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

// AnalyzeFile scans line-by-line for legacy comments in Go, TypeScript and JavaScript files.
func (r *LegacyCommentMarkerRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() && !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if ctx.IsTestFile() {
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
	if core.LineSuppresses(line, "legacy-comment-marker") {
		return nil
	}

	commentText := r.extractComment(line, isBlock)
	if commentText == "" {
		return nil
	}

	// Every finding holds the word; the directive and quote checks below only
	// take findings away.
	if !strings.Contains(strings.ToLower(commentText), "legacy") {
		return nil
	}

	// Suppression directives name rules (nolint:legacy-identifier,
	// legacy-identifier: safe); naming a rule admits nothing about the code.
	lower := suppressionDirectiveRE.ReplaceAllString(strings.ToLower(commentText), " ")
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
// extractComment returns the comment part of a line. Inside a block comment
// the whole line is comment text; otherwise the canonical core.CommentPart
// decides, so that a "//" inside a string literal — a regexp source, for
// instance — is not treated as a comment.
func (r *LegacyCommentMarkerRule) extractComment(line string, isBlock bool) string {
	if isBlock {
		return line
	}
	return core.CommentPart(line)
}

// suppressionDirectiveRE matches, in a lowercased comment, what names a rule
// rather than admits anything: a nolint rule list, a "<rule>: safe" marker, and
// the rule names legacy-identifier and legacy-comment-marker in prose.
var suppressionDirectiveRE = regexp.MustCompile(`nolint:[a-z0-9_-]+(?:,\s*[a-z0-9_-]+)*|[a-z0-9_-]+:\s*safe\b|\blegacy-(?:identifier|comment-marker)\b`)

// legacyWordRE matches "legacy" as a standalone word, not as a substring
// (e.g., "legally", "legacies").
var legacyWordRE = regexp.MustCompile(`\blegacy\b`) // legacy-identifier: safe — named after the marker this rule detects

// containsLegacyWord checks that "legacy" appears as a standalone word.
func containsLegacyWord(lowerText string) bool { // legacy-identifier: safe — named after the marker this rule detects
	return legacyWordRE.MatchString(lowerText)
}

// urlAdjacentLegacyParenRE matches "legacy" appearing inside parentheses on a
// line that also contains a URL — i.e., the comment is describing a 3rd-party
// service's capability (e.g., "Google Tag Manager (legacy browser support)"),
// not admitting a legacy code path in this project.
var urlAdjacentLegacyParenRE = regexp.MustCompile(`\([^)]*\blegacy\b[^)]*\)`) // legacy-identifier: safe — named after the marker this rule detects

// isURLAdjacentLegacyDescriptor reports whether the line carries a URL plus a
// parenthetical "legacy ..." descriptor — a canonical 3rd-party-capability
// comment pattern that should not trip the rule.
func isURLAdjacentLegacyDescriptor(rawLine, lowerComment string) bool { // legacy-identifier: safe — named after the marker this rule detects
	if !strings.Contains(rawLine, "http://") && !strings.Contains(rawLine, "https://") {
		return false
	}
	return urlAdjacentLegacyParenRE.MatchString(lowerComment)
}
