package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTombstoneCommentRule())
}

// TombstoneCommentRule detects "tombstone" comments describing code that was
// deleted:
//
//	// GetDB removed — architectural boundary violation eliminated
//	// УДАЛЕНО: processed статус (дубликат approved)
//	_ = disableFixes // Crypto2B fixes removed
//
// CLAUDE.md: "Delete cleanly, git remembers" — history lives in git, not in
// comments. A tombstone is noise the moment the commit lands.
//
// Not flagged: behavior descriptions ("entries are removed after TTL"),
// Deprecated: markers (deprecated-comment rule), policy quotes.
type TombstoneCommentRule struct {
	*rules.BaseRule
	tombstone    *regexp.Regexp
	behaviorAux  *regexp.Regexp
	behaviorTail *regexp.Regexp
	policyLine   *regexp.Regexp
}

// NewTombstoneCommentRule creates the rule
func NewTombstoneCommentRule() *TombstoneCommentRule {
	return &TombstoneCommentRule{
		BaseRule: rules.NewBaseRule(
			"tombstone-comment",
			"patterns",
			"Detects comments describing deleted code — git history already remembers",
			core.SeverityLow,
		),
		// NOTE: RE2 \b is ASCII-only, so the Cyrillic branch uses an explicit
		// non-letter boundary; it also rejects "удалённый" (remote).
		tombstone: regexp.MustCompile(
			`(?i)\b(?:removed|deleted)\b|удал[её]н[оаы]?(?:[^а-яё]|$)|больше не использ|no longer (?:used|needed|exists|supported)`),
		behaviorAux: regexp.MustCompile(
			`(?i)(?:\b(?:is|are|be|being|been|get|gets|got|to|soft)\s+|будут\s+|будет\s+|был[аио]?\s+|должн\w*\s+быть\s+|могут\s+быть\s+|не\s+|что\s+|сколько\s+)$`),
		behaviorTail: regexp.MustCompile(
			`(?i)^(?:\s+from\b|\s*(?:->|→))`),
		policyLine: regexp.MustCompile(
			`(?i)CLAUDE\.md|принцип|запрещ|policy|deprecated:`),
	}
}

// AnalyzeFile checks comment lines for tombstones
func (r *TombstoneCommentRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() && !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if ctx.IsTestFile() || strings.Contains(ctx.Path, "tombstone_comment") {
		return nil
	}

	var violations []*core.Violation

	for i, line := range ctx.Lines {
		comment := commentTextOfLine(line)
		if comment == "" || r.policyLine.MatchString(comment) {
			continue
		}
		loc := r.tombstone.FindStringIndex(comment)
		if loc == nil {
			continue
		}
		if r.behaviorAux.MatchString(comment[:loc[0]]) {
			continue // "are removed", "будут удалены" — behavior, not a tombstone
		}
		if loc[0] > 0 && strings.IndexByte("='\"`.>/-_", comment[loc[0]-1]) >= 0 {
			continue // Status=deleted, 'deleted', soft-deleted — a value, not a tombstone
		}
		if r.behaviorTail.MatchString(comment[loc[1]:]) {
			continue // "removed from X", "deleted -> *" — data-flow/state docs
		}
		v := r.CreateViolation(ctx.RelPath, i+1,
			"Tombstone comment about deleted code — git history already remembers; delete the note")
		v.WithCode(strings.TrimSpace(line))
		v.WithSuggestion("Remove the comment (and any dead code it annotates); use git log/blame for history")
		violations = append(violations, v)
	}

	return violations
}

// commentTextOfLine returns the comment text of the line (without the //
// marker), or "" when the line has no comment. Comment markers inside string
// literals are ignored; block-comment continuation lines ("* text") count.
func commentTextOfLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "*") {
		return strings.TrimPrefix(trimmed, "*")
	}
	quote := byte(0)
	for i := 0; i < len(line)-1; i++ {
		c := line[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '/':
			if line[i+1] == '/' || line[i+1] == '*' {
				return line[i+2:]
			}
		}
	}
	return ""
}
