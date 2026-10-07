package patterns

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewTombstoneCommentRule())
}

// TombstoneCommentRule detects "tombstone" comments — notes about code that
// has been deleted:
//
//	// GetDB removed — architectural boundary violation eliminated
//	// УДАЛЕНО: processed статус (дубликат approved)
//	_ = disableFixes // CryptoProv fixes removed
//
// CLAUDE.md: "Delete cleanly, git remembers" — history lives in git, not in
// comments. A tombstone is noise the moment the commit lands.
//
// Not flagged: behavior descriptions ("entries are removed after TTL", "if
// the record was removed"), godoc deprecation markers (owned by the
// deprecated-comment rule), policy quotes, Go doc code blocks (//<tab>),
// which quote an example instead of annotating the code around them, and a
// status word in capitals that a string literal of the file spells too (a
// note on rows over the query filtering that status): it names the value, not
// code that went away.
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
			`(?i)(?:\b(?:is|are|was|were|be|being|been|get|gets|got|to|soft)\s+(?:\w+ly\s+)?|будут\s+|будет\s+|был[аио]?\s+|должн\w*\s+быть\s+|могут\s+быть\s+|не\s+|что\s+|сколько\s+)$`),
		behaviorTail: regexp.MustCompile(
			`(?i)^(?:\s+from\b|\s*(?:->|→)|\s*(?:или|либо|or)\s)`),
		policyLine: regexp.MustCompile(
			`(?i)CLAUDE\.md|принцип|запрещ|policy|deprecated:`),
	}
}

// AnalyzeFile checks comment lines for tombstones
// tombstoneNeedles are lower-case texts one of which every match of the
// tombstone pattern contains.
var tombstoneNeedles = []string{"removed", "deleted", "удал", "больше не использ", "no longer"}

func (r *TombstoneCommentRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() && !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation
	var literalWords map[string]bool

	for i, line := range ctx.Lines {
		comment := commentTextOfLine(line)
		// Words every tombstone match holds: most comments are ruled out
		// without running the regexps.
		if comment == "" || !helpers.ContainsAny(strings.ToLower(comment), tombstoneNeedles) || r.policyLine.MatchString(comment) {
			continue
		}
		if ctx.IsGoFile() && strings.HasPrefix(comment, "\t") {
			continue // gofmt keeps doc code blocks as //<tab>: an example, not a note
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
			continue // "removed from X", "deleted -> *", "удалено или ..." — data-flow/state docs
		}
		if word := strings.TrimFunc(comment[loc[0]:loc[1]], isNotLetter); isCapitalWord(word) {
			if literalWords == nil {
				literalWords = stringLiteralWords(ctx)
			}
			if literalWords[word] {
				continue // the status value a literal spells, not a tombstone
			}
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
// commentTextOfLine returns the text of a line's comment without its marker.
// The marker itself is located by the canonical core.CommentPart, so that a
// "//" inside a string literal never starts a comment.
func commentTextOfLine(line string) string {
	comment := core.CommentPart(line)
	switch {
	case strings.HasPrefix(comment, "//"), strings.HasPrefix(comment, "/*"):
		return comment[2:]
	case strings.HasPrefix(comment, "*"):
		return comment[1:]
	}
	return ""
}

// isCapitalWord reports a word written in capitals only (DELETED, УДАЛЕНО).
func isCapitalWord(word string) bool {
	for _, c := range word {
		if !unicode.IsUpper(c) {
			return false
		}
	}
	return word != ""
}

func isNotLetter(c rune) bool { return !unicode.IsLetter(c) }

// stringLiteralWords returns the words spelled inside the file's string
// literals, multi-line raw strings included: the characters the literal mask
// blanks and the comment mask keeps.
func stringLiteralWords(ctx *core.FileContext) map[string]bool {
	text := helpers.FileJSText(ctx)
	code := helpers.FileJSCode(ctx)
	words := map[string]bool{}
	var literal strings.Builder
	for i := range text {
		literal.Reset()
		for j := 0; j < len(text[i]) && j < len(code[i]); j++ {
			if text[i][j] != code[i][j] {
				literal.WriteByte(text[i][j])
			} else {
				literal.WriteByte(' ')
			}
		}
		for _, word := range strings.FieldsFunc(literal.String(), isNotLetter) {
			words[word] = true
		}
	}
	return words
}
