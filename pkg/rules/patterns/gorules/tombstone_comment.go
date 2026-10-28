package gorules

import (
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

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
//	// RefreshToken wrapper физически устранён
//	_ = disableFixes // CryptoProv fixes removed
//
// CLAUDE.md: "Delete cleanly, git remembers" — history lives in git, not in
// comments. A tombstone is noise the moment the commit lands.
//
// Not flagged: behavior descriptions ("entries are removed after TTL", "if
// the record was removed", "a channel deleted since"), a series of changes
// ("lines added and removed", "rows inserted, updated or deleted"), godoc
// deprecation markers (owned by the deprecated-comment rule), policy quotes,
// Go doc code blocks (//<tab>), which quote an example instead of annotating
// the code around them, and a
// status word in capitals that a string literal of the file spells too (a
// note on rows over the query filtering that status): it names the value, not
// code that went away.
//
// A note about deleted code names what went away and stops there: the
// removal word opens it ("Removed the fallback", "SIMPLIFIED: removed 3
// wrappers") or closes its clause ("GetDB removed.", "importer deleted — use
// the queue"). A removal word that a sentence goes on from ("removed
// afterwards", "deleted in the work tree", "a deleted file") is about what the
// program does to files and records; a sentence wrapped onto the next comment
// line goes on there. A pronoun before the removal word ("one it removed",
// "the rows they deleted") is the one that removes: the program, not a note.
// So is the first sentence of a godoc comment that opens with the name
// declared below ("Result counts the entries a trim removed"): it describes
// the declaration; a later sentence of the doc can still be a note.
type TombstoneCommentRule struct {
	*rules.BaseRule
	tombstone    *regexp.Regexp
	behaviorAux  *regexp.Regexp
	behaviorTail *regexp.Regexp
	runtimeState *regexp.Regexp
	addedBefore  *regexp.Regexp
	addedAfter   *regexp.Regexp
	policyLine   *regexp.Regexp
	noteStart    *regexp.Regexp
	noteEnd      *regexp.Regexp
	remover      *regexp.Regexp
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
			`(?i)\b(?:removed|deleted)\b|(?:удал|устран)[её]н[оаы]?(?:[^а-яё]|$)|больше не использ|no longer (?:used|needed|exists|supported)`),
		behaviorAux: regexp.MustCompile(
			`(?i)(?:\b(?:is|are|was|were|be|being|been|get|gets|got|to|soft|never|not)\s+(?:\w+ly\s+)?|будут\s+|будет\s+|был[аио]?\s+|должн\w*\s+быть\s+|могут\s+быть\s+|не\s+|что\s+|сколько\s+)$`),
		// "deleted since," and "removed in the meantime" date a state of the
		// data; "removed since v2" dates code and stays a tombstone.
		behaviorTail: regexp.MustCompile(
			`(?i)^(?:\s+from\b|\s*(?:->|→)|\s*(?:или|либо|or)\s|\s+since(?:\s*[,.;:)]|\s*$|\s+(?:then|it|they|the|opening|loading)\b)|\s+(?:meanwhile|in the meantime|concurrently|in between)\b)`),
		// A filesystem object directly before the removal word usually names
		// runtime state rather than deleted code.
		runtimeState: regexp.MustCompile(
			`(?i)(?:\b(?:file|files|dir|directory|folder|worktree|repository)\s+(?:(?:is|was|were|has been)\s+)?$|(?:^|[^\p{L}\p{N}_])(?:каталог|директори[яи]|папк[аи]|файл[аы]?|дерев[оа])\s*$)`),
		// A series of changes to data ends in the removal word: "added and
		// removed", "inserted, updated or deleted".
		addedBefore: regexp.MustCompile(`(?i)\b(?:added|inserted|updated|created|changed|modified|written|moved|renamed)\s*(?:,|and|or|&|/)\s*$`),
		addedAfter:  regexp.MustCompile(`(?i)^\s*(?:and|or|&|/)\s*added\b`),
		policyLine: regexp.MustCompile(
			`(?i)CLAUDE\.md|принцип|запрещ|policy|deprecated:`),
		// What precedes a removal word that opens a note: nothing, a label
		// ("SIMPLIFIED:", "networks:") or the end of a sentence.
		noteStart: regexp.MustCompile(`(?:^|[.;!?—–]\s|\()\s*(?:[\p{L}\d_.-]+:\s*)?$`),
		// What follows a removal word that closes a note: the end of the
		// sentence or clause, a dash, a date of the removal.
		noteEnd: regexp.MustCompile(`(?i)^(?:\s*$|\s*[.,;:!?)]|\s+[—–-]|\s+since\b)`),
		// A pronoun right before the removal word is its subject, the one that
		// removes ("one it removed", "the rows they deleted"): the word is a
		// verb of the program, not a note on code.
		remover: regexp.MustCompile(`(?i)\b(?:i|it|they|we|you|he|she)\s+(?:(?:has|have|had|\w+ly)\s+)?$`),
	}
}

// tombstoneNeedles are lower-case texts one of which every match of the
// tombstone pattern contains.
var tombstoneNeedles = []string{"removed", "deleted", "удал", "устран", "больше не использ", "no longer"}

// AnalyzeFile checks comment lines for tombstones.
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
		// The Cyrillic branch ends on the character after the word: the
		// text after the note starts there.
		if last, size := utf8.DecodeLastRuneInString(comment[loc[0]:loc[1]]); !unicode.IsLetter(last) {
			loc[1] -= size
		}
		before := sentenceBefore(comment[:loc[0]], ctx.Lines, i)
		if r.behaviorAux.MatchString(before) || r.remover.MatchString(before) || r.runtimeState.MatchString(before) {
			continue // "are removed", "будут удалены" — behavior, not a tombstone
		}
		if loc[0] > 0 && strings.IndexByte("='\"`.>/-_", comment[loc[0]-1]) >= 0 {
			continue // Status=deleted, 'deleted', soft-deleted — a value, not a tombstone
		}
		if describesDeclaration(ctx.Lines, i, comment[:loc[0]], comment[loc[0]:loc[1]]) {
			continue // a doc of the name declared below, not a note on deleted code
		}
		if r.behaviorTail.MatchString(comment[loc[1]:]) {
			continue // "removed from X", "deleted -> *", "удалено или ..." — data-flow/state docs
		}
		if r.addedBefore.MatchString(before) || r.addedAfter.MatchString(comment[loc[1]:]) {
			continue // "lines added and removed", "rows inserted, updated or deleted" — changes to data
		}
		after := comment[loc[1]:]
		if strings.TrimSpace(after) != "" || !isCapitalWord(strings.TrimFunc(comment[loc[0]:loc[1]], isNotLetter)) {
			after = sentenceAfter(after, ctx.Lines, i)
		}
		if !r.noteStart.MatchString(before) && !r.noteEnd.MatchString(after) {
			continue // "removed afterwards", "a deleted file" — a sentence about what the program does
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

// sentenceBefore returns the text of a comment line before a word: when the
// word opens the line and the comment line above ends mid-sentence, the
// sentence started there ("the entry it described was / deleted, or ...").
func sentenceBefore(before string, lines []string, i int) string {
	if strings.TrimSpace(before) != "" || i == 0 {
		return before
	}
	above := strings.TrimRight(commentTextOfLine(lines[i-1]), " \t")
	if above == "" || strings.HasPrefix(above, "\t") || strings.ContainsRune(".!?:;—–", lastRune(above)) {
		return before
	}
	return above + " " + strings.TrimLeft(before, " \t")
}

// lastRune returns the last character of a non-empty string.
func lastRune(s string) rune {
	r, _ := utf8.DecodeLastRuneInString(s)
	return r
}

// commentTextOfLine returns the text of a line's comment without its marker,
// or "" when the line has no comment. The marker is located by the canonical
// core.CommentPart, so that a "//" inside a string literal never starts a
// comment; block-comment continuation lines ("* text") count.
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

// documentsName reports a comment on line i over code that spells name as
// an identifier: a doc comment opens with the name it documents.
func documentsName(lines []string, i int, name string) bool {
	for _, line := range lines[i+1:] {
		text := strings.TrimSpace(line)
		if text == "" || isCommentLine(line) {
			continue
		}
		return slices.Contains(strings.FieldsFunc(text, isNotIdentChar), name)
	}
	return false
}

// describesDeclaration reports a removal word on comment line i, with before
// the text ahead of it, inside a doc of the declaration below: "// Removed —
// titles ..." over the field Removed, or "Result counts the entries a trim
// removed" over type Result.
func describesDeclaration(lines []string, i int, before, word string) bool {
	if strings.TrimSpace(before) == "" && documentsName(lines, i, word) {
		return true
	}
	return godocFirstSentence(lines, i, before)
}

// isCommentLine reports a line that holds a comment and nothing else.
func isCommentLine(line string) bool {
	return commentTextOfLine(line) != "" && strings.HasPrefix(strings.TrimSpace(line), core.CommentPart(line))
}

// sentenceEnd matches the end of a sentence inside a comment.
var sentenceEnd = regexp.MustCompile(`[.!?;](?:\s|$)`)

// godocFirstSentence reports a match on comment line i, with before the text
// of the line ahead of it, inside the first sentence of a doc comment that
// opens with the name the code below declares, and goes on past it: godoc's
// "Result counts the entries ..." describes the declaration.
func godocFirstSentence(lines []string, i int, before string) bool {
	if !isCommentLine(lines[i]) {
		return false
	}
	start := i
	for start > 0 && isCommentLine(lines[start-1]) {
		start--
	}
	var text strings.Builder
	for _, line := range lines[start:i] {
		comment := commentTextOfLine(line)
		if strings.HasPrefix(comment, "\t") {
			return false
		}
		text.WriteString(comment + " ")
	}
	text.WriteString(before)
	if sentenceEnd.MatchString(text.String()) {
		return false
	}
	words := strings.FieldsFunc(text.String(), isNotIdentChar)
	return len(words) > 1 && documentsName(lines, i, words[0])
}

func isNotIdentChar(c rune) bool { return c != '_' && !unicode.IsLetter(c) && !unicode.IsDigit(c) }

// sentenceAfter returns the text after a match on line i: the rest of the
// line, or, when the line ends there, the next comment line the sentence is
// wrapped onto - one that does not open with a capital, and not after a
// removal word in capitals, which labels a note.
func sentenceAfter(rest string, lines []string, i int) string {
	if strings.TrimSpace(rest) != "" || i+1 >= len(lines) {
		return rest
	}
	next := commentTextOfLine(lines[i+1])
	first, _ := utf8.DecodeRuneInString(strings.TrimSpace(next))
	if strings.TrimSpace(next) == "" || strings.HasPrefix(next, "\t") || unicode.IsUpper(first) {
		return rest // a capital opens a sentence of its own
	}
	return " " + next
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
