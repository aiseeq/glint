package core

import (
	"regexp"
	"slices"
	"strings"
	"sync"
)

// SuppressionInline marks a Violation.Suppression entry that stands for an
// inline marker which silenced a finding; an exception entry is
// SuppressionExceptionPrefix followed by the exception's key.
const (
	SuppressionInline          = "inline"
	SuppressionExceptionPrefix = "exception:"
)

// suppressionLog records, per rule name, the lines of the inline markers that
// silenced a finding. Rules of one file may run on several goroutines.
type suppressionLog struct {
	mu   sync.Mutex
	hits map[string][]int
}

func (l *suppressionLog) record(rule string, line int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = make(map[string][]int)
	}
	if !slices.Contains(l.hits[rule], line) {
		l.hits[rule] = append(l.hits[rule], line)
	}
}

// TakeSuppressionHits returns the lines of the markers that silenced findings
// of the rule since the last call, and forgets them.
func (ctx *FileContext) TakeSuppressionHits(rule string) []int {
	ctx.suppression.mu.Lock()
	defer ctx.suppression.mu.Unlock()
	lines := ctx.suppression.hits[rule]
	delete(ctx.suppression.hits, rule)
	slices.Sort(lines)
	return lines
}

// safeMarker matches the "<rule>: safe" form; only names of more than one
// word are taken, so prose such as "note: safe" is no marker.
var safeMarker = regexp.MustCompile(`\b([a-z][a-z0-9]*(?:-[a-z0-9]+)+):\s?safe\b`)

// ruleNameShape is what a rule name in a nolint list looks like.
var ruleNameShape = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

// ParseSuppressionComment reads the suppression marker a comment carries —
// "//" or "/*" included, or a block-comment continuation line — when the
// comment starts with it: nolint:<list>, "<rule>: safe", or the bare //nolint
// directive that names no rule. Prose that mentions a marker after other words
// is no marker.
func ParseSuppressionComment(comment string) (names []string, bare bool) {
	directive := strings.HasPrefix(comment, "//nolint")
	text := strings.TrimLeft(strings.TrimLeft(comment, "/*"), " \t")
	switch {
	case strings.HasPrefix(text, "nolint:"):
		list, _ := nolintNames(text)
		for _, name := range list {
			if ruleNameShape.MatchString(name) {
				names = append(names, name)
			}
		}
	case directive:
		rest := strings.TrimPrefix(comment, "//nolint")
		bare = rest == "" || rest[0] == ' ' || rest[0] == '\t'
	default:
		if match := safeMarker.FindStringSubmatchIndex(text); match != nil && match[0] == 0 {
			names = append(names, text[match[2]:match[3]])
		}
	}
	return names, bare
}
