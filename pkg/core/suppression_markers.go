package core

import (
	"slices"
	"strings"
)

// SuppressionMarker is an inline suppression comment of a line: the rule
// names it lists, or a bare nolint that names none. Text is the comment the
// marker was read from.
type SuppressionMarker struct {
	Line  int
	Rules []string
	Bare  bool
	Text  string
}

// fileMarkers are the markers of a file, and by line the indexes of those on
// each line.
type fileMarkers struct {
	list   []SuppressionMarker
	byLine map[int][]int
}

// markersKey keys the markers of a file in FileShared.
type markersKey struct{}

// SuppressionMarkers returns the suppression markers of the file: those that
// start a comment of its language — the Go and TypeScript/JavaScript
// comments outside literals, '#' in shell, make, Docker, YAML, env, Python
// and nginx files, '--' and '/* */' in SQL, '<!-- -->' in Markdown outside
// code and in HTML, '{{/* */}}' in templates, '//' and '/* */' in tsconfig.
// A file of another kind has none. A Go doc code block (//<tab>) quotes an
// example and gives none.
//
// This is the one source of markers: what suppresses a finding (IsSuppressed,
// LineSuppresses) is exactly what the marker rules see and judge. The result
// must not be modified.
func (ctx *FileContext) SuppressionMarkers() []SuppressionMarker {
	return ctx.markers().list
}

func (ctx *FileContext) markers() *fileMarkers {
	return FileShared(ctx, markersKey{}, func() *fileMarkers {
		markers := &fileMarkers{byLine: map[int][]int{}}
		goFile := ctx.IsGoFile()
		for _, comment := range fileComments(ctx) {
			text := strings.TrimSpace(comment.Text)
			if goFile && strings.HasPrefix(comment.Text, "//\t") {
				continue
			}
			names, bare := ParseSuppressionComment(text)
			if len(names) == 0 && !bare {
				continue
			}
			markers.byLine[comment.Line] = append(markers.byLine[comment.Line], len(markers.list))
			markers.list = append(markers.list, SuppressionMarker{Line: comment.Line, Rules: names, Bare: bare, Text: text})
		}
		return markers
	})
}

// lineSuppresses reports whether a marker on the line (1-based) suppresses
// the rule. The marker of suppression-without-reason suppresses only with a
// reason: a bare one would hide its own finding and the marker it stands over.
func (ctx *FileContext) lineSuppresses(line int, ruleName string) bool {
	markers := ctx.markers()
	for _, i := range markers.byLine[line] {
		marker := markers.list[i]
		if slices.Contains(marker.Rules, ruleName) && (ruleName != SuppressionReasonRule || SuppressionHasReason(marker.Text, ruleName)) {
			return true
		}
	}
	return false
}
