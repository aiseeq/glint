package patterntest

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// FileRuleLines runs a file rule on one file and returns the reported lines.
func FileRuleLines(t *testing.T, rule FileRule, path, source string) []int {
	t.Helper()
	var got []int
	for _, v := range rule.AnalyzeFile(rulestest.GoFile(t, path, source)) {
		got = append(got, v.Line)
	}
	return got
}

func AnalyzeFileRule(t *testing.T, rule FileRule, source string) []int {
	t.Helper()
	return FileRuleLines(t, rule, "app.go", source)
}

// wantLines returns the lines of the source marked with a // want comment.
func wantLines(source string) []int {
	var lines []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// want") {
			lines = append(lines, i+1)
		}
	}
	return lines
}

func AssertWanted(t *testing.T, rule any, source string) {
	t.Helper()
	switch r := rule.(type) {
	case GoProjectRule:
		assert.Equal(t, wantLines(source), AppRuleLines(t, r, source))
	case FileRule:
		assert.Equal(t, wantLines(source), AnalyzeFileRule(t, r, source))
	default:
		t.Fatalf("%T is neither a project nor a file rule", rule)
	}
}
