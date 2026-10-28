package patterntest

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

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
	case rules.GoProjectRule:
		assert.Equal(t, wantLines(source), rulestest.GoProjectRuleLines(t, r, "app.go", source))
	case rules.Rule:
		assert.Equal(t, wantLines(source), rulestest.GoFileRuleLines(t, r, "app.go", source))
	default:
		t.Fatalf("%T is neither a project nor a file rule", rule)
	}
}
