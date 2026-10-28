package patterntest

import (
	"github.com/aiseeq/glint/pkg/core"
)

func ViolationLines(violations []*core.Violation) []int {
	lines := make([]int, 0, len(violations))
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	return lines
}
