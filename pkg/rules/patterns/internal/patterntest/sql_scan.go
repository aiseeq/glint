package patterntest

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// WantedLines returns file:line of the lines marked "want <rule>"; a marker
// saying "the line above" points at the previous line.
func WantedLines(files map[string]string, rule string) []string {
	var places []string
	for name, source := range files {
		for i, line := range strings.Split(source, "\n") {
			if !strings.Contains(line, "want "+rule) {
				continue
			}
			n := i + 1
			if strings.Contains(line, "the line above") {
				n--
			}
			places = append(places, fmt.Sprintf("%s:%d", name, n))
		}
	}
	slices.Sort(places)
	return places
}

func FoundLines(violations []*core.Violation) []string {
	return rulestest.ViolationPlaces(violations)
}
