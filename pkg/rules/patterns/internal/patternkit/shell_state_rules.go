package patternkit

import (
	"strings"
)

// ReadsFile reports a command of the body, other than the test at index i,
// that names the tested file.
func ReadsFile(body []ShellLine, test int, file string) bool {
	for j, l := range body {
		if j != test && strings.Contains(l.Text, file) {
			return true
		}
	}
	return false
}
