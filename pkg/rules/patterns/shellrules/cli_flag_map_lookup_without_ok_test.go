package shellrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestCLIFlagMapLookupWithoutOKIgnoresMapUpdates(t *testing.T) {
	assert.Empty(t, rulestest.GoProjectRuleLines(t, NewCLIFlagMapLookupWithoutOKRule(), "app.go", `package main

import "flag"

func main() {
	class := flag.String("class", "small", "class")
	flag.Parse()
	counts := map[string]int{}
	counts[*class]++
	counts[*class]--
	counts[*class] += 2
	_ = counts
}
`))
}

func TestCLIFlagMapLookupWithoutOKReportsDictionaryLookup(t *testing.T) {
	assert.Equal(t, []int{10}, rulestest.GoProjectRuleLines(t, NewCLIFlagMapLookupWithoutOKRule(), "app.go", `package main

import "flag"

var table = map[string]int{"small": 1, "large": 2}

func main() {
	mode := flag.String("mode", "small", "mode")
	flag.Parse()
	_ = table[*mode]
}
`))
}

// The rule reports one finding per flag; a counter met first must not take
// that place and hide a lookup of the same flag further down.
func TestCLIFlagMapLookupWithoutOKCounterDoesNotHideLaterLookup(t *testing.T) {
	assert.Equal(t, []int{12}, rulestest.GoProjectRuleLines(t, NewCLIFlagMapLookupWithoutOKRule(), "app.go", `package main

import "flag"

var table = map[string]int{"small": 1, "large": 2}

func main() {
	class := flag.String("class", "small", "class")
	flag.Parse()
	counts := map[string]int{}
	counts[*class]++
	_ = table[*class]
	_ = counts
}
`))
}
