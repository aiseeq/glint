package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/shellrules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// The flag in a field of the value that indexes the map keeps the finding.
func TestCLIFlagFieldOfTheSameValueIndexesMap(t *testing.T) {
	assert.Equal(t, []int{17}, rulestest.GoProjectRuleLines(t, shellrules.NewCLIFlagMapLookupWithoutOKRule(), "app.go", `package main

import (
	"flag"
	"fmt"
)

type Job struct{ Model string }

var limits = map[string]int{"a": 1}

func main() {
	model := flag.String("model", "", "")
	flag.Parse()
	j := Job{Model: *model}
	_ = j
	fmt.Println(limits[j.Model])
}
`))
}

// Appending to the slice under a key is the zero-value idiom: no comma-ok is
// needed even when the key is a flag.
func TestCLIFlagMapAppendIdiom(t *testing.T) {
	assert.Empty(t, rulestest.GoProjectRuleLines(t, shellrules.NewCLIFlagMapLookupWithoutOKRule(), "app.go", `package main

import "flag"

var groups = map[string][]int{}

func main() {
	name := flag.String("name", "", "")
	flag.Parse()
	groups[*name] = append(groups[*name], 1)
}
`))
}

// Appending under one key to the slice read under another key is a lookup
// without comma-ok: the read key is not the written one.
func TestCLIFlagMapAppendOtherKeyIsLookup(t *testing.T) {
	assert.Equal(t, []int{11}, rulestest.GoProjectRuleLines(t, shellrules.NewCLIFlagMapLookupWithoutOKRule(), "app.go", `package main

import "flag"

var groups = map[string][]int{}

func main() {
	a := flag.String("a", "", "")
	b := flag.String("b", "", "")
	flag.Parse()
	groups[*a] = append(groups[*b], 1)
}
`))
}

// The idiom in parentheses is the same idiom.
func TestCLIFlagMapAppendIdiomInParens(t *testing.T) {
	assert.Empty(t, rulestest.GoProjectRuleLines(t, shellrules.NewCLIFlagMapLookupWithoutOKRule(), "app.go", `package main

import "flag"

var groups = map[string][]int{}

func main() {
	name := flag.String("name", "", "")
	flag.Parse()
	(groups[*name]) = (append((groups[*name]), 1))
}
`))
}

// A map entry assigned from a call with two results is no append idiom: the
// later read under the flag is a lookup without comma-ok.
func TestCLIFlagMapEntryFromTwoResultCall(t *testing.T) {
	assert.Equal(t, []int{15}, rulestest.GoProjectRuleLines(t, shellrules.NewCLIFlagMapLookupWithoutOKRule(), "app.go", `package main

import "flag"

var groups = map[string][]int{}

func pair() (int, []int) { return 0, nil }

func main() {
	name := flag.String("name", "", "")
	flag.Parse()
	var n int
	n, groups[*name] = pair()
	_ = n
	_ = groups[*name]
}
`))
}
