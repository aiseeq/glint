package concurrencyrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const regexpCompileInLoopSource = `package units

import (
	"regexp"
	"strings"
	"sync"
)

const prefix = "^"
const suffix = "word$"
const pattern = prefix + suffix

func Scan(lines []string, dynamic []string) {
	for i, line := range lines {
		regexp.MustCompile("^x+").MatchString(line) // want regexp-compile-in-loop
		regexp.Compile(pattern) // want regexp-compile-in-loop
		regexp.MatchString("x+", line) // want regexp-compile-in-loop
		regexp.Match("x+", []byte(line)) // want regexp-compile-in-loop
		regexp.MatchReader("x+", strings.NewReader(line)) // want regexp-compile-in-loop
		regexp.MustCompilePOSIX("x+") // want regexp-compile-in-loop
		regexp.CompilePOSIX("x+") // want regexp-compile-in-loop
		regexp.MustCompile("^" + suffix) // want regexp-compile-in-loop
		regexp.MustCompile(dynamic[i])
		for range 1 {
			regexp.Compile("nested") // want regexp-compile-in-loop
		}
	}
}

func Cold() {
	regexp.MustCompile("outside")
}

//glint:hot
func Hot(s string) {
	regexp.MustCompile("hot") // want regexp-compile-in-loop
	func() { regexp.Compile("iife") }() // want regexp-compile-in-loop
	_ = func() { regexp.Compile("deferred literal") }
}

func Once(lines []string) {
	var once sync.Once
	for _, line := range lines {
		once.Do(func() { regexp.MustCompile("once") })
		cached := sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile("value") })
		_ = cached()
		_ = sync.OnceFunc(func() { regexp.MustCompile("func") })
		_ = line
	}
}

func Constants(lines []string) {
	for _, line := range lines {
		regexp.MatchString(prefix+suffix, line) // want regexp-compile-in-loop
	}
}
`

func TestRegexpCompileInLoop(t *testing.T) {
	files := map[string]string{"units/units.go": regexpCompileInLoopSource}
	violations, err := NewRegexpCompileInLoopRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "regexp-compile-in-loop"), patterntest.FoundLines(violations))
}
