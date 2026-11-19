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
	"sort"
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
	hotOnce.Do(func() { regexp.MustCompile("hot once") })
}

var hotOnce sync.Once

func Once(lines []string) {
	var once sync.Once
	for _, line := range lines {
		once.Do(func() { regexp.MustCompile("once") })
		cached := sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile("value") }) // want regexp-compile-in-loop
		_ = cached()
		_ = sync.OnceFunc(func() { regexp.MustCompile("func") }) // want regexp-compile-in-loop
		_ = sync.OnceValues(func() (*regexp.Regexp, error) { return regexp.Compile("values") }) // want regexp-compile-in-loop
		_ = line
	}
}

func OnceOutside(lines []string) {
	cached := sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile("cached outside") })
	onceFunc := sync.OnceFunc(func() { regexp.MustCompile("func outside") })
	onceValues := sync.OnceValues(func() (*regexp.Regexp, error) { return regexp.Compile("values outside") })
	for _, line := range lines {
		_ = cached()
		onceFunc()
		_, _ = onceValues()
		_ = line
	}
}

func ForCondition(s string) {
	for regexp.MustCompile("condition").MatchString(s) { // want regexp-compile-in-loop
		s = s[1:]
	}
}

func ForPost(s string) {
	for i := 0; i < 1; regexp.MatchString("post", s) { // want regexp-compile-in-loop
		i++
	}
}

func ForClauseForms() {
	for i := 0; i < 1; i++ {
		regexp.MustCompile("for clause") // want regexp-compile-in-loop
	}
	for {
		regexp.MustCompile("infinite") // want regexp-compile-in-loop
		break
	}
}

func CallbackInLoop(lines []string) {
	for _, line := range lines {
		_ = len(strings.FieldsFunc(line, func(r rune) bool {
			return regexp.MustCompile("callback").MatchString(string(r)) // want regexp-compile-in-loop
		}))
		sort.Slice([]string{line}, func(i, j int) bool {
			return regexp.MustCompile("comparator").MatchString(line) // want regexp-compile-in-loop
		})
	}
}

func Constants(lines []string) {
	for _, line := range lines {
		regexp.MatchString(prefix+suffix, line) // want regexp-compile-in-loop
	}
}
`

const regexpCompileInLoopTestFileSource = `package units

import "regexp"

func TestForLoops() {
	for i := 0; i < 1; i++ {
		regexp.MustCompile("test file")
	}
	for {
		regexp.MustCompile("test infinite")
		break
	}
}
`

func TestRegexpCompileInLoop(t *testing.T) {
	files := map[string]string{
		"units/units.go":      regexpCompileInLoopSource,
		"units/units_test.go": regexpCompileInLoopTestFileSource,
	}
	violations, err := NewRegexpCompileInLoopRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "regexp-compile-in-loop"), patterntest.FoundLines(violations))
}
