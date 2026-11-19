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
	"slices"
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

type memo struct{}

func (memo) GetOrCreate(key string, make func() *regexp.Regexp) *regexp.Regexp { return make() }

type runner struct{}

func (runner) Do(f func()) { f() }

func StoredCallbacks(paths []string, cache memo, handle func(string, func()), r runner) {
	for _, path := range paths {
		handle(path, func() { regexp.MustCompile("stored handler") })
		_ = cache.GetOrCreate(path, func() *regexp.Regexp { return regexp.MustCompile("memo") })
		r.Do(func() { regexp.MustCompile("custom do") })
		func() { regexp.MustCompile("iife in loop") }() // want regexp-compile-in-loop
		_ = slices.IndexFunc(paths, func(p string) bool { return regexp.MustCompile("generic").MatchString(p) }) // want regexp-compile-in-loop
	}
}

//glint:hot
func HotCallbacks(lines []string, handle func(func())) {
	sort.Slice(lines, func(i, j int) bool { return regexp.MustCompile("hot comparator").MatchString(lines[i]) }) // want regexp-compile-in-loop
	handle(func() { regexp.MustCompile("hot stored") })
}

func LoopHeaders(lines []string) {
	for re := regexp.MustCompile("init"); re != nil; re = nil {
		_ = re
	}
	for range regexp.MustCompile("range x").FindAllString("a", -1) {
	}
	for range func(yield func(int) bool) { regexp.MustCompile("iterator") } {
	}
	for range lines {
		for range func(yield func(int) bool) { regexp.MustCompile("iterator in loop") } { // want regexp-compile-in-loop
		}
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
