package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeFields(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := NewUnusedFieldRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

// A field nothing reads and nothing writes is dead weight: it costs memory per
// instance and misleads every reader of the struct.
func TestUnusedFieldReportsNeverMentionedField(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type Cache struct {
	entries map[string]string
	hits    int
}

func New() *Cache {
	return &Cache{entries: make(map[string]string)}
}

func (c *Cache) Get(key string) string {
	return c.entries[key]
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Contains(t, violations[0].Message, "hits")
}

// A field written but never read is a computation nobody consumes.
func TestUnusedFieldReportsWriteOnlyField(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type Cache struct {
	entries map[string]string
	hits    int
}

func New() *Cache {
	return &Cache{entries: make(map[string]string), hits: 0}
}

func (c *Cache) Get(key string) string {
	c.hits++
	return c.entries[key]
}
`,
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "hits")
	assert.Contains(t, violations[0].Message, "never read")
}

func TestUnusedFieldAcceptsReadField(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type Cache struct {
	entries map[string]string
	hits    int
}

func (c *Cache) Get(key string) string {
	c.hits++
	return c.entries[key]
}

func (c *Cache) Hits() int {
	return c.hits
}
`,
	})

	assert.Empty(t, violations)
}

// An exported field of an exported type is part of the package's API: the code
// that reads it may live outside the analyzed tree.
func TestUnusedFieldIgnoresExportedField(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type Stats struct {
	Hits   int
	Misses int
}

func New() *Stats {
	return &Stats{}
}
`,
	})

	assert.Empty(t, violations)
}

// Serialization fills and reads tagged fields without naming them in code.
func TestUnusedFieldIgnoresTaggedField(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type entry struct {
	key   string ` + "`json:\"key\"`" + `
	value string
}

func New() *entry {
	return &entry{}
}

func (e *entry) Value() string { return e.value }
`,
	})

	assert.Empty(t, violations)
}

// An embedded field provides the methods of its type; nothing has to mention it.
func TestUnusedFieldIgnoresEmbeddedField(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

import "sync"

type Cache struct {
	sync.Mutex
	value int
}

func (c *Cache) Set(v int) {
	c.Lock()
	defer c.Unlock()
	c.value = v
}

func (c *Cache) Get() int {
	return c.value
}
`,
	})

	assert.Empty(t, violations)
}

// A blank field is padding or alignment, never meant to be used.
func TestUnusedFieldIgnoresBlankField(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type Cache struct {
	_     [0]func()
	value int
}

func (c *Cache) Get() int { return c.value }
`,
	})

	assert.Empty(t, violations)
}

// A type that is only ever constructed reaches its fields through the literal.
func TestUnusedFieldCountsLiteralKeyAsWrite(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type entry struct {
	value string
}

func New(v string) *entry {
	return &entry{value: v}
}
`,
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "never read")
}

// Repro from glint itself: a struct used as a map key has every field read by
// the runtime when it hashes and compares it, so no field of it is dead.
func TestUnusedFieldIgnoresStructUsedAsMapKey(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type key struct {
	file string
	line int
}

func Dedupe(files []string, lines []int) int {
	seen := make(map[key]bool)
	for i, f := range files {
		seen[key{file: f, line: lines[i]}] = true
	}
	return len(seen)
}
`,
	})

	assert.Empty(t, violations)
}

// Comparing two values reads every field just as hashing does.
func TestUnusedFieldIgnoresComparedStruct(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type point struct {
	x int
	y int
}

func Same(a, b point) bool {
	return a == b
}
`,
	})

	assert.Empty(t, violations)
}

func TestUnusedFieldMetadata(t *testing.T) {
	rule := NewUnusedFieldRule()
	assert.Equal(t, "unused-field", rule.Name())
	assert.Equal(t, "deadcode", rule.Category())
	assert.False(t, rule.RequiresSSA())
	assert.Nil(t, rule.AnalyzeFile(nil))
}

func TestUnusedFieldRejectsNilProject(t *testing.T) {
	_, err := NewUnusedFieldRule().AnalyzeGoProject(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil Go project context")
}
