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

// White-box tests assert on internal counters all the time. Test packages are
// not loaded (packages.Load runs with Tests:false), so without a fallback scan
// a field read only by its test was reported as dead.
func TestUnusedFieldAcceptsFieldReadOnlyByTest(t *testing.T) {
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
	c.hits++
	return c.entries[key]
}
`,
		"cache_test.go": `package cache

import "testing"

func TestGetCountsHits(t *testing.T) {
	c := New()
	c.Get("a")
	if c.hits != 1 {
		t.Fatalf("hits = %d", c.hits)
	}
}
`,
	})

	assert.Empty(t, violations, "a field read by its white-box test is not dead")
}

// A similarly named but different identifier in the test must not save the field.
func TestUnusedFieldTestMentionMustMatchWholeName(t *testing.T) {
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
	c.hits++
	return c.entries[key]
}
`,
		"cache_test.go": `package cache

import "testing"

func TestGet(t *testing.T) {
	hitsTotal := 0
	c := New()
	c.Get("a")
	_ = hitsTotal
	_ = c
	if testing.Short() {
		t.Skip()
	}
}
`,
	})

	require.Len(t, violations, 1)
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

// Внутри метода generic-типа обращение c.field даёт поле инстанцированной структуры —
// это другой *types.Var, чем объявление. Пока ключом был указатель, каждое такое чтение
// терялось и любое generic-поле объявлялось мёртвым.
func TestUnusedFieldSeesReadsInsideGenericType(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type box[T any] struct {
	fetch func() T
	val   T
	dead  int
}

func (b *box[T]) get() T {
	b.val = b.fetch()
	return b.val
}
`,
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "dead")
}

// Generic-тип, инстанцированный извне: чтение через конкретный аргумент типа тоже
// должно засчитываться объявленному полю.
func TestUnusedFieldSeesReadsThroughInstantiatedGeneric(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"cache.go": `package cache

type pair[T any] struct {
	first  T
	second T
}

func firstOf(p *pair[string]) string {
	return p.first
}
`,
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "second")
}

// Repro from a real project: six behaviour options were set in the literals of
// a registry and read nowhere, so the code paths behind them were unreachable.
// A composite literal counts as use for the compiler and for deadcode tools,
// which is why the settings survived so long.
func TestUnusedFieldReportsOptionFieldOnlyWritten(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"tactics.go": `package tactics

type Opts struct {
	Wave     int
	MacroAt  int
}

var registry = map[string]Opts{
	"rush":  {Wave: 6, MacroAt: 3},
	"macro": {Wave: 0, MacroAt: 1},
}

func waveOf(name string) int {
	return registry[name].Wave
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Contains(t, violations[0].Message, "MacroAt")
}

// An exported field of an ordinary struct may well be read outside the analyzed
// tree; only settings types are checked, where a field nobody reads means the
// setting does nothing.
func TestUnusedFieldAcceptsExportedFieldOfPlainStruct(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"model.go": `package model

type Order struct {
	ID     string
	Amount int
}

func New(id string) Order {
	return Order{ID: id, Amount: 1}
}
`,
	})

	assert.Empty(t, violations)
}

// A setting that is read somewhere is doing its job.
func TestUnusedFieldAcceptsReadOptionField(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"tactics.go": `package tactics

type Settings struct {
	Wave int
}

var defaults = Settings{Wave: 6}

func wave() int { return defaults.Wave }
`,
	})

	assert.Empty(t, violations)
}

// A setting the program never reads itself is still read by the encoder when
// the struct is marshalled — the value leaves the process, so the field is not
// dead.
func TestUnusedFieldAcceptsMarshalledSettingType(t *testing.T) {
	violations := analyzeFields(t, map[string]string{
		"report.go": `package report

import "encoding/json"

type ExportOptions struct {
	Format string
}

func Dump() ([]byte, error) {
	return json.Marshal(ExportOptions{Format: "csv"})
}
`,
	})

	assert.Empty(t, violations)
}
