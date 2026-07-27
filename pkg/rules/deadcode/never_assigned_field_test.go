package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeNeverAssigned(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := NewNeverAssignedFieldRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

// Классический случай: конструктор перестал заполнять поле, читатели остались.
// Компилируется, падает на первом обращении.
func TestNeverAssignedFieldReportsDependencyDroppedFromConstructor(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"composer.go": `package composer

type Logger interface{ Info(string) }

type Manager interface{ Apply() }

type Composer struct {
	logger  Logger
	manager Manager
}

func New(m Manager) *Composer {
	return &Composer{manager: m}
}

func (c *Composer) Apply() {
	c.logger.Info("applied")
	c.manager.Apply()
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, 8, violations[0].Line)
	assert.Contains(t, violations[0].Message, "logger")
}

// Поле, заполняемое присваиванием после конструктора, — рабочая проводка.
func TestNeverAssignedFieldAcceptsSetterAssignment(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"composer.go": `package composer

type Logger interface{ Info(string) }

type Composer struct {
	logger Logger
}

func New() *Composer { return &Composer{} }

func (c *Composer) SetLogger(l Logger) { c.logger = l }

func (c *Composer) Apply() { c.logger.Info("applied") }
`,
	})

	assert.Empty(t, violations)
}

// Позиционный литерал не называет полей и заполняет все — из него нельзя
// заключить, что какое-то поле осталось пустым.
func TestNeverAssignedFieldAcceptsPositionalLiteral(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"deps.go": `package deps

type Logger interface{ Info(string) }

type Repo interface{ Get() string }

type deps struct {
	logger Logger
	repo   Repo
}

func New(l Logger, r Repo) *deps { return &deps{l, r} }

func (d *deps) Run() string {
	d.logger.Info("run")
	return d.repo.Get()
}
`,
	})

	assert.Empty(t, violations)
}

// Поле примитивного типа пропускается: отсутствие записи даёт неверное значение,
// а не панику, и такие поля штатно заполняет рефлексия (json/sql).
func TestNeverAssignedFieldIgnoresBasicTypes(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"row.go": `package row

type Row struct {
	name  string
	count int
}

func (r *Row) Describe() string {
	if r.count > 0 {
		return r.name
	}
	return ""
}
`,
	})

	assert.Empty(t, violations)
}

// Поле, которое никто не читает, — забота unused-field, а не этого правила.
func TestNeverAssignedFieldIgnoresUnreadField(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"cache.go": `package cache

type Logger interface{ Info(string) }

type Cache struct {
	logger Logger
}

func New() *Cache { return &Cache{} }
`,
	})

	assert.Empty(t, violations)
}

// Взятие адреса поля отдаёт запись наружу (sql.Scan(&r.field)) — это запись.
func TestNeverAssignedFieldAcceptsAddressOfField(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"scan.go": `package scan

type Row struct {
	values *[]string
}

func fill(dst **[]string) { *dst = nil }

func (r *Row) Load() int {
	fill(&r.values)
	if r.values == nil {
		return 0
	}
	return len(*r.values)
}
`,
	})

	assert.Empty(t, violations)
}

// Опциональный фильтр: указатель никто не заполняет, но каждый читатель проверяет
// на nil — это вводит в заблуждение, но не падает, и правилу здесь делать нечего.
func TestNeverAssignedFieldIgnoresNilCheckedPointer(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"filter.go": `package filter

type Filter struct {
	userID *string
}

func (f *Filter) Query() string {
	if f.userID == nil {
		return "all"
	}
	return "one"
}
`,
	})

	assert.Empty(t, violations)
}

// Указатель, который разыменовывают без проверки, падает так же, как интерфейс.
func TestNeverAssignedFieldReportsDereferencedPointer(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"holder.go": `package holder

type Inner struct{ Name string }

type Holder struct {
	inner *Inner
}

func New() *Holder { return &Holder{} }

func (h *Holder) Name() string { return h.inner.Name }
`,
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "inner")
}
