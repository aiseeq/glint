package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Встроенный интерфейс, который никто не присваивает: вызов продвинутого
// метода идёт через nil-интерфейс и паникует.
func TestNeverAssignedFieldReportsEmbeddedInterfaceWithPromotedCall(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"holder.go": `package holder

type Service interface{ Run() error }

type Holder struct {
	Service
	name string
}

func New(name string) *Holder {
	return &Holder{name: name}
}

func (h *Holder) Start() error {
	return h.Run()
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Service")
}

// Встроенный интерфейс, заданный в литерале, — рабочая проводка.
func TestNeverAssignedFieldAcceptsAssignedEmbeddedInterface(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"holder.go": `package holder

type Service interface{ Run() error }

type Holder struct {
	Service
}

func New(s Service) *Holder {
	return &Holder{Service: s}
}

func (h *Holder) Start() error {
	return h.Run()
}
`,
	})

	assert.Empty(t, violations)
}

// Тестовый фейк встраивает интерфейс ради набора методов, а вызываемый метод
// определён у самого типа: через встроенное поле ничего не идёт.
func TestNeverAssignedFieldAcceptsEmbeddedInterfaceWithOwnMethods(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"fake.go": `package fake

type Store interface {
	Get(id string) string
	Put(id, v string)
}

type fakeStore struct {
	Store
	got []string
}

func (f *fakeStore) Get(id string) string {
	f.got = append(f.got, id)
	return id
}

func Use(s Store) string { return s.Get("a") }

func Run() string { return Use(&fakeStore{}) }
`,
	})

	assert.Empty(t, violations)
}

// Встроенный указатель на структуру без присвоения: чтение продвинутого поля
// разыменовывает nil.
func TestNeverAssignedFieldReportsEmbeddedPointerWithPromotedField(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"conf.go": `package conf

type Base struct{ Timeout int }

type Conf struct {
	*Base
	name string
}

func New(name string) *Conf {
	return &Conf{name: name}
}

func (c *Conf) Wait() int {
	return c.Timeout
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Base")
}

// Интерфейс встроен во встроенную структуру-значение: продвинутый вызов идёт
// через оба встроенных поля, nil — у внутреннего интерфейса.
func TestNeverAssignedFieldReportsNestedEmbeddedInterface(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"nested.go": `package nested

type Service interface{ Run() error }

type Inner struct {
	Service
}

type Outer struct {
	Inner
	name string
}

func New(name string) *Outer {
	return &Outer{name: name}
}

func (o *Outer) Start() error {
	return o.Run()
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Service")
}

// Метод с указательным приёмником, который сам проверяет nil, через
// встроенный nil-указатель вызывается без паники.
func TestNeverAssignedFieldAcceptsPointerMethodOnEmbeddedPointer(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"logger.go": `package logger

type Log struct{ lines []string }

func (l *Log) Printf(s string) {
	if l == nil {
		return
	}
	l.lines = append(l.lines, s)
}

type Worker struct {
	*Log
	name string
}

func New(name string) *Worker {
	return &Worker{name: name}
}

func (w *Worker) Do() {
	w.Printf(w.name)
}
`,
	})

	assert.Empty(t, violations)
}

// Выражение метода только называет метод и ничего не вызывает.
func TestNeverAssignedFieldAcceptsMethodExpressionOfEmbeddedInterface(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"expr.go": `package expr

type Service interface{ Run() error }

type Holder struct {
	Service
}

func New() *Holder { return &Holder{} }

var run = (*Holder).Run
`,
	})

	assert.Empty(t, violations)
}

const embeddedHolderSource = `package holder

type Service interface{ Run() error }

type Holder struct {
	Service
	name string
}

func New(name string) *Holder {
	return &Holder{name: name}
}

func (h *Holder) Start() error {
	return h.Run()
}
`

// Имя встроенного поля — имя его типа. Тест, который упоминает только тип
// (фейк, проверка реализации), поле не заполняет.
func TestNeverAssignedFieldReportsEmbeddedInterfaceWhenTestsNameOnlyTheType(t *testing.T) {
	violations := analyzeNeverAssigned(t, map[string]string{
		"holder.go": embeddedHolderSource,
		"holder_test.go": `package holder

type fakeService struct{}

func (fakeService) Run() error { return nil }

var _ Service = fakeService{}
`,
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Service")
}

// Тест, который сам заполняет встроенное поле, держит его живым, как и
// именованное поле.
func TestNeverAssignedFieldAcceptsEmbeddedInterfaceFilledByTests(t *testing.T) {
	for name, test := range map[string]string{
		"literal key": `package holder

type fakeService struct{}

func (fakeService) Run() error { return nil }

func newTestHolder() *Holder { return &Holder{Service: fakeService{}} }
`,
		"assignment": `package holder

type fakeService struct{}

func (fakeService) Run() error { return nil }

func newTestHolder() *Holder {
	h := New("x")
	h.Service = fakeService{}
	return h
}
`,
	} {
		violations := analyzeNeverAssigned(t, map[string]string{
			"holder.go":      embeddedHolderSource,
			"holder_test.go": test,
		})
		assert.Empty(t, violations, name)
	}
}
